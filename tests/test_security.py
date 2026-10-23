import hashlib
import io
import json
import os
import sqlite3
import ssl
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import grpc

from securitykit.cli import initialize
from securitykit.core import CipherBox, SecurityError, Vault, canonical, load_kernel
from securitykit.pki import TemporaryWorkspace
from securitykit.transports import (SecurityMiddleware, grpc_call, grpc_channel,
                                    grpc_server, https_call, https_server, parse_json)


class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = TemporaryWorkspace(prefix="securitykit-tests-")
        cls.master = Path(cls.temporary.name) / "master"
        initialize(cls.master)
        cls.clients = json.loads((cls.master / "clients.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.temp = TemporaryWorkspace(dir=self.temporary.name)
        self.state = Path(self.temp.name)
        (self.state / "server.json").write_bytes((self.master / "server.json").read_bytes())
        self.kernel = load_kernel(self.state)
        self.vault = Vault(self.kernel)

    def tearDown(self):
        self.temp.cleanup()

    def auth(self, name="writer-a"):
        return "Bearer " + self.clients[name]["token"]

    def call(self, action, who="writer-a", tenant="tenant-a", resource="sample", value="secret-test-value"):
        return self.vault.call(self.auth(who), tenant, action, resource, value)

    def expect(self, status, callback):
        with self.assertRaises(SecurityError) as caught:
            callback()
        self.assertEqual(status, caught.exception.status)

    def test_01_encrypted_roundtrip_no_plaintext_at_rest(self):
        self.call("create")
        self.assertEqual(self.call("read", "viewer-a")["value"], "secret-test-value")
        with closing(self.kernel.connect()) as tx:
            envelope = tx.execute("SELECT envelope FROM secrets").fetchone()[0]
            self.assertNotIn("secret-test-value", envelope)
            self.assertEqual(json.loads(envelope)["v"], 1)

    def test_02_viewer_cannot_write_even_owned(self):
        self.call("create")
        self.expect(403, lambda: self.call("create", "viewer-a", resource="new"))
        with closing(self.kernel.connect()) as tx:
            tx.execute("UPDATE secrets SET owner='viewer-a'")
        self.expect(403, lambda: self.call("update", "viewer-a"))
        self.expect(403, lambda: self.call("delete", "viewer-a"))

    def test_03_contributor_ownership_admin_override(self):
        self.call("create")
        self.call("update")
        self.expect(403, lambda: self.call("update", "writer2-a"))
        self.call("update", "admin-a", value="admin-update")
        self.assertEqual(self.call("read")["value"], "admin-update")
        self.call("delete", "admin-a")
        self.expect(404, lambda: self.call("read"))

    def test_04_no_cross_tenant_owner_bypass(self):
        self.call("create")
        for action in ("read", "create", "update", "delete", "audit"):
            self.expect(403, lambda a=action: self.call(a, "owner-b"))

    def test_05_same_id_two_tenants_stays_separate(self):
        self.call("create", value="A")
        self.call("create", "owner-b", "tenant-b", value="B")
        self.assertEqual(self.call("read")["value"], "A")
        self.assertEqual(self.call("read", "owner-b", "tenant-b")["value"], "B")

    def test_06_invalid_expired_disabled_tokens(self):
        self.expect(401, lambda: self.vault.call("Bearer " + "x" * 40, "tenant-a", "read", "sample"))
        for mutation in ({"expires_at": time.time() - 1}, {"disabled": True}):
            digest = hashlib.sha256(self.clients["writer-a"]["token"].encode()).hexdigest()
            original = dict(self.kernel.credentials[digest])
            self.kernel.credentials[digest].update(mutation)
            self.expect(401, lambda: self.call("create"))
            self.kernel.credentials[digest].update(original)

    def test_07_aes_wrong_tenant_resource_key_tag_rejected(self):
        box = self.kernel.cipher
        envelope = box.encrypt("top-secret", "tenant-a", "one")
        self.expect(503, lambda: box.decrypt(envelope, "tenant-b", "one"))
        self.expect(503, lambda: box.decrypt(envelope, "tenant-a", "two"))
        other = CipherBox({"key1": os.urandom(32)}, "key1")
        self.expect(503, lambda: other.decrypt(envelope, "tenant-a", "one"))
        item = json.loads(envelope)
        item["data"] = "A" + item["data"][1:] if not item["data"].startswith("A") else "B" + item["data"][1:]
        self.expect(503, lambda: box.decrypt(json.dumps(item), "tenant-a", "one"))
        self.expect(503, lambda: box.decrypt("legacy-plaintext", "tenant-a", "one"))

    def test_08_aes_key_id_rotation_and_fresh_nonce(self):
        old = self.kernel.cipher
        envelope = old.encrypt("old", "tenant-a", "one")
        keys = {**old.keys, "key2": os.urandom(32)}
        new = CipherBox(keys, "key2")
        self.assertEqual(new.decrypt(envelope, "tenant-a", "one"), "old")
        self.assertEqual(json.loads(new.encrypt("new", "tenant-a", "one"))["kid"], "key2")
        nonces = {json.loads(new.encrypt("new", "tenant-a", "one"))["nonce"] for _ in range(100)}
        self.assertEqual(len(nonces), 100)
        with self.assertRaises(ValueError):
            CipherBox({"bad": b"short"}, "bad")

    def test_09_audit_contains_metadata_only(self):
        self.call("create")
        self.expect(403, lambda: self.call("update", "viewer-a"))
        with closing(self.kernel.connect()) as tx:
            data = "\n".join(r[0] for r in tx.execute("SELECT event FROM audit"))
        self.assertNotIn("secret-test-value", data)
        for record in self.clients.values():
            self.assertNotIn(record["token"], data)
        self.assertEqual(self.kernel.verify_audit()["seq"], 2)

    def test_10_audit_tamper_detected(self):
        self.call("create")
        with closing(self.kernel.connect()) as tx:
            tx.execute("UPDATE audit SET event=replace(event,'success','denied')")
        self.expect(503, self.kernel.verify_audit)
        self.expect(503, lambda: load_kernel(self.state))

    def test_11_tail_deletion_detected_with_external_checkpoint(self):
        self.call("create")
        self.call("read")
        checkpoint = self.kernel.verify_audit()
        with closing(self.kernel.connect()) as tx:
            tx.execute("DELETE FROM audit WHERE seq=2")
        self.assertEqual(self.kernel.verify_audit()["seq"], 1)
        self.expect(503, lambda: self.kernel.verify_audit(checkpoint))

    def test_12_audit_write_failure_rolls_back_business_write(self):
        with closing(self.kernel.connect()) as tx:
            tx.executescript("CREATE TRIGGER fail_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'test'); END;")
        self.expect(503, lambda: self.call("create"))
        with closing(self.kernel.connect()) as tx:
            self.assertEqual(tx.execute("SELECT count(*) FROM secrets").fetchone()[0], 0)

    def test_13_operation_failure_rolls_back_and_records_safe_error(self):
        def failing(tx, principal):
            tx.execute("INSERT INTO secrets VALUES ('tenant-a','bad','writer-a','unused')")
            raise RuntimeError("never-log-this-secret")
        self.expect(503, lambda: self.kernel.run(self.auth(), "tenant-a", "sample.failure", "bad", "contributor", failing))
        with closing(self.kernel.connect()) as tx:
            self.assertEqual(tx.execute("SELECT count(*) FROM secrets").fetchone()[0], 0)
            self.assertNotIn("never-log-this-secret", tx.execute("SELECT event FROM audit").fetchone()[0])

    def test_14_audit_list_is_tenant_scoped_admin_only(self):
        self.call("create")
        self.call("create", "owner-b", "tenant-b", value="B")
        self.expect(403, lambda: self.call("audit", "viewer-a"))
        self.assertTrue(all(e["tenant"] == "tenant-a" for e in self.call("audit", "admin-a")["events"]))

    def test_15_concurrent_writers_chain_is_consistent(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: self.call("create", resource=f"item-{i}"), range(24)))
        self.assertEqual(self.kernel.verify_audit()["seq"], 24)

    def test_16_strict_input_limits(self):
        self.expect(400, lambda: self.call("create", resource="../../escape"))
        self.expect(400, lambda: self.call("create", value="x" * 16385))
        self.expect(400, lambda: self.call("create", value=123))
        for raw in (b'{"value":1,"value":2}', b'{"n":NaN}', b'[]', b'bad', b'x' * 65537):
            self.expect(400, lambda r=raw: parse_json(r))

    def test_17_generic_kernel_and_unknown_required_role(self):
        self.assertEqual(self.kernel.run(self.auth(), "tenant-a", "app.read", "item", "viewer", lambda tx, p: p.subject), "writer-a")
        with self.assertRaises(ValueError):
            self.kernel.run(self.auth(), "tenant-a", "app.read", "item", "unknown", lambda *_: None)

    def test_18_wsgi_ignores_forged_headers_and_requires_https(self):
        app = SecurityMiddleware(self.kernel)
        environ = {"wsgi.url_scheme": "https", "REQUEST_METHOD": "POST",
                   "PATH_INFO": "/v1/tenants/tenant-a/secrets/one", "CONTENT_TYPE": "application/json",
                   "CONTENT_LENGTH": "13", "wsgi.input": io.BytesIO(b'{"value":"x"}'),
                   "HTTP_AUTHORIZATION": self.auth("viewer-a"), "HTTP_X_ROLE": "owner",
                   "HTTP_X_TENANT": "tenant-a"}
        responses = []
        app(environ, lambda status, headers: responses.append(status))
        self.assertTrue(responses[-1].startswith("403"))
        environ["wsgi.url_scheme"] = "http"
        app(environ, lambda status, headers: responses.append(status))
        self.assertTrue(responses[-1].startswith("400"))


# Network tests use a separate class so inherited test methods are not re-run.
class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = TemporaryWorkspace(prefix="securitykit-network-")
        cls.state = Path(cls.temp.name) / "state"
        initialize(cls.state)
        cls.kernel = load_kernel(cls.state)
        cls.clients = json.loads((cls.state / "clients.json").read_text())
        cls.pki = cls.state / "pki"
        cls.http = https_server(cls.kernel, cls.pki, port=0)
        cls.thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.thread.start()
        cls.rpc, cls.rpc_port = grpc_server(cls.kernel, cls.pki, port=0)
        cls.rpc.start()

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        cls.http.server_close()
        cls.rpc.stop(0).wait(3)
        cls.thread.join(3)
        cls.temp.cleanup()

    def token(self, name="writer-a"):
        return self.clients[name]["token"]

    def test_19_https_and_grpc_share_rbac_and_storage(self):
        https_call(self.pki, self.token(), "tenant-a", "create", "wire", "wire-secret", self.http.server_port)
        with grpc_channel(self.pki, f"localhost:{self.rpc_port}") as channel:
            self.assertEqual(grpc_call(channel, self.token("viewer-a"), "tenant-a", "read", "wire")["value"], "wire-secret")
            with self.assertRaises(grpc.RpcError) as error:
                grpc_call(channel, self.token("owner-b"), "tenant-a", "read", "wire")
            self.assertEqual(error.exception.code(), grpc.StatusCode.PERMISSION_DENIED)
            with self.assertRaises(grpc.RpcError) as error:
                grpc_call(channel, "x" * 40, "tenant-a", "read", "wire")
            self.assertEqual(error.exception.code(), grpc.StatusCode.UNAUTHENTICATED)

    def test_20_https_requires_client_certificate(self):
        context = ssl.create_default_context(cafile=str(self.pki / "ca.pem"))
        req = Request(f"https://localhost:{self.http.server_port}/v1/tenants/tenant-a/secrets/wire")
        with self.assertRaises((URLError, ssl.SSLError, ConnectionError, OSError)):
            urlopen(req, context=context, timeout=3)

    def test_21_https_wrong_ca_and_plaintext_rejected(self):
        with self.assertRaises(URLError):
            urlopen(f"https://localhost:{self.http.server_port}/", context=ssl.create_default_context(), timeout=3)
        with self.assertRaises((URLError, ConnectionError, OSError)):
            urlopen(f"http://localhost:{self.http.server_port}/", timeout=3)

    def test_22_grpc_requires_client_cert_and_correct_server_name(self):
        creds = grpc.ssl_channel_credentials((self.pki / "ca.pem").read_bytes())
        with grpc.secure_channel(f"localhost:{self.rpc_port}", creds) as channel:
            with self.assertRaises(grpc.RpcError) as error:
                channel.unary_unary("/securitykit.Vault/Call")(b'{}', timeout=2)
            self.assertIn(error.exception.code(), (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED))
        pki = self.pki
        creds = grpc.ssl_channel_credentials((pki / "ca.pem").read_bytes(),
            (pki / "client-key.pem").read_bytes(), (pki / "client.pem").read_bytes())
        with grpc.secure_channel(f"localhost:{self.rpc_port}", creds,
                                 options=[("grpc.ssl_target_name_override", "wrong.invalid")]) as channel:
            with self.assertRaises(grpc.RpcError) as error:
                channel.unary_unary("/securitykit.Vault/Call")(b'{}', timeout=2)
            self.assertIn(error.exception.code(), (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED))

    def test_23_grpc_rejects_plaintext_unknown_methods_and_duplicate_auth(self):
        with grpc.insecure_channel(f"localhost:{self.rpc_port}") as channel:
            with self.assertRaises(grpc.RpcError):
                channel.unary_unary("/securitykit.Vault/Call")(b'{}', timeout=2)
        with grpc_channel(self.pki, f"localhost:{self.rpc_port}") as channel:
            with self.assertRaises(grpc.RpcError) as error:
                channel.unary_unary("/unknown/Call")(b'{}', timeout=2)
            self.assertEqual(error.exception.code(), grpc.StatusCode.UNIMPLEMENTED)
            with self.assertRaises(grpc.RpcError) as error:
                channel.unary_unary("/securitykit.Vault/Call")(
                    canonical({"tenant": "tenant-a", "action": "read", "resource": "wire"}),
                    metadata=[("authorization", "Bearer " + self.token())] * 2, timeout=3)
            self.assertEqual(error.exception.code(), grpc.StatusCode.UNAUTHENTICATED)

    def test_24_grpc_oversize_rejected(self):
        with grpc_channel(self.pki, f"localhost:{self.rpc_port}") as channel:
            with self.assertRaises(grpc.RpcError) as error:
                channel.unary_unary("/securitykit.Vault/Call")(b'x' * 65537, timeout=3)
            self.assertEqual(error.exception.code(), grpc.StatusCode.RESOURCE_EXHAUSTED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
