"""Command-line entry point. Generated state is private and never part of a release."""
import argparse
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

from .core import CipherBox, SecurityError, Vault, b64, canonical, load_kernel
from .pki import TemporaryWorkspace, create_pki, private_write


def initialize(state):
    state = Path(state)
    # Refuse overwrite, including partially initialised directories.
    state.mkdir(parents=True, mode=0o777 if os.name == "nt" else 0o700, exist_ok=False)
    config = {"version": 1, "active_key": "key1", "encryption_keys": {"key1": b64(os.urandom(32))},
              "audit_key": b64(os.urandom(32)), "credentials": {}}
    clients = {}
    for name, tenant, role in (("owner-a", "tenant-a", "owner"), ("admin-a", "tenant-a", "admin"),
                               ("writer-a", "tenant-a", "contributor"), ("writer2-a", "tenant-a", "contributor"),
                               ("viewer-a", "tenant-a", "viewer"), ("owner-b", "tenant-b", "owner")):
        token = secrets.token_urlsafe(32)
        config["credentials"][hashlib.sha256(token.encode()).hexdigest()] = {
            "subject": name, "memberships": {tenant: role}, "disabled": False,
            "expires_at": int(time.time()) + 30 * 86400}
        clients[name] = {"token": token, "tenant": tenant}
    private_write(state / "server.json", canonical(config))
    private_write(state / "clients.json", canonical(clients))
    create_pki(state / "pki")
    load_kernel(state)


def serve(state, http_port=8443, grpc_port=50051):
    from .transports import grpc_server, https_server
    kernel = load_kernel(state)
    pki = Path(state) / "pki"
    http = https_server(kernel, pki, port=http_port)
    try:
        rpc, bound = grpc_server(kernel, pki, port=grpc_port)
    except Exception:
        http.server_close()
        raise
    rpc.start()
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    print(f"HTTPS mTLS: https://localhost:{http.server_port}", flush=True)
    print(f"gRPC mTLS: localhost:{bound}", flush=True)
    print("Authentication and audit required. Ctrl+C to stop.", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        http.shutdown()
        http.server_close()
        rpc.stop(2).wait(3)
        thread.join(3)


def self_demo():
    """Real loopback HTTPS + gRPC calls, not simulated TLS or crypto."""
    from urllib.error import HTTPError
    import grpc
    from .transports import https_server, https_call, grpc_server, grpc_channel, grpc_call
    with TemporaryWorkspace(prefix="securitykit-demo-") as directory:
        state = Path(directory) / "state"
        initialize(state)
        kernel = load_kernel(state)
        clients = json.loads((state / "clients.json").read_text())
        pki = state / "pki"
        http = https_server(kernel, pki, port=0)
        rpc, port = grpc_server(kernel, pki, port=0)
        rpc.start()
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        thread.start()
        checks = []
        try:
            writer, viewer, outsider = [clients[n]["token"] for n in ("writer-a", "viewer-a", "owner-b")]
            https_call(pki, writer, "tenant-a", "create", "sample", "local-demo-value", http.server_port)
            assert https_call(pki, viewer, "tenant-a", "read", "sample", port=http.server_port)["value"] == "local-demo-value"
            checks.append("HTTPS mTLS + bearer + encrypted secret roundtrip")
            for token, action, expected in ((viewer, "update", 403), (outsider, "read", 403), ("x" * 40, "read", 401)):
                try:
                    https_call(pki, token, "tenant-a", action, "sample", "blocked", http.server_port)
                    raise RuntimeError("expected rejection")
                except HTTPError as error:
                    assert error.code == expected
            checks.append("Read-only role, cross-tenant and invalid token blocked")
            with grpc_channel(pki, f"localhost:{port}") as channel:
                assert grpc_call(channel, viewer, "tenant-a", "read", "sample")["value"] == "local-demo-value"
                try:
                    grpc_call(channel, outsider, "tenant-a", "read", "sample")
                    raise RuntimeError("expected rejection")
                except grpc.RpcError as error:
                    assert error.code() == grpc.StatusCode.PERMISSION_DENIED
            checks.append("gRPC mTLS + shared tenant/RBAC engine")
            checkpoint = kernel.verify_audit()
            assert checkpoint["seq"] >= 6
            checks.append("Authenticated audit chain verified")
            return {"passed": len(checks), "checks": checks, "audit_events": checkpoint["seq"]}
        finally:
            http.shutdown()
            http.server_close()
            rpc.stop(0).wait(3)
            thread.join(3)


def main(argv=None):
    parser = argparse.ArgumentParser(description="BackendSecurityKit 1.0.0 — tenant RBAC, AES-GCM, TLS, audit")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="generate fresh local state, keys, tokens and development certificates")
    init.add_argument("--state", type=Path, default=Path("private-state"))
    server = sub.add_parser("serve", help="start loopback HTTPS and gRPC (mTLS required)")
    server.add_argument("--state", type=Path, default=Path("private-state"))
    server.add_argument("--http-port", type=int, default=8443)
    server.add_argument("--grpc-port", type=int, default=50051)
    sub.add_parser("demo", help="run isolated end-to-end security demo; no state retained")
    verify = sub.add_parser("verify-audit", help="verify HMAC chain; prints a checkpoint to retain externally")
    verify.add_argument("--state", type=Path, default=Path("private-state"))
    verify.add_argument("--checkpoint", type=Path)
    client = sub.add_parser("call", help="call the HTTPS or gRPC demo using local generated client identity")
    client.add_argument("--state", type=Path, default=Path("private-state"))
    client.add_argument("--transport", choices=["https", "grpc"], default="https")
    client.add_argument("--identity", default="viewer-a")
    client.add_argument("--tenant")
    client.add_argument("--port", type=int)
    client.add_argument("--resource", default="sample")
    client.add_argument("--value-file", type=Path, help="UTF-8 input; keeps secret values out of command history")
    client.add_argument("action", choices=["create", "read", "update", "delete", "audit"])
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            initialize(args.state)
            print("Initialised. Private credentials are in server.json, clients.json and pki/ under your state directory.")
            print("Never include that directory when sharing the release.")
        elif args.command == "serve":
            serve(args.state, args.http_port, args.grpc_port)
        elif args.command == "demo":
            print(json.dumps(self_demo(), indent=2))
        elif args.command == "verify-audit":
            config = json.loads((args.state / "server.json").read_text())
            # Build only what verification needs, without constructor/schema mutations.
            from .core import SecurityKernel, unb64
            kernel = object.__new__(SecurityKernel)
            kernel.database, kernel.audit_key = args.state / "security.db", unb64(config["audit_key"])
            checkpoint = json.loads(args.checkpoint.read_text()) if args.checkpoint else None
            print(json.dumps(kernel.verify_audit(checkpoint)))
        elif args.command == "call":
            from .transports import grpc_channel, grpc_call, https_call
            record = json.loads((args.state / "clients.json").read_text())[args.identity]
            tenant = args.tenant or record["tenant"]
            value = args.value_file.read_text("utf8") if args.value_file else None
            if args.action in {"create", "update"} and args.value_file is None:
                raise ValueError("--value-file is required for writes")
            if args.transport == "https":
                result = https_call(args.state / "pki", record["token"], tenant,
                                    args.action, args.resource, value, args.port or 8443)
            else:
                with grpc_channel(args.state / "pki", f"localhost:{args.port or 50051}") as channel:
                    result = grpc_call(channel, record["token"], tenant, args.action, args.resource, value)
            print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        # Do not print exception text: remote payloads or local file paths may be sensitive.
        code = error.code if isinstance(error, SecurityError) else type(error).__name__
        print("Operation failed: " + str(code), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
