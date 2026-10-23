"""WSGI security middleware and TLS-only, unary JSON gRPC adapter.

The small vault is a reference app. SecurityKernel.run is the domain-neutral API.
"""
import json
import re
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

import grpc
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone

from .core import SecurityError, Vault, canonical

MAX_BODY = 65536
ROUTE = re.compile(r"/v1/tenants/([A-Za-z0-9_.-]{1,64})/(secrets/([A-Za-z0-9_.-]{1,64})|audit)\Z")
METHODS = {"GET": "read", "POST": "create", "PUT": "update", "DELETE": "delete"}


def parse_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result
    try:
        if len(raw) > MAX_BODY:
            raise ValueError()
        item = json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(item, dict):
            raise ValueError()
        return item
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise SecurityError(400, "invalid_json") from None


class SecurityMiddleware:
    """WSGI reference adapter. All protected operations route into the same kernel.

    No trust is placed in X-Tenant, X-User, X-Role or forwarded headers.
    Host WSGI servers must expose this app only over authenticated TLS.
    """
    def __init__(self, kernel):
        self.vault = Vault(kernel)

    def __call__(self, environ, start_response):
        try:
            if environ.get("wsgi.url_scheme") != "https":
                raise SecurityError(400, "tls_required")
            match = ROUTE.fullmatch(environ.get("PATH_INFO", ""))
            method = environ.get("REQUEST_METHOD", "")
            if not match:
                raise SecurityError(404, "route_not_found")
            tenant, kind, resource = match.groups()
            action = "audit" if kind == "audit" and method == "GET" else METHODS.get(method)
            if not action or (kind == "audit" and method != "GET"):
                raise SecurityError(405, "method_not_allowed")
            value = None
            if method in {"POST", "PUT"}:
                if environ.get("CONTENT_TYPE", "").split(";", 1)[0].strip() != "application/json":
                    raise SecurityError(415, "json_required")
                try:
                    size = int(environ.get("CONTENT_LENGTH", ""))
                except ValueError:
                    raise SecurityError(400, "content_length_required") from None
                if not 0 < size <= MAX_BODY:
                    raise SecurityError(413, "body_too_large")
                payload = parse_json(environ["wsgi.input"].read(size))
                if set(payload) != {"value"}:
                    raise SecurityError(400, "unexpected_fields")
                value = payload["value"]
            result = self.vault.call(environ.get("HTTP_AUTHORIZATION", ""), tenant, action,
                                     resource or "all", value)
            status = 201 if method == "POST" else 200
        except SecurityError as error:
            status, result = error.status, {"error": error.code}
        except Exception:
            status, result = 503, {"error": "service_unavailable"}
        body = canonical(result)
        start_response(f"{status} {HTTPStatus(status).phrase}", [
            ("Content-Type", "application/json; charset=utf-8"), ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")])
        return [body]


def tls_context(pki, server=False):
    pki = Path(pki)
    if server:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(pki / "server.pem", pki / "server-key.pem")
        ctx.load_verify_locations(pki / "ca.pem")
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx = ssl.create_default_context(cafile=str(pki / "ca.pem"))
        ctx.load_cert_chain(pki / "client.pem", pki / "client-key.pem")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def https_server(kernel, pki, host="127.0.0.1", port=8443):
    application = SecurityMiddleware(kernel)

    class Handler(BaseHTTPRequestHandler):
        server_version = "SecurityKit"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def handle_app(self):
            # One request per connection; reject ambiguous framing and duplicate auth.
            self.close_connection = True
            if (self.headers.get("Transfer-Encoding") or
                    len(self.headers.get_all("Content-Length", [])) > 1 or
                    len(self.headers.get_all("Authorization", [])) > 1):
                self.send_error(400)
                return
            environ = {"PATH_INFO": self.path.split("?", 1)[0], "REQUEST_METHOD": self.command,
                       "CONTENT_TYPE": self.headers.get("Content-Type", ""),
                       "CONTENT_LENGTH": self.headers.get("Content-Length", ""),
                       "HTTP_AUTHORIZATION": self.headers.get("Authorization", ""),
                       "wsgi.url_scheme": "https",
                       "wsgi.input": self.rfile}

            def respond(status, headers):
                self.send_response(int(status.split()[0]))
                for key, value in headers:
                    self.send_header(key, value)
                self.send_header("Connection", "close")
                self.end_headers()

            for body in application(environ, respond):
                self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = handle_app

        def log_message(self, *_args):
            pass  # Avoid request paths, user-controlled text and credentials in stderr.

    # Wrap accepted sockets rather than listener: slow TLS clients cannot block accept.
    context = tls_context(pki, server=True)

    class SecureHTTPServer(ThreadingHTTPServer):
        daemon_threads = True
        slots = threading.BoundedSemaphore(32)

        def process_request(self, request, client_address):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except Exception:
                self.slots.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.slots.release()

        def get_request(self):
            sock, address = super().get_request()
            sock.settimeout(5)
            return context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), address

        def handle_error(self, *_args):
            pass  # Invalid TLS/HTTP must not echo attacker-controlled data or local paths.

    return SecureHTTPServer((host, port), Handler)


STATUS = {400: grpc.StatusCode.INVALID_ARGUMENT, 401: grpc.StatusCode.UNAUTHENTICATED,
          403: grpc.StatusCode.PERMISSION_DENIED, 404: grpc.StatusCode.NOT_FOUND,
          409: grpc.StatusCode.ALREADY_EXISTS, 503: grpc.StatusCode.UNAVAILABLE}


class SecurityInterceptor(grpc.ServerInterceptor):
    """TLS-only server adapter for the explicitly mapped unary JSON Vault.Call RPC."""
    def __init__(self, kernel):
        self.vault = Vault(kernel)

    def intercept_service(self, continuation, details):
        handler = continuation(details)
        if handler is None:
            return None  # gRPC returns UNIMPLEMENTED; no catch-all business handler.

        def invoke(raw, context):
            try:
                if details.method != "/securitykit.Vault/Call":
                    raise SecurityError(403, "rpc_not_allowed")
                entries = [v for k, v in context.invocation_metadata() if k == "authorization"]
                authorization = entries[0] if len(entries) == 1 else ""
                request = parse_json(raw)
                if set(request) - {"tenant", "action", "resource", "value"}:
                    raise SecurityError(400, "unexpected_fields")
                return canonical(self.vault.call(authorization, request.get("tenant"),
                    request.get("action"), request.get("resource", "all"), request.get("value")))
            except SecurityError as error:
                context.abort(STATUS.get(error.status, grpc.StatusCode.INTERNAL), error.code)
            except Exception:
                context.abort(grpc.StatusCode.UNAVAILABLE, "service_unavailable")

        return grpc.unary_unary_rpc_method_handler(invoke)


def grpc_server(kernel, pki, host="127.0.0.1", port=50051):
    pki = Path(pki)
    # Validate expiry and key/certificate pairing before binding, not on first request.
    tls_context(pki, server=True)
    for name in ("server.pem", "ca.pem"):
        cert = x509.load_pem_x509_certificate((pki / name).read_bytes())
        if not cert.not_valid_before_utc <= datetime.now(timezone.utc) < cert.not_valid_after_utc:
            raise ValueError("TLS certificate is expired or not yet valid")
    credentials = grpc.ssl_server_credentials([
        ((pki / "server-key.pem").read_bytes(), (pki / "server.pem").read_bytes())],
        root_certificates=(pki / "ca.pem").read_bytes(), require_client_auth=True)
    server = grpc.server(ThreadPoolExecutor(max_workers=8),
                         interceptors=[SecurityInterceptor(kernel)], maximum_concurrent_rpcs=32,
                         options=[("grpc.max_receive_message_length", MAX_BODY),
                                  ("grpc.max_send_message_length", 1048576)])
    server.add_generic_rpc_handlers([grpc.method_handlers_generic_handler("securitykit.Vault", {
        "Call": grpc.unary_unary_rpc_method_handler(lambda _r, _c: b"{}")})])
    bound = server.add_secure_port(f"{host}:{port}", credentials)
    if not bound:
        raise RuntimeError("gRPC TLS port could not be bound")
    return server, bound


def grpc_channel(pki, target="localhost:50051"):
    pki = Path(pki)
    creds = grpc.ssl_channel_credentials(root_certificates=(pki / "ca.pem").read_bytes(),
        private_key=(pki / "client-key.pem").read_bytes(), certificate_chain=(pki / "client.pem").read_bytes())
    return grpc.secure_channel(target, creds, options=[("grpc.max_receive_message_length", 1048576)])


def grpc_call(channel, token, tenant, action, resource="all", value=None):
    call = channel.unary_unary("/securitykit.Vault/Call")
    return json.loads(call(canonical({"tenant": tenant, "action": action,
        "resource": resource, "value": value}), metadata=[("authorization", "Bearer " + token)], timeout=5))


def https_call(pki, token, tenant, action, resource="all", value=None, port=8443):
    from .core import identifier
    identifier(tenant)
    identifier(resource)
    method = {"read": "GET", "create": "POST", "update": "PUT", "delete": "DELETE", "audit": "GET"}[action]
    path = "audit" if action == "audit" else "secrets/" + resource
    data = canonical({"value": value}) if method in {"POST", "PUT"} else None
    req = Request(f"https://localhost:{port}/v1/tenants/{tenant}/{path}", data=data, method=method,
                  headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with urlopen(req, context=tls_context(pki), timeout=5) as response:
        return json.load(response)
