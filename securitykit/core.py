"""Tenant RBAC, authenticated encryption and transactional audit.

Inspired by Tencent/WeKnora (see UPSTREAM.md); independently implemented.
Only server-resolved memberships are authoritative. Never use client role headers.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LEVELS = {"viewer": 10, "contributor": 20, "admin": 30, "owner": 40}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
MAX_VALUE = 16384


class SecurityError(Exception):
    def __init__(self, status: int, code: str):
        self.status, self.code = status, code
        super().__init__(code)


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def identifier(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise SecurityError(400, "invalid_identifier")
    return value


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value, altchars=b"-_", validate=True)


@dataclass(frozen=True)
class Principal:
    subject: str
    memberships: object

    def role(self, tenant):
        return self.memberships.get(tenant)


class CipherBox:
    """AES-256-GCM envelope with key IDs and tenant/resource-bound AAD."""
    def __init__(self, keys, active_key):
        self.keys = {identifier(k): bytes(v) for k, v in keys.items()}
        if not self.keys or any(len(k) != 32 for k in self.keys.values()):
            raise ValueError("AES keys must contain exactly 32 random bytes")
        if active_key not in self.keys:
            raise ValueError("active encryption key is missing")
        self.active_key = active_key

    @staticmethod
    def aad(tenant, resource, key_id):
        return canonical(["BackendSecurityKit", 1, identifier(tenant),
                          "secret", identifier(resource), identifier(key_id)])

    def encrypt(self, value: str, tenant: str, resource: str) -> str:
        if not isinstance(value, str) or len(value.encode("utf8")) > MAX_VALUE:
            raise SecurityError(400, "invalid_value")
        nonce = os.urandom(12)
        kid = self.active_key
        data = AESGCM(self.keys[kid]).encrypt(nonce, value.encode("utf8"),
                                            self.aad(tenant, resource, kid))
        return canonical({"v": 1, "kid": kid, "nonce": b64(nonce), "data": b64(data)}).decode()

    def decrypt(self, envelope: str, tenant: str, resource: str) -> str:
        try:
            item = json.loads(envelope)
            if set(item) != {"v", "kid", "nonce", "data"} or type(item["v"]) is not int or item["v"] != 1:
                raise ValueError()
            kid = item["kid"]
            nonce, data = unb64(item["nonce"]), unb64(item["data"])
            if len(nonce) != 12 or len(data) < 16 or len(data) > MAX_VALUE + 16:
                raise ValueError()
            return AESGCM(self.keys[kid]).decrypt(
                nonce, data, self.aad(tenant, resource, kid)).decode("utf8")
        except (ValueError, TypeError, KeyError, InvalidTag, UnicodeError):
            raise SecurityError(503, "encrypted_data_unavailable") from None


SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
    tenant TEXT NOT NULL, id TEXT NOT NULL, owner TEXT NOT NULL,
    envelope TEXT NOT NULL, PRIMARY KEY(tenant,id));
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY, tenant TEXT NOT NULL, event TEXT NOT NULL,
    previous TEXT NOT NULL, tag TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_tenant ON audit(tenant,seq);
"""


class SecurityKernel:
    """Trusted policy API: run a DB operation and its success audit atomically.

    Policy arguments and callbacks come from server code, never request JSON.
    Callbacks must use the supplied transaction for all business DB mutations.
    External effects need a transactional outbox; they cannot be rolled back here.
    """
    def __init__(self, database, cipher, audit_key, credentials):
        self.database = Path(database)
        self.cipher = cipher
        if len(audit_key) != 32 or audit_key in cipher.keys.values():
            raise ValueError("audit HMAC key must be independent and 32 bytes")
        self.audit_key = bytes(audit_key)
        self.credentials = dict(credentials)
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with closing(self.connect()) as tx:
            tx.executescript(SCHEMA)
            tx.execute("PRAGMA journal_mode=WAL")
        self.verify_audit()

    def connect(self):
        tx = sqlite3.connect(self.database, timeout=5, isolation_level=None)
        tx.row_factory = sqlite3.Row
        tx.execute("PRAGMA synchronous=FULL")
        tx.execute("PRAGMA busy_timeout=5000")
        return tx

    def authenticate(self, authorization):
        if not isinstance(authorization, str) or len(authorization) > 512:
            raise SecurityError(401, "unauthenticated")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not 32 <= len(token) <= 256 or not token.isascii():
            raise SecurityError(401, "unauthenticated")
        hashed = hashlib.sha256(token.encode("ascii")).hexdigest()
        record = self.credentials.get(hashed)
        if not record or record.get("disabled") is not False or record["expires_at"] <= time.time():
            raise SecurityError(401, "unauthenticated")
        return Principal(record["subject"], MappingProxyType(dict(record["memberships"])))

    def append_audit(self, tx, *, tenant, actor, role, action, resource, outcome, code, request_id):
        # Explicit schema: no headers, bodies, values, tokens, exception text or URLs.
        row = tx.execute("SELECT seq,tag FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
        seq, previous = (row["seq"] + 1, row["tag"]) if row else (1, "0" * 64)
        event = {"seq": seq, "time": datetime.now(timezone.utc).isoformat(),
                 "tenant": tenant, "actor": actor, "role": role, "action": action,
                 "resource": resource, "outcome": outcome, "code": code,
                 "request_id": request_id}
        payload = canonical(event).decode()
        tag = hmac.new(self.audit_key, previous.encode() + b"\n" + payload.encode(), hashlib.sha256).hexdigest()
        tx.execute("INSERT INTO audit VALUES (?,?,?,?,?)", (seq, tenant, payload, previous, tag))

    def run(self, authorization, tenant, action, resource, required, operation, owner_lookup=None):
        identifier(tenant)
        identifier(resource)
        identifier(action)
        if required not in LEVELS:
            raise ValueError("unknown required role")
        principal, role, request_id = None, None, uuid.uuid4().hex
        with closing(self.connect()) as tx:
            try:
                tx.execute("BEGIN IMMEDIATE")
                principal = self.authenticate(authorization)
                role = principal.role(tenant)
                if role not in LEVELS:
                    raise SecurityError(403, "forbidden")
                if LEVELS[role] < LEVELS[required]:
                    own = (owner_lookup is not None and LEVELS[role] >= LEVELS["contributor"]
                           and owner_lookup(tx, principal) == principal.subject)
                    if not own:
                        raise SecurityError(403, "forbidden")
                result = operation(tx, principal)
                self.append_audit(tx, tenant=tenant, actor=principal.subject, role=role,
                                  action=action, resource=resource, outcome="success",
                                  code="ok", request_id=request_id)
                tx.commit()
                return result
            except SecurityError as error:
                tx.rollback()
                # Audit denial/error separately after undoing a failed business operation.
                try:
                    tx.execute("BEGIN IMMEDIATE")
                    # Cross-tenant attempts belong to a neutral scope, not the victim tenant.
                    scope = tenant if role in LEVELS else "_system"
                    self.append_audit(tx, tenant=scope,
                                      actor=principal.subject if principal else None, role=role,
                                      action=action, resource=resource,
                                      outcome="denied" if error.status in (401, 403) else "error",
                                      code=error.code, request_id=request_id)
                    tx.commit()
                except Exception:
                    tx.rollback()
                    raise SecurityError(503, "audit_unavailable") from None
                raise
            except Exception:
                tx.rollback()
                try:
                    tx.execute("BEGIN IMMEDIATE")
                    self.append_audit(tx, tenant=tenant if role in LEVELS else "_system",
                                      actor=principal.subject if principal else None, role=role,
                                      action=action, resource=resource, outcome="error",
                                      code="operation_failed", request_id=request_id)
                    tx.commit()
                except Exception:
                    tx.rollback()
                    raise SecurityError(503, "audit_unavailable") from None
                raise SecurityError(503, "storage_or_audit_unavailable") from None

    def verify_audit(self, checkpoint=None):
        if not self.database.is_file():
            raise SecurityError(503, "audit_database_missing")
        previous, seq, anchor = "0" * 64, 0, checkpoint is None
        with closing(self.connect()) as tx:
            tx.execute("BEGIN")  # Consistent read snapshot during concurrent writers.
            for row in tx.execute("SELECT * FROM audit ORDER BY seq"):
                seq += 1
                event = json.loads(row["event"])
                calculated = hmac.new(self.audit_key,
                                      previous.encode() + b"\n" + row["event"].encode(), hashlib.sha256).hexdigest()
                if (row["seq"] != seq or event["seq"] != seq or event["tenant"] != row["tenant"]
                        or row["previous"] != previous or not hmac.compare_digest(row["tag"], calculated)):
                    raise SecurityError(503, "audit_integrity_failed")
                previous = row["tag"]
                if checkpoint and checkpoint["seq"] == seq:
                    anchor = hmac.compare_digest(checkpoint["tag"], previous)
            if checkpoint and checkpoint["seq"] == 0:
                anchor = checkpoint["tag"] == "0" * 64
            if not anchor:
                raise SecurityError(503, "audit_checkpoint_mismatch")
        return {"seq": seq, "tag": previous}


class Vault:
    """Small example domain using the reusable SecurityKernel."""
    def __init__(self, kernel):
        self.kernel = kernel

    def call(self, authorization, tenant, action, resource="all", value=None):
        if not isinstance(action, str) or action not in {"read", "create", "update", "delete", "audit"}:
            raise SecurityError(400, "unknown_action")
        required = {"read": "viewer", "create": "contributor", "update": "admin",
                    "delete": "admin", "audit": "admin"}[action]

        def owner(tx, principal):
            row = tx.execute("SELECT owner FROM secrets WHERE tenant=? AND id=?", (tenant, resource)).fetchone()
            return row["owner"] if row else None

        def operation(tx, principal):
            if action == "audit":
                return {"events": [json.loads(r["event"]) for r in tx.execute(
                    "SELECT event FROM audit WHERE tenant=? ORDER BY seq DESC LIMIT 100", (tenant,))]}
            row = tx.execute("SELECT * FROM secrets WHERE tenant=? AND id=?", (tenant, resource)).fetchone()
            if action == "create":
                if row:
                    raise SecurityError(409, "already_exists")
                envelope = self.kernel.cipher.encrypt(value, tenant, resource)
                tx.execute("INSERT INTO secrets VALUES (?,?,?,?)", (tenant, resource, principal.subject, envelope))
                return {"id": resource, "created": True}
            if not row:
                raise SecurityError(404, "not_found")
            if action == "read":
                return {"id": resource, "value": self.kernel.cipher.decrypt(row["envelope"], tenant, resource)}
            if action == "update":
                envelope = self.kernel.cipher.encrypt(value, tenant, resource)
                tx.execute("UPDATE secrets SET envelope=? WHERE tenant=? AND id=?", (envelope, tenant, resource))
            elif action == "delete":
                tx.execute("DELETE FROM secrets WHERE tenant=? AND id=?", (tenant, resource))
            return {"id": resource, "changed": True}

        return self.kernel.run(authorization, tenant, "secrets." + action, resource,
                               required, operation, owner if action in {"update", "delete"} else None)


def load_kernel(state):
    state = Path(state)
    config = json.loads((state / "server.json").read_text("utf8"))
    if config.get("version") != 1 or not isinstance(config.get("credentials"), dict):
        raise ValueError("invalid configuration")
    for digest, record in config["credentials"].items():
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("invalid token hash")
        identifier(record["subject"])
        if type(record["disabled"]) is not bool or type(record["expires_at"]) not in (int, float):
            raise ValueError("invalid credential status")
        if not record["memberships"]:
            raise ValueError("empty membership")
        for tenant, role in record["memberships"].items():
            identifier(tenant)
            if role not in LEVELS:
                raise ValueError("unknown role")
    box = CipherBox({k: unb64(v) for k, v in config["encryption_keys"].items()}, config["active_key"])
    return SecurityKernel(state / "security.db", box, unb64(config["audit_key"]), config["credentials"])
