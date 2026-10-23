# Verification record

Build date: 2026-10-19. Target: Windows x64, CPython 3.12.14; cryptography 48.0.0,
grpcio 1.84.0. Unit/integration runner: Python standard-library unittest.

## Source tests

`python -m unittest discover -s tests -v`: **24 tests passed** on the target runtime.

- AES-GCM roundtrip, no secret plaintext in stored envelope, context binding to
  tenant/resource, wrong keys/tags rejected, plaintext input rejected on decrypt,
  key ID rotation and distinct nonces.
- Viewer denied writes even when named resource owner; Contributor own-resource
  update allowed, other-creator mutation denied; Admin override within tenant.
- Cross-tenant Owner denied for read/create/update/delete/audit; same resource ID
  in two tenants remains isolated; invalid, expired and disabled tokens rejected.
- Metadata-only audit; record alteration detected; tail deletion detected against
  an external checkpoint; audit insert failure rolls back secret creation;
  callback failure rolls back business state and records a safe error.
- Tenant-scoped audit list restricted to Admin/Owner; 24 concurrent writers create
  a valid, ordered HMAC chain.
- Input sizes/types/identifiers, duplicate JSON fields, NaN, unknown required
  role, forged role/tenant headers and insecure WSGI scheme.
- Real localhost HTTPS mTLS and gRPC mTLS share policy/storage; missing client
  certificate, wrong CA, wrong server name, plaintext transport, duplicate auth,
  unknown RPC and oversized RPC rejected. TLS failures can surface as UNAVAILABLE
  or DEADLINE_EXCEEDED depending on gRPC connection scheduling; both indicate no
  successful business RPC.

## CI

GitHub Actions `tests` (ubuntu-latest, CPython 3.12) passed all 24 tests on 2026-10-23, including real loopback HTTPS/gRPC mTLS. This covers the source test suite only, not the production deployment boundaries above.

## Portable and release verification

The 1.0.0 release metadata is in RELEASE-INFO.json. Archive CRC, manifest and
portable-executable checks belong to the separately distributed Windows package
and are not part of this source repository. The source demo makes real local
HTTPS and gRPC calls with newly generated certificates and credentials; it does
not mock TLS or encryption.

## Limits

Tests are correctness checks, not a penetration test, external audit or compliance
certification. No public deployment, cluster/KMS/WORM integration, certificate
revocation service, load test or long-running soak test was performed. See README
for the Windows ACL, nonce lifecycle, audit anchoring and production deployment
boundaries.
