# Third-party notices

BackendSecurityKit application sources are independently implemented under the
MIT license in [LICENSE](LICENSE). WeKnora is used as a source design reference;
its complete upstream LICENSE is retained in `licenses/WeKnora-LICENSE.txt`.
See [UPSTREAM.md](UPSTREAM.md) for the fixed commit and intentional differences.

This source repository does **not** distribute Python wheels, the Windows EXE,
`_internal/`, certificates or runtime databases. The optional portable build and
the dependency wheels contain these components; their original notices ship with
those artifacts.

| Component | Version | License |
|---|---|---|
| CPython | 3.12 (portable build) | Python Software Foundation license and bundled notices |
| cryptography | 48.0.0 | Apache-2.0 OR BSD-3-Clause |
| grpcio | 1.84.0 | Apache-2.0 and bundled third-party notices |
| cffi | 2.1.1 | MIT |
| pycparser | 3.11 | BSD-3-Clause |
| typing_extensions | 4.16.0 | Python Software Foundation license |
| OpenSSL (CPython ssl) | 3.5.8 (portable build) | Apache-2.0 |
| PyInstaller bootloader/build tool | 6.16.0 (build only) | GPL with bootloader exception |

cryptography bundles OpenSSL; grpcio bundles native third-party code including
BoringSSL. Their licenses are separate from the MIT license of this application.
The full portable package retains the corresponding LICENSE/COPYING/NOTICE/AUTHORS
files, including `licenses/grpc-third-party/` and its `SOURCES.json`.

Dependencies are obtained from official PyPI wheels; the 1.0.0 wheel hashes are
recorded in [RELEASE-INFO.json](RELEASE-INFO.json). This is not a Tencent, Python,
OpenSSL or gRPC official distribution.
