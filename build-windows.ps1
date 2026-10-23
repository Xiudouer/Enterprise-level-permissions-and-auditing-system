$ErrorActionPreference = 'Stop'
Push-Location -LiteralPath $PSScriptRoot
try {
    python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
    python -m PyInstaller --noconfirm --onedir --name BackendSecurityKit --paths . --collect-all grpc --collect-all cryptography --copy-metadata grpcio --copy-metadata cryptography --distpath build/dist --workpath build/work --specpath build run.py
    if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
    & .\build\dist\BackendSecurityKit\BackendSecurityKit.exe demo
    if ($LASTEXITCODE -ne 0) { throw 'Executable verification failed' }
    python scripts/build_release.py --dist-dir build/dist/BackendSecurityKit
    if ($LASTEXITCODE -ne 0) { throw 'Packaging failed' }
} finally {
    Pop-Location
}
