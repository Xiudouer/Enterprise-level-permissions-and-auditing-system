"""Whitelist packager. Runtime state is never copied, even if present in source.

Run tests/build verification first. Never point dist-dir to a user data directory.
"""
import argparse
import hashlib
import json
import pathlib
import re
import shutil
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOP_FILES = ("README.md", "UPSTREAM.md", "LICENSE", "THIRD-PARTY.md", "TEST-RESULTS.md",
             "RELEASE-INFO.json", "requirements.txt", "pyproject.toml", ".gitignore", "run.py", "demo.bat", "start.bat", "build-windows.ps1")
SOURCE_DIRS = {"securitykit": {".py"}, "tests": {".py"}, "examples": {".py", ".txt"},
               "scripts": {".py"}, "licenses": None}
FORBIDDEN = {"server.json", "clients.json", "security.db", "security.db-wal", "security.db-shm"}


def assemble(destination, dist=None):
    for name in TOP_FILES:
        shutil.copyfile(ROOT / name, destination / name)
    for directory, suffixes in SOURCE_DIRS.items():
        for file in (ROOT / directory).rglob("*"):
            if not file.is_file() or "__pycache__" in file.parts or file.name in FORBIDDEN:
                continue
            if suffixes is not None and file.suffix not in suffixes:
                continue
            target = destination / file.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(file, target)
    if dist:
        dist = dist.resolve()
        if not (dist / "BackendSecurityKit.exe").is_file() or not (dist / "_internal").is_dir():
            raise RuntimeError("Expected verified PyInstaller onedir output")
        shutil.copyfile(dist / "BackendSecurityKit.exe", destination / "BackendSecurityKit.exe")
        shutil.copytree(dist / "_internal", destination / "_internal")
    files = sorted(f for f in destination.rglob("*") if f.is_file())
    private_pattern = re.compile(rb"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----\r?\n[A-Za-z0-9+/]")
    if any(f.name in FORBIDDEN or (f.suffix == ".pem" and "_internal" not in f.relative_to(destination).parts)
           or private_pattern.search(f.read_bytes()) for f in files):
        raise RuntimeError("Private runtime state found in release")
    manifest = {f.relative_to(destination).as_posix(): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    (destination / "MANIFEST.sha256.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=pathlib.Path, default=ROOT / "releases")
    parser.add_argument("--dist-dir", type=pathlib.Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    kind = "Windows-x64" if args.dist_dir else "Source"
    archive = args.output / f"BackendSecurityKit-1.0.0-{kind}.zip"
    checksum = pathlib.Path(str(archive) + ".sha256")
    if archive.exists() or checksum.exists():
        raise FileExistsError("Release already exists; choose a new output directory")
    with tempfile.TemporaryDirectory(prefix="securitykit-release-") as temporary:
        stage = pathlib.Path(temporary) / "BackendSecurityKit"
        stage.mkdir()
        assemble(stage, args.dist_dir)
        with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as zipped:
            for file in sorted(stage.rglob("*")):
                if file.is_file():
                    zipped.write(file, file.relative_to(stage.parent).as_posix())
        with zipfile.ZipFile(archive) as zipped:
            if zipped.testzip() is not None:
                raise RuntimeError("ZIP integrity check failed")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum.write_text(digest + "  " + archive.name + "\n", encoding="ascii")
    print(archive.name, digest)


if __name__ == "__main__":
    main()
