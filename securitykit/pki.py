"""Generate a fresh, short-lived development CA; no shared private keys ship."""
import ipaddress
import os
import secrets
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class TemporaryWorkspace:
    """Temporary directory with inherited Windows ACLs and POSIX 0700.

    Windows state permissions are inherited from the selected parent, as documented.
    """
    def __init__(self, prefix="securitykit-", dir=None):
        root = Path(dir) if dir else Path(tempfile.gettempdir())
        path = root / (prefix + secrets.token_hex(12))
        path.mkdir(mode=0o777 if os.name == "nt" else 0o700)
        self.name = str(path)

    def cleanup(self):
        shutil.rmtree(self.name)

    def __enter__(self):
        return self.name

    def __exit__(self, *_args):
        self.cleanup()


def private_write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as target:
        target.write(data)


def create_pki(directory):
    directory = Path(directory)
    directory.mkdir(mode=0o777 if os.name == "nt" else 0o700)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecurityKit Local Demo CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=False, decipher_only=False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    private_write(directory / "ca.pem", ca.public_bytes(serialization.Encoding.PEM))
    for name, usage in (("server", ExtendedKeyUsageOID.SERVER_AUTH), ("client", ExtendedKeyUsageOID.CLIENT_AUTH)):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost" if name == "server" else "demo-client")])
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca.subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                               key_encipherment=True, data_encipherment=False,
                                               key_agreement=False, key_cert_sign=False, crl_sign=False,
                                               encipher_only=False, decipher_only=False), critical=True))
        if name == "server":
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address("::1"))]), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())
        private_write(directory / f"{name}.pem", cert.public_bytes(serialization.Encoding.PEM))
        private_write(directory / f"{name}-key.pem", key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    # CA private key deliberately never written. Reinitialise development state to renew.
