"""
tls_utils.py — TLS 1.3 setup for p2pshare.

Each peer generates a self-signed X.509 certificate bound to their Ed25519 identity.
TLS provides the transport encryption layer; our application-layer handshake
(HANDSHAKE_INIT/RESP with X25519 + HKDF) provides PFS session keys for file chunks.

We use Python's ssl module with PROTOCOL_TLS_CLIENT / PROTOCOL_TLS_SERVER,
forcing TLS 1.3 minimum.
"""

import ssl
import os
import tempfile
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from crypto_utils import Identity


def _generate_cert_for_identity(identity: Identity) -> tuple[bytes, bytes]:
    """
    Generate a self-signed X.509 certificate using the Ed25519 identity key.
    Returns (cert_pem, key_pem).
    """
    # Access the private key object directly
    priv = identity._priv

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, identity.fingerprint[:32]),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(identity.public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(priv, None)  # Ed25519 doesn't use a hash algorithm parameter
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _write_temp_pem(data: bytes, suffix: str) -> str:
    """Write PEM data to a temp file and return path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def make_server_ssl_context(identity: Identity) -> tuple[ssl.SSLContext, str, str]:
    """
    Create an SSL server context with TLS 1.3.
    Returns (ctx, cert_tmp_path, key_tmp_path) — caller should clean up temp files.
    """
    cert_pem, key_pem = _generate_cert_for_identity(identity)
    cert_path = _write_temp_pem(cert_pem, ".crt")
    key_path  = _write_temp_pem(key_pem, ".key")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert_path, key_path)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # We do our own identity verification
    return ctx, cert_path, key_path


def make_client_ssl_context() -> ssl.SSLContext:
    """
    Create an SSL client context with TLS 1.3.
    We don't verify the server cert via CA chain — identity is verified
    at the application layer via Ed25519 fingerprint matching.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
