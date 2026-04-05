"""
Cryptographic identity and primitives for P2P Share.

Identity:
  - Ed25519 signing key pair (long-term identity)
  - X25519 key exchange (ephemeral, for PFS)

Encryption:
  - AES-256-GCM for file encryption (stored files)
  - ChaCha20-Poly1305 for in-transit encryption
  - HKDF for key derivation

File integrity:
  - SHA-256 hash signed by the origin peer's Ed25519 key
  - Recipients can verify even when downloading from a third party (req. 5)

Key storage:
  - Identity key encrypted with a password-derived key (Argon2id -> AES-GCM)
  - Stored files encrypted with a master file key, itself sealed with the identity key
"""

import os
import json
import hashlib
import base64
import struct
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint(pub_key_bytes: bytes) -> str:
    """Return a human-readable colon-separated hex fingerprint of a public key."""
    h = hashlib.sha256(pub_key_bytes).hexdigest().upper()
    return ":".join(h[i:i+4] for i in range(0, 32, 4))


def encode_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def decode_b64(s: str) -> bytes:
    return base64.b64decode(s)


# ---------------------------------------------------------------------------
# Password-based key derivation (for protecting the identity key on disk)
# ---------------------------------------------------------------------------

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from a password using scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    return kdf.derive(password.encode())


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

class Identity:
    """
    Long-term Ed25519 signing identity.
    The public key bytes (raw 32 bytes) serve as the canonical identity.
    """

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        self._public_key = private_key.public_key()
        self._pub_bytes = self._public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

    # --- properties ---

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    @property
    def public_key_bytes(self) -> bytes:
        return self._pub_bytes

    @property
    def fingerprint(self) -> str:
        return fingerprint(self._pub_bytes)

    # --- signing ---

    def sign(self, data: bytes) -> bytes:
        return self._private_key.sign(data)

    # --- serialization ---

    def to_encrypted_dict(self, password: str) -> dict:
        """Serialize the private key, encrypted with the given password."""
        salt = random_bytes(32)
        key = derive_key_from_password(password, salt)
        priv_raw = self._private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )
        nonce = random_bytes(12)
        ct = AESGCM(key).encrypt(nonce, priv_raw, None)
        return {
            "version": 1,
            "salt": encode_b64(salt),
            "nonce": encode_b64(nonce),
            "ciphertext": encode_b64(ct),
        }

    @classmethod
    def from_encrypted_dict(cls, d: dict, password: str) -> "Identity":
        salt = decode_b64(d["salt"])
        nonce = decode_b64(d["nonce"])
        ct = decode_b64(d["ciphertext"])
        key = derive_key_from_password(password, salt)
        try:
            priv_raw = AESGCM(key).decrypt(nonce, ct, None)
        except InvalidTag:
            raise ValueError("Wrong password or corrupted identity key file.")
        private_key = Ed25519PrivateKey.from_private_bytes(priv_raw)
        return cls(private_key)

    @classmethod
    def generate(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate())

    # --- verification (class method, works on arbitrary public keys) ---

    @staticmethod
    def verify_signature(pub_bytes: bytes, signature: bytes, data: bytes) -> bool:
        try:
            pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub.verify(signature, data)
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Ephemeral X25519 key exchange (Perfect Forward Secrecy)
# ---------------------------------------------------------------------------

class EphemeralKeyPair:
    """One-time X25519 key pair for a single session."""

    def __init__(self):
        self._priv = X25519PrivateKey.generate()
        self._pub = self._priv.public_key()

    @property
    def public_bytes(self) -> bytes:
        return self._pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

    def exchange(self, peer_pub_bytes: bytes) -> bytes:
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        return self._priv.exchange(peer_pub)

    def derive_session_keys(
        self,
        peer_pub_bytes: bytes,
        initiator: bool,
        my_identity_pub: bytes,
        peer_identity_pub: bytes,
    ) -> Tuple[bytes, bytes]:
        """
        Perform X25519 ECDH and derive two 32-byte session keys via HKDF:
          - send_key  (initiator->responder)
          - recv_key  (responder->initiator)
        Returns (send_key, recv_key) from the caller's perspective.
        """
        shared_secret = self.exchange(peer_pub_bytes)
        # Bind to both identity public keys (sorted so both sides produce the same info).
        id_keys = sorted([my_identity_pub, peer_identity_pub])
        info = b"p2p-share-session-v1" + id_keys[0] + id_keys[1]
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=info,
        )
        key_material = hkdf.derive(shared_secret)
        k1, k2 = key_material[:32], key_material[32:]
        if initiator:
            return k1, k2   # send=k1, recv=k2
        else:
            return k2, k1   # send=k2, recv=k1


# ---------------------------------------------------------------------------
# Symmetric encryption helpers (ChaCha20-Poly1305 for transport)
# ---------------------------------------------------------------------------

def encrypt_message(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Encrypt with ChaCha20-Poly1305. Returns nonce||ciphertext."""
    nonce = random_bytes(12)
    ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt_message(key: bytes, data: bytes, aad: bytes = b"") -> bytes:
    """Decrypt ChaCha20-Poly1305. Raises InvalidTag on failure."""
    nonce, ct = data[:12], data[12:]
    return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)


# ---------------------------------------------------------------------------
# File encryption (AES-256-GCM, for local storage)
# ---------------------------------------------------------------------------

def encrypt_file(file_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt file contents for local storage. Returns nonce||ciphertext."""
    nonce = random_bytes(12)
    ct = AESGCM(file_key).encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_file(file_key: bytes, data: bytes) -> bytes:
    """Decrypt file from local storage."""
    nonce, ct = data[:12], data[12:]
    try:
        return AESGCM(file_key).decrypt(nonce, ct, None)
    except InvalidTag:
        raise ValueError("[SECURITY] File decryption failed: data may be corrupted or tampered.")


def generate_file_key() -> bytes:
    """Generate a random 256-bit file encryption key."""
    return random_bytes(32)


# ---------------------------------------------------------------------------
# Master file-key management
# ---------------------------------------------------------------------------

class FileKeyStore:
    """
    Manages a per-file encryption key store.
    The store itself is encrypted under a master key derived from the identity key.
    """

    def __init__(self, identity: Identity, store_path: str):
        self._path = store_path
        # Derive master key from identity signing key bytes (deterministic)
        priv_raw = identity._private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"file-key-store-v1",
            info=b"master-file-key",
        )
        self._master_key = hkdf.derive(priv_raw)
        self._store: dict = {}  # filename -> hex key
        self._load()

    def _load(self):
        if not os.path.exists(self._path):
            return
        with open(self._path, "rb") as f:
            raw = f.read()
        if not raw:
            return
        try:
            nonce, ct = raw[:12], raw[12:]
            plaintext = AESGCM(self._master_key).decrypt(nonce, ct, None)
            self._store = json.loads(plaintext)
        except Exception:
            self._store = {}

    def _save(self):
        plaintext = json.dumps(self._store).encode()
        nonce = random_bytes(12)
        ct = AESGCM(self._master_key).encrypt(nonce, plaintext, None)
        with open(self._path, "wb") as f:
            f.write(nonce + ct)
        os.chmod(self._path, 0o600)

    def get_or_create(self, filename: str) -> bytes:
        if filename not in self._store:
            key = generate_file_key()
            self._store[filename] = encode_b64(key)
            self._save()
        return decode_b64(self._store[filename])

    def get(self, filename: str) -> Optional[bytes]:
        v = self._store.get(filename)
        return decode_b64(v) if v else None

    def remove(self, filename: str):
        self._store.pop(filename, None)
        self._save()
