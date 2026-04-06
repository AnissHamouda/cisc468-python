"""
crypto_utils.py — All cryptographic primitives for p2pshare.

Implements exactly the spec:
 - Ed25519 identity keys
 - Fingerprint = hex(sha256(raw_ed25519_pubkey))  → 64 hex chars
 - Argon2id key derivation  (time=3, mem=64MB, threads=4, key_len=32)
 - AES-256-GCM for at-rest encryption
 - X25519 ephemeral ECDH
 - HKDF-SHA256 for session key derivation
 - Session nonce counter (nonce_base XOR chunk_index last 8 bytes)
"""

import os
import json
import base64
import struct
import hashlib
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ARGON2_TIME = 3
ARGON2_MEMORY = 65536          # 64 MB in KiB
ARGON2_THREADS = 4
ARGON2_KEY_LEN = 32

CHUNK_SIZE = 524_288           # 512 KB
MAX_FRAME = 4_194_304          # 4 MB


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

def pubkey_to_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def fingerprint_from_bytes(raw_pub: bytes) -> str:
    """fingerprint = hex(sha256(raw_ed25519_pubkey))  → 64 lowercase hex chars"""
    return hashlib.sha256(raw_pub).hexdigest()


def fingerprint_of(pub: Ed25519PublicKey) -> str:
    return fingerprint_from_bytes(pubkey_to_bytes(pub))


# ---------------------------------------------------------------------------
# Argon2id
# ---------------------------------------------------------------------------

def argon2id_derive(password: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte key with Argon2id per spec."""
    kdf = Argon2id(
        salt=salt,
        length=ARGON2_KEY_LEN,
        iterations=ARGON2_TIME,
        lanes=ARGON2_THREADS,
        memory_cost=ARGON2_MEMORY,
        ad=None,
        secret=None,
    )
    return kdf.derive(password)


# ---------------------------------------------------------------------------
# AES-256-GCM helpers
# ---------------------------------------------------------------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Returns (nonce 12 bytes, ciphertext+tag)."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad or None)
    return nonce, ct


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad or None)


# ---------------------------------------------------------------------------
# Ed25519 Identity
# ---------------------------------------------------------------------------

class Identity:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._priv = private_key
        self._pub = private_key.public_key()
        self._raw_pub = pubkey_to_bytes(self._pub)
        self._fp = fingerprint_from_bytes(self._raw_pub)

    @classmethod
    def generate(cls) -> "Identity":
        return cls(Ed25519PrivateKey.generate())

    @property
    def fingerprint(self) -> str:
        return self._fp

    @property
    def raw_public_key(self) -> bytes:
        return self._raw_pub

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._pub

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)

    def _raw_seed(self) -> bytes:
        return self._priv.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    def save(self, path_prefix: str, password: str):
        """
        Save to:
          <path_prefix>/identity.key   → 12-byte nonce || ciphertext
          <path_prefix>/identity.key.meta → JSON {salt_b64, pubkey_b64}
        """
        salt = os.urandom(32)
        key = argon2id_derive(password.encode(), salt)
        nonce, ct = aes_gcm_encrypt(key, self._raw_seed())
        key_path = os.path.join(path_prefix, "identity.key")
        meta_path = os.path.join(path_prefix, "identity.key.meta")
        with open(key_path, "wb") as f:
            f.write(nonce + ct)
        with open(meta_path, "w") as f:
            json.dump({
                "salt": base64.b64encode(salt).decode(),
                "pubkey": base64.b64encode(self._raw_pub).decode(),
            }, f)
        os.chmod(key_path, 0o600)
        os.chmod(meta_path, 0o600)

    @classmethod
    def load(cls, path_prefix: str, password: str) -> "Identity":
        key_path = os.path.join(path_prefix, "identity.key")
        meta_path = os.path.join(path_prefix, "identity.key.meta")
        with open(meta_path) as f:
            meta = json.load(f)
        salt = base64.b64decode(meta["salt"])
        key = argon2id_derive(password.encode(), salt)
        with open(key_path, "rb") as f:
            blob = f.read()
        nonce, ct = blob[:12], blob[12:]
        seed = aes_gcm_decrypt(key, nonce, ct)
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        return cls(priv)

    @classmethod
    def exists(cls, path_prefix: str) -> bool:
        return os.path.exists(os.path.join(path_prefix, "identity.key"))


# ---------------------------------------------------------------------------
# Ed25519 signature verification (for remote public keys stored as raw bytes)
# ---------------------------------------------------------------------------

def ed25519_verify(raw_pub: bytes, signature: bytes, data: bytes) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(raw_pub)
        pub.verify(signature, data)
        return True
    except (InvalidSignature, Exception):
        return False


# ---------------------------------------------------------------------------
# X25519 ephemeral key pair
# ---------------------------------------------------------------------------

class EphemeralKeypair:
    def __init__(self):
        self._priv = X25519PrivateKey.generate()
        self._pub = self._priv.public_key()

    @property
    def public_bytes(self) -> bytes:
        return self._pub.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )

    def exchange(self, peer_pub_bytes: bytes) -> bytes:
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        return self._priv.exchange(peer_pub)


# ---------------------------------------------------------------------------
# HKDF session key derivation (spec §HKDF label strings)
# ---------------------------------------------------------------------------

class SessionKeys:
    """
    tx_key  : AES-256-GCM key  initiator→responder
    rx_key  : AES-256-GCM key  responder→initiator
    tx_nonce: 12-byte nonce base
    rx_nonce: 12-byte nonce base
    From responder's perspective tx/rx are swapped.
    """
    def __init__(self, tx_key, rx_key, tx_nonce, rx_nonce):
        self.tx_key = tx_key
        self.rx_key = rx_key
        self.tx_nonce_base = tx_nonce
        self.rx_nonce_base = rx_nonce

    @classmethod
    def derive(
        cls,
        shared_secret: bytes,
        initiator_nonce: bytes,
        responder_nonce: bytes,
        initiator_fp: str,
        responder_fp: str,
        is_initiator: bool,
    ) -> "SessionKeys":
        salt = bytes(a ^ b for a, b in zip(initiator_nonce, responder_nonce))
        info_base = ("CISC468-SESSION-V1" + initiator_fp + responder_fp).encode()

        def derive_label(label: str, length: int) -> bytes:
            return HKDF(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                info=info_base + label.encode(),
            ).derive(shared_secret)

        tx_key   = derive_label("TX",  32)
        rx_key   = derive_label("RX",  32)
        tx_nonce = derive_label("NTX", 12)
        rx_nonce = derive_label("NRX", 12)

        if is_initiator:
            return cls(tx_key, rx_key, tx_nonce, rx_nonce)
        else:
            # Responder swaps TX/RX
            return cls(rx_key, tx_key, rx_nonce, tx_nonce)


# ---------------------------------------------------------------------------
# Chunk nonce derivation
# ---------------------------------------------------------------------------

def chunk_nonce(nonce_base: bytes, chunk_index: int) -> bytes:
    """
    chunk_nonce = nonce_base XOR pad_left(uint64_be(chunk_index), 12)
    XOR applied to last 8 bytes.
    """
    idx_bytes = struct.pack(">Q", chunk_index)           # 8 bytes big-endian
    padded = b"\x00" * 4 + idx_bytes                    # 12 bytes
    return bytes(a ^ b for a, b in zip(nonce_base, padded))


# ---------------------------------------------------------------------------
# Chunk encryption / decryption
# ---------------------------------------------------------------------------

def encrypt_chunk(
    key: bytes,
    nonce_base: bytes,
    chunk_index: int,
    data: bytes,
    file_id: str,
    total_chunks: int,
    message_id: str,
) -> bytes:
    nonce = chunk_nonce(nonce_base, chunk_index)
    aad = f"{file_id}:{chunk_index}:{total_chunks}:{message_id}".encode()
    return AESGCM(key).encrypt(nonce, data, aad)


def decrypt_chunk(
    key: bytes,
    nonce_base: bytes,
    chunk_index: int,
    ciphertext: bytes,
    file_id: str,
    total_chunks: int,
    message_id: str,
) -> bytes:
    nonce = chunk_nonce(nonce_base, chunk_index)
    aad = f"{file_id}:{chunk_index}:{total_chunks}:{message_id}".encode()
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


# ---------------------------------------------------------------------------
# Random helpers
# ---------------------------------------------------------------------------

def random_nonce_32() -> bytes:
    return os.urandom(32)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)
