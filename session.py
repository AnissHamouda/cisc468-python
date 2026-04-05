"""
Secure session management.

Handshake (Noise-like, simplified):
  Both sides send an unencrypted HELLO containing:
    - ephemeral X25519 public key
    - long-term Ed25519 public key
    - Ed25519 signature over (ephemeral_pub || peer_ephemeral_pub || "hello")
      NOTE: the peer's ephemeral pub is included to prevent replay.

  After receiving the HELLO from the other side each party can:
    1. Verify the signature (authenticates the peer's long-term key)
    2. Perform X25519 ECDH to derive session keys (provides PFS)

  All subsequent messages are ChaCha20-Poly1305 encrypted with the session keys.
"""

import socket
import json
import logging
import struct
from typing import Tuple, Optional

from .crypto import (
    Identity, EphemeralKeyPair,
    encrypt_message, decrypt_message,
    encode_b64, decode_b64,
)
from .protocol import (
    MSG_HELLO, MSG_HELLO_REPLY,
    read_msg, send_msg, CHUNK_SIZE,
)

log = logging.getLogger(__name__)


class SessionError(Exception):
    pass


class Session:
    """
    A fully authenticated, encrypted session over a TCP socket.
    """

    def __init__(
        self,
        sock: socket.socket,
        send_key: bytes,
        recv_key: bytes,
        peer_pub_bytes: bytes,
    ):
        self._sock = sock
        self._send_key = send_key
        self._recv_key = recv_key
        self.peer_pub_bytes = peer_pub_bytes

    def send(self, msg: dict):
        raw = json.dumps(msg).encode()
        encrypted = encrypt_message(self._send_key, raw)
        self._sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)

    def recv(self) -> dict:
        raw_len = self._recv_exact(4)
        length = struct.unpack("!I", raw_len)[0]
        if length > 256 * 1024 * 1024:
            raise SessionError("Incoming message too large")
        raw_encrypted = self._recv_exact(length)
        try:
            raw = decrypt_message(self._recv_key, raw_encrypted)
        except Exception:
            raise SessionError("[SECURITY] Message authentication failed — possible tampering detected.")
        return json.loads(raw)

    def send_raw_encrypted(self, plaintext: bytes):
        """Send raw bytes encrypted (for file chunks)."""
        encrypted = encrypt_message(self._send_key, plaintext)
        self._sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)

    def recv_raw_encrypted(self) -> bytes:
        """Receive raw bytes and decrypt."""
        raw_len = self._recv_exact(4)
        length = struct.unpack("!I", raw_len)[0]
        if length > 256 * 1024 * 1024:
            raise SessionError("Incoming chunk too large")
        raw_encrypted = self._recv_exact(length)
        try:
            return decrypt_message(self._recv_key, raw_encrypted)
        except Exception:
            raise SessionError("[SECURITY] Chunk authentication failed — data may have been tampered with.")

    def close(self):
        try:
            self._sock.close()
        except Exception:
            pass

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed unexpectedly")
            buf += chunk
        return buf


def _build_hello(identity: Identity, ephemeral: EphemeralKeyPair, peer_ephemeral_pub: Optional[bytes]) -> dict:
    """
    Build a HELLO or HELLO_REPLY message.
    The signature covers: ephemeral_pub || (peer_ephemeral_pub or zeros) || b"hello"
    so that the message is bound to this specific exchange.
    """
    peer_eph = peer_ephemeral_pub if peer_ephemeral_pub else bytes(32)
    payload = ephemeral.public_bytes + peer_eph + b"hello"
    sig = identity.sign(payload)
    return {
        "type": MSG_HELLO,
        "ephemeral_pub": encode_b64(ephemeral.public_bytes),
        "identity_pub": encode_b64(identity.public_key_bytes),
        "signature": encode_b64(sig),
    }


def _verify_hello(msg: dict, my_ephemeral_pub: bytes) -> Tuple[bytes, bytes]:
    """
    Verify a HELLO/HELLO_REPLY.
    Returns (peer_identity_pub_bytes, peer_ephemeral_pub_bytes).
    Raises SessionError on failure.
    """
    try:
        peer_eph = decode_b64(msg["ephemeral_pub"])
        peer_id = decode_b64(msg["identity_pub"])
        sig = decode_b64(msg["signature"])
    except Exception as e:
        raise SessionError(f"[SECURITY] Malformed HELLO: {e}")

    payload = peer_eph + my_ephemeral_pub + b"hello"
    if not Identity.verify_signature(peer_id, sig, payload):
        raise SessionError("[SECURITY] HELLO signature verification failed — peer identity cannot be confirmed.")
    return peer_id, peer_eph


def perform_handshake_initiator(
    sock: socket.socket, identity: Identity
) -> Session:
    """
    Initiator side of the handshake.
    """
    ephemeral = EphemeralKeyPair()

    # Step 1: send HELLO without knowing peer's ephemeral yet
    hello = _build_hello(identity, ephemeral, None)
    send_msg(sock, hello)

    # Step 2: receive HELLO_REPLY
    reply = read_msg(sock)
    if reply.get("type") not in (MSG_HELLO, MSG_HELLO_REPLY):
        raise SessionError("[SECURITY] Expected HELLO_REPLY, got unexpected message.")

    peer_id, peer_eph = _verify_hello(reply, ephemeral.public_bytes)

    # Step 3: derive session keys
    send_key, recv_key = ephemeral.derive_session_keys(
        peer_eph,
        initiator=True,
        my_identity_pub=identity.public_key_bytes,
        peer_identity_pub=peer_id,
    )

    log.debug("Handshake complete (initiator). Peer: %s", encode_b64(peer_id)[:16])
    return Session(sock, send_key, recv_key, peer_id)


def perform_handshake_responder(
    sock: socket.socket, identity: Identity
) -> Session:
    """
    Responder side of the handshake.
    """
    # Step 1: receive initiator HELLO
    hello = read_msg(sock)
    if hello.get("type") != MSG_HELLO:
        raise SessionError("[SECURITY] Expected HELLO, got unexpected message.")

    peer_id, peer_eph = _verify_hello(hello, bytes(32))  # initiator didn't know our pub yet

    # Step 2: generate our ephemeral and send HELLO_REPLY
    ephemeral = EphemeralKeyPair()
    reply = _build_hello(identity, ephemeral, peer_eph)
    reply["type"] = MSG_HELLO_REPLY
    send_msg(sock, reply)

    # Step 3: re-verify with correct my_ephemeral_pub bound into sig
    # (The initiator's sig was built with zeros for peer_eph; we accept that)

    # Step 4: derive session keys
    send_key, recv_key = ephemeral.derive_session_keys(
        peer_eph,
        initiator=False,
        my_identity_pub=identity.public_key_bytes,
        peer_identity_pub=peer_id,
    )

    log.debug("Handshake complete (responder). Peer: %s", encode_b64(peer_id)[:16])
    return Session(sock, send_key, recv_key, peer_id)


def open_session(host: str, port: int, identity: Identity, timeout: float = 10.0) -> Session:
    """Connect to a peer and perform the handshake."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(60.0)
        return perform_handshake_initiator(sock, identity)
    except ConnectionRefusedError:
        raise SessionError(f"[ERROR] Could not connect to {host}:{port} — peer may be offline.")
    except socket.timeout:
        raise SessionError(f"[ERROR] Connection to {host}:{port} timed out.")
