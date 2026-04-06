"""
protocol.py — Wire protocol implementation for p2pshare.

Frame format: [4-byte big-endian uint32 length][UTF-8 JSON payload]
Max frame: 4 MB

Envelope:
  { "from": fp, "id": uuid, "payload": {...}, "sig": b64, "type": TYPE, "v": 1 }

Canonical form for signing (sorted keys, specific order):
  {"v":1,"type":"...","id":"...","from":"...","payload":{...}}
"""

import json
import uuid
import struct
import socket
import base64
import hashlib
from typing import Any, Optional

from crypto_utils import Identity, ed25519_verify, b64e, b64d, MAX_FRAME

# ---------------------------------------------------------------------------
# Message type constants
# ---------------------------------------------------------------------------
MSG_HELLO               = "HELLO"
MSG_CONTACT_REQUEST     = "CONTACT_REQUEST"
MSG_CONTACT_ACCEPT      = "CONTACT_ACCEPT"
MSG_HANDSHAKE_INIT      = "HANDSHAKE_INIT"
MSG_HANDSHAKE_RESP      = "HANDSHAKE_RESP"
MSG_LIST_FILES_REQUEST  = "LIST_FILES_REQUEST"
MSG_LIST_FILES_RESPONSE = "LIST_FILES_RESPONSE"
MSG_FILE_REQUEST        = "FILE_REQUEST"
MSG_FILE_APPROVE        = "FILE_APPROVE"
MSG_FILE_DENY           = "FILE_DENY"
MSG_TRANSFER_START      = "TRANSFER_START"
MSG_CHUNK               = "CHUNK"
MSG_TRANSFER_DONE       = "TRANSFER_DONE"
MSG_KEY_ROTATE_NOTICE   = "KEY_ROTATE_NOTICE"
MSG_ERROR               = "ERROR"

# Types that REQUIRE a signature
SIGNED_TYPES = {
    MSG_HELLO,
    MSG_CONTACT_REQUEST,
    MSG_CONTACT_ACCEPT,
    MSG_HANDSHAKE_INIT,
    MSG_HANDSHAKE_RESP,
    MSG_KEY_ROTATE_NOTICE,
    MSG_TRANSFER_START,
}


# ---------------------------------------------------------------------------
# Canonical envelope for signing
# ---------------------------------------------------------------------------

def canonical_for_signing(msg_type: str, msg_id: str, from_fp: str, payload: dict) -> bytes:
    """
    {"v":1,"type":"...","id":"...","from":"...","payload":{...}}
    Keys in exactly that order, serialised with separators=(',',':').
    """
    d = {"v": 1, "type": msg_type, "id": msg_id, "from": from_fp, "payload": payload}
    # We must preserve key order as specified in the spec
    ordered = '{"v":1,"type":' + json.dumps(msg_type) + \
              ',"id":' + json.dumps(msg_id) + \
              ',"from":' + json.dumps(from_fp) + \
              ',"payload":' + json.dumps(payload, separators=(',', ':'), sort_keys=True) + \
              '}'
    return ordered.encode()


# ---------------------------------------------------------------------------
# Build a signed envelope
# ---------------------------------------------------------------------------

def build_envelope(
    identity: Identity,
    msg_type: str,
    payload: dict,
    msg_id: Optional[str] = None,
) -> dict:
    if msg_id is None:
        msg_id = str(uuid.uuid4())
    env = {
        "from": identity.fingerprint,
        "id": msg_id,
        "payload": payload,
        "sig": "",
        "type": msg_type,
        "v": 1,
    }
    if msg_type in SIGNED_TYPES:
        canon = canonical_for_signing(msg_type, msg_id, identity.fingerprint, payload)
        sig_bytes = identity.sign(canon)
        env["sig"] = b64e(sig_bytes)
    return env


# ---------------------------------------------------------------------------
# Verify envelope signature
# ---------------------------------------------------------------------------

def verify_envelope(env: dict, raw_pub: bytes) -> bool:
    """
    Verify the Ed25519 signature on an envelope.
    Returns True if valid or if type doesn't require a signature.
    """
    msg_type = env.get("type", "")
    if msg_type not in SIGNED_TYPES:
        return True
    sig_b64 = env.get("sig", "")
    if not sig_b64:
        return False
    try:
        sig = b64d(sig_b64)
    except Exception:
        return False
    canon = canonical_for_signing(
        msg_type,
        env["id"],
        env["from"],
        env["payload"],
    )
    return ed25519_verify(raw_pub, sig, canon)


# ---------------------------------------------------------------------------
# Frame I/O — works on raw sockets (after TLS wrapping)
# ---------------------------------------------------------------------------

def send_frame(sock: socket.socket, envelope: dict):
    """Serialise envelope (sorted keys) and send with 4-byte length prefix."""
    data = json.dumps(envelope, separators=(',', ':'), sort_keys=True).encode()
    if len(data) > MAX_FRAME:
        raise ValueError(f"Frame too large: {len(data)} bytes")
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_frame(sock: socket.socket) -> dict:
    """Receive one length-prefixed frame and return parsed envelope."""
    raw_len = _recv_exact(sock, 4)
    length = struct.unpack("!I", raw_len)[0]
    if length > MAX_FRAME:
        raise ValueError(f"Frame too large: {length} bytes")
    raw = _recv_exact(sock, length)
    return json.loads(raw)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf


# ---------------------------------------------------------------------------
# Manifest canonical JSON
# ---------------------------------------------------------------------------

def canonical_manifest(
    file_id: str,
    filename: str,
    original_owner: str,
    sha256_hex: str,
    size: int,
    timestamp: str,
) -> bytes:
    """Alphabetically sorted keys as required by spec."""
    d = {
        "file_id": file_id,
        "filename": filename,
        "original_owner": original_owner,
        "sha256_hex": sha256_hex,
        "size": size,
        "timestamp": timestamp,
    }
    return json.dumps(d, separators=(',', ':'), sort_keys=True).encode()
