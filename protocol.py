"""
Wire protocol for P2P Share.

All messages are length-prefixed JSON envelopes (after the handshake).
During the handshake, messages are plain JSON (unencrypted) because
we're negotiating the session key.

Message flow:
  1. TCP connect
  2. Initiator sends HELLO (ephemeral pub key + identity pub key + sig)
  3. Responder sends HELLO-REPLY (same)
  4. Both sides derive session keys via X25519 HKDF
  5. All subsequent messages are encrypted with ChaCha20-Poly1305

Message types (after handshake):
  LIST_FILES         request  -> peer sends back FILE_LIST
  FILE_LIST          response
  REQUEST_FILE       request  -> peer either accepts (FILE_DATA) or rejects (ERROR)
  SEND_FILE          push     -> peer prompted for consent; sends CONSENT or REJECT
  CONSENT            response to REQUEST_FILE / SEND_FILE
  FILE_DATA          data payload (chunked transfer handled at socket level)
  REJECT             peer declined
  NOTIFY_KEY_ROTATION  peer announcing their new key
  ERROR              error message
  PING / PONG        keepalive
"""

import json
import struct
from typing import Optional

# Message type constants
MSG_HELLO             = "HELLO"
MSG_HELLO_REPLY       = "HELLO_REPLY"
MSG_LIST_FILES        = "LIST_FILES"
MSG_FILE_LIST         = "FILE_LIST"
MSG_REQUEST_FILE      = "REQUEST_FILE"
MSG_SEND_FILE         = "SEND_FILE"
MSG_CONSENT           = "CONSENT"
MSG_REJECT            = "REJECT"
MSG_FILE_DATA         = "FILE_DATA"
MSG_NOTIFY_KEY_ROTATE = "NOTIFY_KEY_ROTATION"
MSG_ERROR             = "ERROR"
MSG_PING              = "PING"
MSG_PONG              = "PONG"

MAX_MESSAGE_SIZE = 128 * 1024 * 1024  # 128 MB limit for a single JSON envelope
CHUNK_SIZE = 65536  # 64 KB file transfer chunks


def encode_msg(msg: dict) -> bytes:
    """Encode a message as 4-byte length + UTF-8 JSON."""
    payload = json.dumps(msg).encode()
    if len(payload) > MAX_MESSAGE_SIZE:
        raise ValueError(f"Message too large: {len(payload)} bytes")
    return struct.pack("!I", len(payload)) + payload


def decode_msg(data: bytes) -> dict:
    return json.loads(data)


def read_msg(sock) -> dict:
    """Read one length-prefixed message from a socket."""
    raw_len = _recv_exact(sock, 4)
    length = struct.unpack("!I", raw_len)[0]
    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Incoming message too large: {length}")
    raw = _recv_exact(sock, length)
    return json.loads(raw)


def send_msg(sock, msg: dict):
    """Send one length-prefixed message."""
    sock.sendall(encode_msg(msg))


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf


def send_file_data(sock, filename: str, data: bytes, sha256: str, signature: str, owner_fp: str, send_key, encrypt_fn):
    """
    Stream file data after consent.
    Sends chunks as encrypted FILE_DATA messages; final chunk has 'last': True.
    """
    total = len(data)
    offset = 0
    chunk_idx = 0
    while offset < total:
        chunk = data[offset:offset + CHUNK_SIZE]
        is_last = (offset + len(chunk)) >= total
        env = {
            "type": MSG_FILE_DATA,
            "filename": filename,
            "sha256": sha256,
            "signature": signature,
            "owner_fp": owner_fp,
            "chunk_index": chunk_idx,
            "offset": offset,
            "total_size": total,
            "last": is_last,
            "data": list(chunk),  # JSON-safe byte list
        }
        raw = json.dumps(env).encode()
        encrypted = encrypt_fn(send_key, raw)
        sock.sendall(struct.pack("!I", len(encrypted)) + encrypted)
        offset += len(chunk)
        chunk_idx += 1


def recv_file_data(sock, recv_key, decrypt_fn) -> dict:
    """
    Receive a single encrypted FILE_DATA chunk.
    Returns the parsed envelope.
    """
    raw_len = _recv_exact(sock, 4)
    length = struct.unpack("!I", raw_len)[0]
    raw_encrypted = _recv_exact(sock, length)
    raw = decrypt_fn(recv_key, raw_encrypted)
    return json.loads(raw)
