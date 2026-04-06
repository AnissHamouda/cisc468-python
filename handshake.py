"""
handshake.py — Application-layer handshake for Perfect Forward Secrecy.

Transcript (spec §Handshake transcript construction):
  "CISC468-HANDSHAKE-V1"
  + initiator_fp (64 hex chars, UTF-8 encoded)
  + responder_fp (64 hex chars, UTF-8 encoded)
  + initiator_eph_pub  (32 bytes raw)
  + responder_eph_pub  (32 bytes raw)
  + initiator_nonce    (32 bytes)
  + responder_nonce    (32 bytes)
  + 0x00 0x00 0x00 0x01  (protocol version, big-endian uint32)

The responder signs the full transcript in HANDSHAKE_RESP.
"""

import struct
import socket
import logging
from typing import Optional

from crypto_utils import (
    Identity, EphemeralKeypair, SessionKeys,
    ed25519_verify, random_nonce_32, b64e, b64d,
)
from protocol import (
    build_envelope, verify_envelope, send_frame, recv_frame,
    MSG_HANDSHAKE_INIT, MSG_HANDSHAKE_RESP, MSG_ERROR,
)

log = logging.getLogger(__name__)


class HandshakeError(Exception):
    pass


def _build_transcript(init_fp, resp_fp, init_eph, resp_eph, init_nonce, resp_nonce):
    return (
        b"CISC468-HANDSHAKE-V1"
        + init_fp.encode()
        + resp_fp.encode()
        + init_eph
        + resp_eph
        + init_nonce
        + resp_nonce
        + struct.pack(">I", 1)
    )


def _send_error(sock, identity, message):
    try:
        env = build_envelope(identity, MSG_ERROR, {"message": message})
        send_frame(sock, env)
    except Exception:
        pass


def perform_handshake_initiator(sock, identity, responder_fp, responder_raw_pub):
    eph = EphemeralKeypair()
    nonce = random_nonce_32()
    payload = {"ephemeral_pub": b64e(eph.public_bytes), "nonce": b64e(nonce)}
    send_frame(sock, build_envelope(identity, MSG_HANDSHAKE_INIT, payload))

    resp = recv_frame(sock)
    if resp.get("type") == MSG_ERROR:
        raise HandshakeError(f"Peer error: {resp['payload'].get('message','')}")
    if resp.get("type") != MSG_HANDSHAKE_RESP:
        raise HandshakeError(f"Expected HANDSHAKE_RESP, got {resp.get('type')}")
    if resp.get("from") != responder_fp:
        raise HandshakeError(
            f"[SECURITY] HANDSHAKE_RESP fingerprint mismatch\n"
            f"  Expected: {responder_fp}\n  Got: {resp.get('from')}"
        )
    if not verify_envelope(resp, responder_raw_pub):
        raise HandshakeError("[SECURITY] HANDSHAKE_RESP envelope signature FAILED")

    resp_eph_pub = b64d(resp["payload"]["ephemeral_pub"])
    resp_nonce   = b64d(resp["payload"]["nonce"])

    transcript = _build_transcript(
        identity.fingerprint, responder_fp,
        eph.public_bytes, resp_eph_pub, nonce, resp_nonce,
    )
    try:
        ts = b64d(resp["payload"]["transcript_sig"])
    except Exception:
        raise HandshakeError("[SECURITY] Cannot decode transcript_sig")
    if not ed25519_verify(responder_raw_pub, ts, transcript):
        raise HandshakeError("[SECURITY] Responder transcript signature FAILED — possible MitM!")

    shared = eph.exchange(resp_eph_pub)
    return SessionKeys.derive(shared, nonce, resp_nonce,
                              identity.fingerprint, responder_fp, is_initiator=True)


def perform_handshake_responder(sock, identity, initiator_fp, initiator_raw_pub, prefetched_env=None):
    init = prefetched_env if prefetched_env is not None else recv_frame(sock)

    if init.get("type") == MSG_ERROR:
        raise HandshakeError(f"Peer error: {init['payload'].get('message','')}")
    if init.get("type") != MSG_HANDSHAKE_INIT:
        raise HandshakeError(f"Expected HANDSHAKE_INIT, got {init.get('type')}")
    if init.get("from") != initiator_fp:
        _send_error(sock, identity, f"Fingerprint mismatch: expected {initiator_fp}")
        raise HandshakeError(
            f"[SECURITY] HANDSHAKE_INIT fingerprint mismatch\n"
            f"  Expected: {initiator_fp}\n  Got: {init.get('from')}"
        )
    if not verify_envelope(init, initiator_raw_pub):
        _send_error(sock, identity, "HANDSHAKE_INIT signature invalid")
        raise HandshakeError("[SECURITY] HANDSHAKE_INIT envelope signature FAILED")

    init_eph_pub = b64d(init["payload"]["ephemeral_pub"])
    init_nonce   = b64d(init["payload"]["nonce"])

    eph = EphemeralKeypair()
    nonce = random_nonce_32()

    transcript = _build_transcript(
        initiator_fp, identity.fingerprint,
        init_eph_pub, eph.public_bytes, init_nonce, nonce,
    )
    payload = {
        "ephemeral_pub": b64e(eph.public_bytes),
        "nonce": b64e(nonce),
        "transcript_sig": b64e(identity.sign(transcript)),
    }
    send_frame(sock, build_envelope(identity, MSG_HANDSHAKE_RESP, payload))

    shared = eph.exchange(init_eph_pub)
    return SessionKeys.derive(shared, init_nonce, nonce,
                              initiator_fp, identity.fingerprint, is_initiator=False)
