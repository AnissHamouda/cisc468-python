"""
P2P Share Client — initiates connections and sends requests.
"""

import os
import json
import hashlib
import logging
from typing import List, Optional, Tuple

from .crypto import (
    Identity, FileKeyStore,
    fingerprint as fp_of,
    encode_b64, decode_b64,
    encrypt_file, decrypt_file,
    sha256_hex,
)
from .contacts import ContactStore, Contact
from .share_index import ShareIndex, SharedFile, PeerFileCache, file_sha256
from .session import open_session, SessionError
from .protocol import *

log = logging.getLogger(__name__)


class Client:
    def __init__(
        self,
        identity: Identity,
        contacts: ContactStore,
        share_index: ShareIndex,
        peer_cache: PeerFileCache,
        file_key_store: FileKeyStore,
        received_dir: str,
    ):
        self.identity = identity
        self.contacts = contacts
        self.share_index = share_index
        self.peer_cache = peer_cache
        self.file_key_store = file_key_store
        self.received_dir = received_dir

    # -----------------------------------------------------------------------
    # add-contact: exchange public keys with a new peer
    # -----------------------------------------------------------------------

    def add_contact(self, host: str, port: int) -> Contact:
        session = open_session(host, port, self.identity)
        try:
            peer_fp = fp_of(session.peer_pub_bytes)

            # Check if already known
            existing = self.contacts.get(peer_fp)
            if existing:
                existing.host = host
                existing.port = port
                self.contacts.add(existing)
                print(f"[OK] Contact already known. Updated address.")
                return existing

            contact = Contact(
                pub_bytes=session.peer_pub_bytes,
                host=host,
                port=port,
                alias="",
                verified=False,
            )
            self.contacts.add(contact)
            # Ping to confirm session
            session.send({"type": MSG_PING})
            reply = session.recv()
            if reply.get("type") != MSG_PONG:
                print("[WARNING] Unexpected response to PING.")
        finally:
            session.close()

        return contact

    # -----------------------------------------------------------------------
    # list-files: get the file index from a peer
    # -----------------------------------------------------------------------

    def list_files(self, peer_fp: str) -> List[dict]:
        contact = self._require_contact(peer_fp)
        try:
            session = open_session(contact.host, contact.port, self.identity)
        except SessionError as e:
            # Try from cache
            cached = self.peer_cache.get(peer_fp)
            if cached:
                print(f"[OFFLINE] Peer is unreachable. Showing cached file list.")
                return cached
            raise

        try:
            peer_actual_fp = fp_of(session.peer_pub_bytes)
            if peer_actual_fp != peer_fp:
                raise SessionError(
                    f"[SECURITY] Connected peer fingerprint mismatch!\n"
                    f"  Expected: {peer_fp}\n"
                    f"  Got:      {peer_actual_fp}"
                )
            session.send({"type": MSG_LIST_FILES})
            reply = session.recv()
            if reply.get("type") != MSG_FILE_LIST:
                raise SessionError("Unexpected response to LIST_FILES")
            files = reply.get("files", [])
            # Update cache
            self.peer_cache.update(peer_fp, files)
            return files
        finally:
            session.close()

    # -----------------------------------------------------------------------
    # request: download a file from a peer (or proxy)
    # -----------------------------------------------------------------------

    def request_file(self, peer_fp: str, filename: str) -> bool:
        contact = self._require_contact(peer_fp)
        try:
            return self._request_from_peer(contact, peer_fp, filename)
        except SessionError as e:
            msg = str(e)
            if "offline" in msg.lower() or "connect" in msg.lower() or "timed out" in msg.lower():
                print(f"[INFO] Peer {peer_fp[:16]} is offline. Searching for a proxy...")
                return self._request_via_proxy(peer_fp, filename)
            raise

    def _request_from_peer(self, contact: Contact, peer_fp: str, filename: str) -> bool:
        session = open_session(contact.host, contact.port, self.identity)
        try:
            actual_fp = fp_of(session.peer_pub_bytes)
            if actual_fp != peer_fp:
                raise SessionError(
                    f"[SECURITY] Peer fingerprint mismatch!\n"
                    f"  Expected: {peer_fp}\n  Got: {actual_fp}"
                )
            session.send({"type": MSG_REQUEST_FILE, "filename": filename})
            reply = session.recv()
            if reply.get("type") == MSG_REJECT:
                print(f"[REJECTED] {reply.get('message', 'Peer declined.')}")
                return False
            if reply.get("type") == MSG_ERROR:
                print(f"[ERROR] {reply.get('message', 'Unknown error')}")
                return False
            if reply.get("type") != MSG_CONSENT:
                print(f"[ERROR] Unexpected response: {reply.get('type')}")
                return False

            # Receive file
            self._recv_streaming_file(session, peer_fp)
            return True
        finally:
            session.close()

    def _request_via_proxy(self, origin_fp: str, filename: str) -> bool:
        """
        Find another peer that has the file from origin_fp and download through them.
        Integrity is verified against the origin's signature.
        """
        cached_file = self.peer_cache.find_file(origin_fp, filename)
        if not cached_file:
            print(f"[ERROR] No cached file info for '{filename}' from {origin_fp[:16]}.")
            return False

        # Search all other contacts to see who has this file
        for contact in self.contacts.all():
            proxy_fp = contact.fingerprint
            if proxy_fp == origin_fp:
                continue
            proxy_cache = self.peer_cache.get(proxy_fp)
            for f in proxy_cache:
                if f.get("filename") == filename and f.get("owner_fp") == origin_fp:
                    print(f"[PROXY] Found '{filename}' at {proxy_fp[:16]}. Downloading via proxy...")
                    try:
                        session = open_session(contact.host, contact.port, self.identity)
                        try:
                            session.send({"type": MSG_REQUEST_FILE, "filename": filename})
                            reply = session.recv()
                            if reply.get("type") == MSG_CONSENT:
                                self._recv_streaming_file(session, origin_fp)
                                return True
                        finally:
                            session.close()
                    except Exception as e:
                        print(f"[WARN] Proxy attempt via {proxy_fp[:16]} failed: {e}")

        print(f"[ERROR] Could not find '{filename}' from any online peer.")
        return False

    # -----------------------------------------------------------------------
    # send: push a file to a peer
    # -----------------------------------------------------------------------

    def send_file(self, peer_fp: str, file_path: str) -> bool:
        if not os.path.exists(file_path):
            print(f"[ERROR] File not found: {file_path}")
            return False

        contact = self._require_contact(peer_fp)
        filename = os.path.basename(file_path)

        with open(file_path, "rb") as f:
            raw = f.read()

        sha = hashlib.sha256(raw).hexdigest()
        sig_payload = f"file:{filename}:{sha}".encode()
        sig = encode_b64(self.identity.sign(sig_payload))
        size = len(raw)

        session = open_session(contact.host, contact.port, self.identity)
        try:
            actual_fp = fp_of(session.peer_pub_bytes)
            if actual_fp != peer_fp:
                raise SessionError(f"[SECURITY] Peer fingerprint mismatch!")

            session.send({
                "type": MSG_SEND_FILE,
                "filename": filename,
                "sha256": sha,
                "signature": sig,
                "owner_fp": self.identity.fingerprint,
                "size": size,
            })
            reply = session.recv()
            if reply.get("type") == MSG_REJECT:
                print(f"[REJECTED] {reply.get('message', 'Peer declined.')}")
                return False
            if reply.get("type") == MSG_ERROR:
                print(f"[ERROR] {reply.get('message', 'Unknown error')}")
                return False
            if reply.get("type") != MSG_CONSENT:
                print(f"[ERROR] Unexpected response: {reply.get('type')}")
                return False

            # Stream file
            self._stream_file(session, filename, raw, sha, sig)
            print(f"[OK] Sent '{filename}' to {contact.alias or peer_fp[:16]}.")
            return True
        finally:
            session.close()

    # -----------------------------------------------------------------------
    # key rotation notification
    # -----------------------------------------------------------------------

    def notify_key_rotation(self, old_identity: Identity, new_identity: Identity):
        """
        Notify all contacts about a key rotation.
        The announcement is signed by the OLD key.
        """
        new_pub = new_identity.public_key_bytes
        payload = b"key-rotation:" + new_pub
        sig = old_identity.sign(payload)
        msg = {
            "type": MSG_NOTIFY_KEY_ROTATE,
            "new_identity_pub": encode_b64(new_pub),
            "signature": encode_b64(sig),
        }
        for contact in self.contacts.all():
            if contact.revoked:
                continue
            try:
                session = open_session(contact.host, contact.port, old_identity)
                try:
                    session.send(msg)
                finally:
                    session.close()
                print(f"[OK] Notified {contact.alias or contact.fingerprint[:16]} of key rotation.")
            except Exception as e:
                print(f"[WARN] Could not notify {contact.alias or contact.fingerprint[:16]}: {e}")

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _require_contact(self, peer_fp: str) -> Contact:
        contact = self.contacts.get(peer_fp)
        if contact is None:
            raise ValueError(f"[ERROR] Unknown contact: {peer_fp}. Use 'add-contact' first.")
        if contact.revoked:
            raise ValueError(
                f"[SECURITY] Contact {peer_fp[:16]} has a REVOKED key. "
                f"Successor: {contact.successor_fp or 'unknown'}. Refusing to connect."
            )
        return contact

    def _stream_file(self, session, filename: str, raw: bytes, sha: str, sig: str):
        total = len(raw)
        offset = 0
        idx = 0
        while offset < total:
            chunk = raw[offset:offset + CHUNK_SIZE]
            is_last = (offset + len(chunk)) >= total
            envelope = json.dumps({
                "type": MSG_FILE_DATA,
                "filename": filename,
                "sha256": sha,
                "signature": sig,
                "owner_fp": self.identity.fingerprint,
                "chunk_index": idx,
                "offset": offset,
                "total_size": total,
                "last": is_last,
                "data": list(chunk),
            }).encode()
            session.send_raw_encrypted(envelope)
            offset += len(chunk)
            idx += 1

    def _recv_streaming_file(self, session, owner_fp: str):
        """Receive a streamed file, verify integrity, save encrypted."""
        buf = b""
        meta = {}
        while True:
            raw = session.recv_raw_encrypted()
            env = json.loads(raw)
            if env.get("type") == MSG_ERROR:
                print(f"\n[ERROR] Transfer failed: {env.get('message')}")
                return
            if env.get("type") != MSG_FILE_DATA:
                print(f"\n[ERROR] Unexpected message type: {env.get('type')}")
                return
            if not meta:
                meta = {
                    "filename": env["filename"],
                    "sha256": env["sha256"],
                    "signature": env["signature"],
                    "owner_fp": env.get("owner_fp", owner_fp),
                    "total_size": env["total_size"],
                }
            buf += bytes(env["data"])
            if env.get("last"):
                break

        filename = meta["filename"]
        expected_sha = meta["sha256"]
        sig_b64 = meta["signature"]
        actual_owner_fp = meta["owner_fp"]

        # Verify hash
        computed_sha = hashlib.sha256(buf).hexdigest()
        if computed_sha != expected_sha:
            print(
                f"\n[SECURITY] '{filename}' FAILED integrity check!\n"
                f"  Expected: {expected_sha}\n"
                f"  Got:      {computed_sha}\n"
                f"  DISCARDING — file may have been tampered with."
            )
            return

        # Verify origin signature
        owner_contact = self.contacts.get(actual_owner_fp)
        if owner_contact is None:
            print(
                f"\n[SECURITY] Cannot verify '{filename}': origin {actual_owner_fp[:16]} unknown."
            )
            return

        sig_payload = f"file:{filename}:{expected_sha}".encode()
        try:
            sig_bytes = decode_b64(sig_b64)
        except Exception:
            print(f"\n[SECURITY] Invalid signature encoding for '{filename}'. DISCARDING.")
            return

        if not Identity.verify_signature(owner_contact.pub_bytes, sig_bytes, sig_payload):
            print(
                f"\n[SECURITY] Signature verification FAILED for '{filename}'!\n"
                f"  File was not signed by {actual_owner_fp[:16]}. DISCARDING."
            )
            return

        # Save encrypted
        file_key = self.file_key_store.get_or_create(filename)
        encrypted = encrypt_file(file_key, buf)
        out_path = os.path.join(self.received_dir, filename)
        with open(out_path, "wb") as f:
            f.write(encrypted)
        os.chmod(out_path, 0o600)

        print(
            f"\n[OK] Received and verified '{filename}' ({len(buf)} bytes).\n"
            f"     Saved (encrypted) to: {out_path}"
        )
