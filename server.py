"""
P2P Share Server.

Listens for incoming connections, performs handshakes, and handles:
  - LIST_FILES
  - REQUEST_FILE (with consent prompt)
  - SEND_FILE    (with consent prompt)
  - NOTIFY_KEY_ROTATION
  - PING
"""

import os
import json
import socket
import threading
import hashlib
import logging
from typing import Optional, Callable

from .crypto import (
    Identity, FileKeyStore,
    fingerprint as fp_of,
    decode_b64, encode_b64,
    sha256_hex,
    encrypt_file, decrypt_file,
)
from cryptography.exceptions import InvalidTag
from .contacts import ContactStore, Contact
from .share_index import ShareIndex, PeerFileCache, SharedFile, file_sha256
from .session import perform_handshake_responder, Session, SessionError
from .protocol import *

log = logging.getLogger(__name__)


class Server:
    def __init__(
        self,
        identity: Identity,
        contacts: ContactStore,
        share_index: ShareIndex,
        peer_cache: PeerFileCache,
        file_key_store: FileKeyStore,
        received_dir: str,
        port: int = 0,
        consent_callback: Optional[Callable] = None,
    ):
        self.identity = identity
        self.contacts = contacts
        self.share_index = share_index
        self.peer_cache = peer_cache
        self.file_key_store = file_key_store
        self.received_dir = received_dir
        self._consent_callback = consent_callback or self._default_consent
        self._port = port
        self._sock: Optional[socket.socket] = None
        self._running = False

    @property
    def port(self) -> int:
        return self._port

    def start(self) -> int:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("0.0.0.0", self._port))
        self._sock.listen(16)
        self._port = self._sock.getsockname()[1]
        self._running = True
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()
        return self._port

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
                t = threading.Thread(
                    target=self._handle_connection,
                    args=(conn, addr),
                    daemon=True,
                )
                t.start()
            except Exception:
                if self._running:
                    log.exception("Accept error")

    def _handle_connection(self, conn: socket.socket, addr):
        conn.settimeout(60.0)
        log.debug("Incoming connection from %s", addr)
        try:
            session = perform_handshake_responder(conn, self.identity)
            peer_fp = fp_of(session.peer_pub_bytes)
            log.debug("Session established with %s", peer_fp)
            self._dispatch(session, peer_fp, addr)
        except SessionError as e:
            print(f"\n[SECURITY WARNING] {e}")
        except Exception as e:
            log.debug("Connection error: %s", e)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _dispatch(self, session: Session, peer_fp: str, addr):
        while True:
            try:
                msg = session.recv()
            except (ConnectionError, OSError):
                break
            except SessionError as e:
                print(f"\n[SECURITY] {e}")
                break

            t = msg.get("type")
            try:
                if t == MSG_PING:
                    session.send({"type": MSG_PONG})
                elif t == MSG_LIST_FILES:
                    self._handle_list_files(session)
                elif t == MSG_REQUEST_FILE:
                    self._handle_request_file(session, msg, peer_fp)
                elif t == MSG_SEND_FILE:
                    self._handle_receive_file(session, msg, peer_fp, addr)
                elif t == MSG_NOTIFY_KEY_ROTATE:
                    self._handle_key_rotation(msg, peer_fp)
                    break
                else:
                    session.send({"type": MSG_ERROR, "message": "Unknown message type"})
            except (ConnectionError, OSError):
                break
            except SessionError as e:
                print(f"\n[SECURITY] {e}")
                session.send({"type": MSG_ERROR, "message": str(e)})
                break
            except Exception as e:
                log.exception("Dispatch error")
                try:
                    session.send({"type": MSG_ERROR, "message": f"Internal error: {e}"})
                except Exception:
                    break

    # -----------------------------------------------------------------------
    # Handlers
    # -----------------------------------------------------------------------

    def _handle_list_files(self, session: Session):
        files = self.share_index.public_list()
        session.send({"type": MSG_FILE_LIST, "files": files})

    def _handle_request_file(self, session: Session, msg: dict, peer_fp: str):
        filename = msg.get("filename", "")
        contact = self.contacts.get(peer_fp)
        contact_name = contact.alias or peer_fp[:16] if contact else peer_fp[:16]

        # Consent prompt
        prompt = f"\n[REQUEST] {contact_name} wants to download '{filename}'. Allow? [y/N]: "
        if not self._consent_callback(prompt):
            session.send({"type": MSG_REJECT, "message": "Peer declined the request."})
            return

        sf = self.share_index.get(filename)
        if sf is None:
            session.send({"type": MSG_ERROR, "message": f"File '{filename}' is not available."})
            return

        if not os.path.exists(sf.path):
            session.send({"type": MSG_ERROR, "message": f"File '{filename}' is no longer available on disk."})
            return

        # Read file — decrypt if it was previously received and stored encrypted
        with open(sf.path, "rb") as f:
            raw = f.read()

        file_key = self.file_key_store.get(filename)
        if file_key is not None:
            try:
                raw = decrypt_file(file_key, raw)
            except Exception:
                pass  # Not encrypted (original shared file), use as-is

        session.send({"type": MSG_CONSENT})
        self._stream_file(session, sf, raw)

    def _handle_receive_file(self, session: Session, msg: dict, peer_fp: str, addr):
        """Peer is pushing a file to us. Ask for consent first."""
        filename = msg.get("filename", "unknown")
        size = msg.get("size", 0)
        sha = msg.get("sha256", "")
        contact = self.contacts.get(peer_fp)
        contact_name = contact.alias or peer_fp[:16] if contact else peer_fp[:16]

        prompt = (
            f"\n[INCOMING] {contact_name} wants to send you '{filename}' "
            f"({size} bytes). Accept? [y/N]: "
        )
        if not self._consent_callback(prompt):
            session.send({"type": MSG_REJECT, "message": "Recipient declined."})
            return

        session.send({"type": MSG_CONSENT})
        self._recv_file_data(session, peer_fp, filename, sha, msg.get("signature", ""), msg.get("owner_fp", peer_fp))

    def _handle_key_rotation(self, msg: dict, old_fp: str):
        """
        Peer is rotating their key. Update our contact store.
        The new key must be signed by the old key.
        """
        new_pub_b64 = msg.get("new_identity_pub", "")
        signature_b64 = msg.get("signature", "")
        try:
            new_pub = decode_b64(new_pub_b64)
            sig = decode_b64(signature_b64)
        except Exception:
            print(f"\n[SECURITY] Received malformed key rotation notice from {old_fp}.")
            return

        old_contact = self.contacts.get(old_fp)
        if old_contact is None:
            print(f"\n[WARNING] Received key rotation notice from unknown peer {old_fp}. Ignoring.")
            return

        # Verify: new key announcement signed by the old key
        payload = b"key-rotation:" + new_pub
        if not Identity.verify_signature(old_contact.pub_bytes, sig, payload):
            print(f"\n[SECURITY] Key rotation signature from {old_fp} is INVALID. Ignoring.")
            return

        new_fp = fp_of(new_pub)
        # Mark old key as revoked, add new contact
        self.contacts.mark_revoked(old_fp, successor_fp=new_fp)
        new_contact = Contact(
            pub_bytes=new_pub,
            host=old_contact.host,
            port=old_contact.port,
            alias=old_contact.alias,
            verified=False,  # must re-verify
            revoked=False,
        )
        self.contacts.add(new_contact)
        print(
            f"\n[KEY ROTATION] Contact '{old_contact.alias or old_fp[:16]}' has rotated their key.\n"
            f"  Old fingerprint: {old_fp}\n"
            f"  New fingerprint: {new_fp}\n"
            f"  *** You must re-verify this contact: verify-contact {new_fp} ***"
        )

    # -----------------------------------------------------------------------
    # File streaming helpers
    # -----------------------------------------------------------------------

    def _stream_file(self, session: Session, sf: SharedFile, raw: bytes):
        """Send file in encrypted chunks."""
        total = len(raw)
        offset = 0
        chunk_idx = 0
        while offset < total:
            chunk = raw[offset:offset + CHUNK_SIZE]
            is_last = (offset + len(chunk)) >= total
            envelope = json.dumps({
                "type": MSG_FILE_DATA,
                "filename": sf.filename,
                "sha256": sf.sha256,
                "signature": sf.signature,
                "owner_fp": sf.owner_fp,
                "chunk_index": chunk_idx,
                "offset": offset,
                "total_size": total,
                "last": is_last,
                "data": list(chunk),
            }).encode()
            session.send_raw_encrypted(envelope)
            offset += len(chunk)
            chunk_idx += 1

    def _recv_file_data(
        self,
        session: Session,
        sender_fp: str,
        filename: str,
        expected_sha: str,
        signature_b64: str,
        owner_fp: str,
    ):
        """Receive streamed file chunks, verify integrity, and save encrypted."""
        buf = b""
        total_size = None
        while True:
            raw = session.recv_raw_encrypted()
            env = json.loads(raw)
            if env.get("type") == MSG_ERROR:
                print(f"\n[ERROR] File transfer failed: {env.get('message', 'unknown error')}")
                return
            if env.get("type") != MSG_FILE_DATA:
                print(f"\n[ERROR] Unexpected message during file transfer.")
                return

            chunk = bytes(env["data"])
            buf += chunk
            if total_size is None:
                total_size = env["total_size"]
                actual_sha = env["sha256"]
                actual_sig = env["signature"]
                actual_owner_fp = env["owner_fp"]

            if env.get("last"):
                break

        # Verify hash
        computed_sha = hashlib.sha256(buf).hexdigest()
        if computed_sha != actual_sha:
            print(
                f"\n[SECURITY] File '{filename}' FAILED integrity check!\n"
                f"  Expected SHA-256: {actual_sha}\n"
                f"  Computed SHA-256: {computed_sha}\n"
                f"  The file may have been tampered with in transit. DISCARDING."
            )
            return

        # Verify origin signature (works even if downloaded from a proxy peer)
        owner_contact = self.contacts.get(actual_owner_fp)
        if owner_contact is None:
            print(
                f"\n[SECURITY] Cannot verify file '{filename}': origin peer {actual_owner_fp} is unknown.\n"
                f"  Add the origin peer as a contact before downloading their files."
            )
            return

        sig_payload = f"file:{filename}:{actual_sha}".encode()
        try:
            sig_bytes = decode_b64(actual_sig)
        except Exception:
            print(f"\n[SECURITY] File '{filename}' has invalid signature encoding. DISCARDING.")
            return

        if not Identity.verify_signature(owner_contact.pub_bytes, sig_bytes, sig_payload):
            print(
                f"\n[SECURITY] File '{filename}' signature verification FAILED!\n"
                f"  The file was NOT signed by {actual_owner_fp}.\n"
                f"  Possible tampering detected. DISCARDING."
            )
            return

        # Encrypt and save
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

    # -----------------------------------------------------------------------
    # Consent callback
    # -----------------------------------------------------------------------

    @staticmethod
    def _default_consent(prompt: str) -> bool:
        try:
            ans = input(prompt).strip().lower()
            return ans == "y"
        except EOFError:
            return False
