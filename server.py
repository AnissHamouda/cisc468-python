"""
server.py — TLS 1.3 TCP server for p2pshare.
"""

import os
import ssl
import json
import math
import socket
import hashlib
import logging
import threading
from typing import Optional, Callable

from crypto_utils import Identity, SessionKeys, encrypt_chunk, b64e, b64d, CHUNK_SIZE
from protocol import (
    build_envelope, verify_envelope, send_frame, recv_frame,
    canonical_manifest,
    MSG_HELLO, MSG_CONTACT_REQUEST, MSG_CONTACT_ACCEPT,
    MSG_HANDSHAKE_INIT,
    MSG_LIST_FILES_REQUEST, MSG_LIST_FILES_RESPONSE,
    MSG_FILE_REQUEST, MSG_FILE_APPROVE, MSG_FILE_DENY,
    MSG_TRANSFER_START, MSG_CHUNK, MSG_TRANSFER_DONE,
    MSG_KEY_ROTATE_NOTICE, MSG_ERROR,
)
from handshake import perform_handshake_responder, HandshakeError
from storage import ContactStore, ShareIndex, Contact, SharedFile
from tls_utils import make_server_ssl_context
from crypto_utils import fingerprint_from_bytes

log = logging.getLogger(__name__)


class Server:
    def __init__(self, identity, contacts, share_index, data_dir,
                 port=0, consent_cb=None):
        self.identity = identity
        self.contacts = contacts
        self.share_index = share_index
        self.data_dir = data_dir
        self._port = port
        self._consent_cb = consent_cb or self._default_consent
        self._sock = None
        self._ssl_ctx = None
        self._cert_path = None
        self._key_path = None
        self._running = False
        self._actual_port = port

    @property
    def port(self):
        return self._actual_port

    def start(self):
        ctx, cert_path, key_path = make_server_ssl_context(self.identity)
        self._ssl_ctx = ctx
        self._cert_path = cert_path
        self._key_path = key_path
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind(("0.0.0.0", self._port))
        raw.listen(32)
        self._actual_port = raw.getsockname()[1]
        self._sock = raw
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self._actual_port

    def stop(self):
        self._running = False
        if self._sock:
            try: self._sock.close()
            except: pass
        for p in [self._cert_path, self._key_path]:
            if p and os.path.exists(p):
                try: os.unlink(p)
                except: pass

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
                threading.Thread(target=self._handle_connection, args=(conn, addr), daemon=True).start()
            except OSError:
                break

    def _handle_connection(self, raw_conn, addr):
        try:
            tls_conn = self._ssl_ctx.wrap_socket(raw_conn, server_side=True)
            tls_conn.settimeout(120.0)
            self._dispatch(tls_conn, addr)
        except ssl.SSLError as e:
            log.debug(f"TLS error from {addr}: {e}")
        except Exception as e:
            log.debug(f"Handler error from {addr}: {e}")
        finally:
            try: raw_conn.close()
            except: pass

    def _dispatch(self, sock, addr):
        try:
            env = recv_frame(sock)
        except Exception as e:
            log.debug(f"Failed to read first frame from {addr}: {e}")
            return

        msg_type = env.get("type", "")
        peer_fp  = env.get("from", "")

        if msg_type == MSG_HELLO:
            self._handle_hello(sock, env, addr)
        elif msg_type == MSG_CONTACT_REQUEST:
            self._handle_contact_request(sock, env, addr)
        elif msg_type == MSG_KEY_ROTATE_NOTICE:
            contact = self.contacts.get(peer_fp)
            if contact is None:
                self._send_error(sock, f"Unknown peer: {peer_fp[:16]}")
                return
            self._handle_key_rotate(sock, env, contact)
        elif msg_type == MSG_LIST_FILES_REQUEST:
            contact = self.contacts.get(peer_fp)
            if contact is None:
                self._send_error(sock, f"Unknown peer: {peer_fp[:16]}")
                return
            if contact.revoked:
                self._send_error(sock, "[SECURITY] Your key has been marked revoked")
                return
            self._handle_list_files(sock, env, contact)
        elif msg_type == MSG_HANDSHAKE_INIT:
            contact = self.contacts.get(peer_fp)
            if contact is None:
                self._send_error(sock, f"Unknown peer: {peer_fp[:16]}")
                return
            if contact.revoked:
                self._send_error(sock, "[SECURITY] Your key has been marked revoked")
                return
            self._handle_file_session(sock, env, contact)
        else:
            self._send_error(sock, f"Unexpected message type: {msg_type}")

    def _handle_hello(self, sock, env, addr):
        reply = build_envelope(self.identity, MSG_HELLO, {
            "raw_pub": b64e(self.identity.raw_public_key),
            "port": self._actual_port,
        })
        send_frame(sock, reply)

    def _handle_contact_request(self, sock, env, addr):
        payload  = env.get("payload", {})
        peer_fp  = env.get("from", "")
        raw_pub_b64 = payload.get("raw_pub", "")
        peer_port   = payload.get("port", 0)

        try:
            raw_pub = b64d(raw_pub_b64)
        except Exception:
            self._send_error(sock, "Invalid raw_pub")
            return

        if not verify_envelope(env, raw_pub):
            self._send_error(sock, "[SECURITY] CONTACT_REQUEST signature invalid")
            print(f"\n[SECURITY] CONTACT_REQUEST from {peer_fp[:16]} failed sig check")
            return

        peer_host = addr[0]
        existing = self.contacts.get(peer_fp)
        if existing is None:
            contact = Contact(
                fingerprint=peer_fp, raw_pub=raw_pub_b64,
                host=peer_host, port=peer_port, verified=False,
            )
            self.contacts.add(contact)
            print(f"\n[NEW CONTACT] {peer_fp}")
            print(f"  Address : {peer_host}:{peer_port}")
            print(f"  Verify  : verify-contact {peer_fp}")
        else:
            self.contacts.update_address(peer_fp, peer_host, peer_port)

        reply = build_envelope(self.identity, MSG_CONTACT_ACCEPT, {
            "raw_pub": b64e(self.identity.raw_public_key),
            "port": self._actual_port,
        })
        send_frame(sock, reply)

    def _handle_list_files(self, sock, env, contact):
        if not verify_envelope(env, contact.raw_pub_bytes()):
            self._send_error(sock, "[SECURITY] LIST_FILES_REQUEST signature invalid")
            return
        files = self.share_index.public_list()
        send_frame(sock, build_envelope(self.identity, MSG_LIST_FILES_RESPONSE, {"files": files}))

    def _handle_file_session(self, sock, env, contact):
        try:
            session = perform_handshake_responder(
                sock, self.identity,
                contact.fingerprint, contact.raw_pub_bytes(),
                prefetched_env=env,
            )
        except HandshakeError as e:
            print(f"\n[SECURITY] Handshake failed: {e}")
            return

        try:
            req_env = recv_frame(sock)
        except Exception as e:
            log.debug(f"Post-handshake read failed: {e}")
            return

        if req_env.get("type") != MSG_FILE_REQUEST:
            self._send_error(sock, f"Expected FILE_REQUEST, got {req_env.get('type')}")
            return

        file_id = req_env["payload"].get("file_id", "")
        sf = self.share_index.get(file_id)
        if sf is None:
            send_frame(sock, build_envelope(self.identity, MSG_FILE_DENY, {
                "file_id": file_id, "reason": "File not found in share index",
            }))
            print(f"\n[ERROR] Peer requested unknown file_id: {file_id}")
            return

        peer_name = contact.alias or contact.fingerprint[:16]
        if not self._consent_cb(contact.fingerprint, peer_name, sf.filename):
            send_frame(sock, build_envelope(self.identity, MSG_FILE_DENY, {
                "file_id": file_id, "reason": "Denied by user",
            }))
            print(f"\n[INFO] File request for '{sf.filename}' denied")
            return

        send_frame(sock, build_envelope(self.identity, MSG_FILE_APPROVE, {"file_id": file_id}))
        self._send_file(sock, session, sf)

    def _send_file(self, sock, session, sf):
        # Read the file — could be an original shared file (plaintext path) 
        # or a previously received file (encrypted in received store)
        try:
            if os.path.exists(sf.path):
                with open(sf.path, "rb") as f:
                    data = f.read()
            else:
                self._send_error(sock, f"File not found on disk: {sf.filename}")
                print(f"\n[ERROR] File missing from disk: {sf.path}")
                return
        except OSError as e:
            self._send_error(sock, f"Cannot read file: {e}")
            print(f"\n[ERROR] Cannot read '{sf.filename}': {e}")
            return

        import uuid as _uuid
        transfer_id = str(_uuid.uuid4())
        total_chunks = max(1, math.ceil(len(data) / CHUNK_SIZE))

        start_payload = {
            "file_id": sf.file_id, "filename": sf.filename,
            "sha256_hex": sf.sha256_hex, "size": sf.size,
            "total_chunks": total_chunks,
            "original_owner": sf.original_owner,
            "manifest_sig": sf.manifest_sig,
            "timestamp": sf.timestamp,
        }
        send_frame(sock, build_envelope(self.identity, MSG_TRANSFER_START,
                                        start_payload, msg_id=transfer_id))

        for idx in range(total_chunks):
            chunk = data[idx * CHUNK_SIZE:(idx + 1) * CHUNK_SIZE]
            ct = encrypt_chunk(
                session.tx_key, session.tx_nonce_base, idx, chunk,
                sf.file_id, total_chunks, transfer_id,
            )
            send_frame(sock, build_envelope(self.identity, MSG_CHUNK, {
                "file_id": sf.file_id, "chunk_index": idx,
                "total_chunks": total_chunks,
                "data": b64e(ct), "transfer_id": transfer_id,
            }))

        send_frame(sock, build_envelope(self.identity, MSG_TRANSFER_DONE, {
            "file_id": sf.file_id, "transfer_id": transfer_id,
            "sha256_hex": sf.sha256_hex,
        }))
        print(f"\n[OK] Sent '{sf.filename}' ({sf.size} bytes)")

    def _handle_key_rotate(self, sock, env, contact):
        if not verify_envelope(env, contact.raw_pub_bytes()):
            self._send_error(sock, "[SECURITY] KEY_ROTATE_NOTICE signature invalid")
            print(f"\n[SECURITY] KEY_ROTATE_NOTICE from {contact.fingerprint[:16]} failed verification")
            return

        payload     = env["payload"]
        new_fp      = payload.get("new_fingerprint", "")
        new_raw_b64 = payload.get("new_raw_pub", "")
        try:
            new_raw = b64d(new_raw_b64)
        except Exception:
            self._send_error(sock, "Invalid new_raw_pub")
            return

        computed = fingerprint_from_bytes(new_raw)
        if computed != new_fp:
            self._send_error(sock, "[SECURITY] New fingerprint doesn't match new public key")
            print(f"\n[SECURITY] KEY_ROTATE_NOTICE: fingerprint/key mismatch from {contact.fingerprint[:16]}")
            return

        self.contacts.mark_revoked(contact.fingerprint, successor_fp=new_fp)
        from storage import Contact as C
        new_contact = C(
            fingerprint=new_fp, raw_pub=new_raw_b64,
            host=contact.host, port=contact.port,
            alias=contact.alias, verified=False,
        )
        self.contacts.add(new_contact)
        send_frame(sock, build_envelope(self.identity, MSG_CONTACT_ACCEPT, {
            "raw_pub": b64e(self.identity.raw_public_key),
            "port": self._actual_port,
        }))
        print(
            f"\n[KEY ROTATION] {contact.alias or contact.fingerprint[:16]} rotated their key\n"
            f"  Old : {contact.fingerprint}\n"
            f"  New : {new_fp}\n"
            f"  *** Re-verify: verify-contact {new_fp} ***"
        )

    def _send_error(self, sock, message):
        try:
            send_frame(sock, build_envelope(self.identity, MSG_ERROR, {"message": message}))
        except Exception:
            pass

    @staticmethod
    def _default_consent(peer_fp, peer_name, filename):
        try:
            ans = input(f"\n[REQUEST] {peer_name} wants '{filename}'. Allow? [y/N]: ")
            return ans.strip().lower() == "y"
        except EOFError:
            return False
