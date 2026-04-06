"""
client.py — Outbound connections for p2pshare.
"""

import os
import json
import math
import hashlib
import logging
import socket
from typing import Optional, List

from crypto_utils import (
    Identity, decrypt_chunk, b64e, b64d,
    fingerprint_from_bytes, CHUNK_SIZE,
)
from protocol import (
    build_envelope, verify_envelope, send_frame, recv_frame,
    canonical_manifest,
    MSG_CONTACT_REQUEST, MSG_CONTACT_ACCEPT,
    MSG_LIST_FILES_REQUEST, MSG_LIST_FILES_RESPONSE,
    MSG_FILE_REQUEST, MSG_FILE_APPROVE, MSG_FILE_DENY,
    MSG_TRANSFER_START, MSG_CHUNK, MSG_TRANSFER_DONE,
    MSG_KEY_ROTATE_NOTICE, MSG_CONTACT_ACCEPT, MSG_ERROR,
)
from handshake import perform_handshake_initiator, HandshakeError
from storage import ContactStore, ShareIndex, Contact, ReceivedFileStore
from tls_utils import make_client_ssl_context
from crypto_utils import ed25519_verify

log = logging.getLogger(__name__)


def _connect_tls(host: str, port: int, timeout: float = 10.0) -> socket.socket:
    ctx = make_client_ssl_context()
    raw = socket.create_connection((host, port), timeout=timeout)
    tls = ctx.wrap_socket(raw, server_hostname=host)
    tls.settimeout(120.0)
    return tls


class Client:
    def __init__(self, identity, contacts, share_index, received_store, listen_port=0):
        self.identity = identity
        self.contacts = contacts
        self.share_index = share_index
        self.received_store = received_store
        self.listen_port = listen_port

    # ------------------------------------------------------------------
    # add-contact
    # ------------------------------------------------------------------
    def add_contact(self, host: str, port: int) -> Contact:
        try:
            sock = _connect_tls(host, port)
        except Exception as e:
            raise ConnectionError(f"Cannot connect to {host}:{port} — {e}")
        try:
            env = build_envelope(self.identity, MSG_CONTACT_REQUEST, {
                "raw_pub": b64e(self.identity.raw_public_key),
                "port": self.listen_port,
            })
            send_frame(sock, env)
            reply = recv_frame(sock)
            if reply.get("type") == MSG_ERROR:
                raise ValueError(reply["payload"].get("message", "Unknown error"))
            if reply.get("type") != MSG_CONTACT_ACCEPT:
                raise ValueError(f"Unexpected response: {reply.get('type')}")

            peer_fp     = reply.get("from", "")
            raw_pub_b64 = reply["payload"].get("raw_pub", "")
            peer_port   = reply["payload"].get("port", port)
            raw_pub     = b64d(raw_pub_b64)

            computed_fp = fingerprint_from_bytes(raw_pub)
            if computed_fp != peer_fp:
                raise ValueError(
                    f"[SECURITY] Fingerprint mismatch!\n"
                    f"  Claimed  : {peer_fp}\n  Computed : {computed_fp}"
                )
            if not verify_envelope(reply, raw_pub):
                raise ValueError("[SECURITY] CONTACT_ACCEPT signature FAILED")

            existing = self.contacts.get(peer_fp)
            if existing is not None:
                self.contacts.update_address(peer_fp, host, peer_port)
                return existing

            contact = Contact(fingerprint=peer_fp, raw_pub=raw_pub_b64,
                              host=host, port=peer_port, verified=False)
            self.contacts.add(contact)
            return contact
        finally:
            sock.close()

    # ------------------------------------------------------------------
    # list-files
    # ------------------------------------------------------------------
    def list_files(self, host: str, port: int) -> List[dict]:
        contact = self._require_contact(host, port)
        try:
            sock = _connect_tls(host, port)
        except Exception as e:
            cached = self._read_cache(contact.fingerprint)
            if cached is not None:
                print("[INFO] Peer offline — showing cached file list")
                return cached
            raise ConnectionError(f"Cannot connect to {host}:{port} — {e}")
        try:
            env = build_envelope(self.identity, MSG_LIST_FILES_REQUEST, {})
            send_frame(sock, env)
            reply = recv_frame(sock)
            if reply.get("type") == MSG_ERROR:
                raise ValueError(reply["payload"].get("message", ""))
            if reply.get("type") != MSG_LIST_FILES_RESPONSE:
                raise ValueError(f"Unexpected: {reply.get('type')}")
            files = reply["payload"].get("files", [])
            self._write_cache(contact.fingerprint, files)
            return files
        finally:
            sock.close()

    # ------------------------------------------------------------------
    # request-file
    # ------------------------------------------------------------------
    def request_file(self, host: str, port: int, file_id: str) -> bool:
        contact = self._require_contact(host, port)
        if contact.revoked:
            print(f"[SECURITY] Contact {contact.fingerprint[:16]} key is REVOKED. Refusing.")
            return False
        try:
            return self._do_request(contact, file_id)
        except (ConnectionError, OSError) as e:
            print(f"[INFO] Peer offline ({e}). Searching for proxy...")
            return self._proxy_download(contact.fingerprint, file_id)

    def _do_request(self, contact: Contact, file_id: str) -> bool:
        try:
            sock = _connect_tls(contact.host, contact.port)
        except Exception as e:
            raise ConnectionError(str(e))
        try:
            session = perform_handshake_initiator(
                sock, self.identity, contact.fingerprint, contact.raw_pub_bytes(),
            )
            send_frame(sock, build_envelope(self.identity, MSG_FILE_REQUEST, {"file_id": file_id}))
            reply = recv_frame(sock)
            if reply.get("type") == MSG_FILE_DENY:
                print(f"\n[DENIED] {reply['payload'].get('reason', 'No reason given')}")
                return False
            if reply.get("type") == MSG_ERROR:
                print(f"\n[ERROR] {reply['payload'].get('message','')}")
                return False
            if reply.get("type") != MSG_FILE_APPROVE:
                print(f"\n[ERROR] Unexpected: {reply.get('type')}")
                return False

            start_env = recv_frame(sock)
            if start_env.get("type") != MSG_TRANSFER_START:
                print(f"\n[ERROR] Expected TRANSFER_START, got {start_env.get('type')}")
                return False
            if not verify_envelope(start_env, contact.raw_pub_bytes()):
                print("\n[SECURITY] TRANSFER_START signature FAILED — possible tampering!")
                return False

            return self._recv_transfer(sock, session, start_env)
        finally:
            sock.close()

    def _recv_transfer(self, sock, session, start_env: dict) -> bool:
        p          = start_env["payload"]
        file_id    = p["file_id"]
        filename   = p["filename"]
        exp_sha    = p["sha256_hex"]
        total_ch   = p["total_chunks"]
        size       = p["size"]
        owner_fp   = p["original_owner"]
        manif_sig  = p["manifest_sig"]
        timestamp  = p.get("timestamp", "")
        transfer_id = start_env["id"]

        # Verify manifest signature against original owner
        owner = self.contacts.get(owner_fp)
        if owner is None:
            print(f"\n[SECURITY] Unknown original owner {owner_fp[:16]}. Cannot verify manifest.")
            return False

        manifest_json = canonical_manifest(file_id, filename, owner_fp, exp_sha, size, timestamp)
        try:
            msig = b64d(manif_sig)
        except Exception:
            print("\n[SECURITY] Cannot decode manifest signature. Rejecting file.")
            return False
        if not ed25519_verify(owner.raw_pub_bytes(), msig, manifest_json):
            print(
                f"\n[SECURITY] Manifest signature FAILED for '{filename}'!\n"
                f"  The file was NOT signed by {owner_fp[:16]}.\n"
                f"  DISCARDING — possible tampering."
            )
            return False

        # Receive chunks
        chunks = {}
        for _ in range(total_ch):
            ce = recv_frame(sock)
            if ce.get("type") == MSG_ERROR:
                print(f"\n[ERROR] Transfer aborted: {ce['payload'].get('message','')}")
                return False
            if ce.get("type") != MSG_CHUNK:
                print(f"\n[ERROR] Expected CHUNK, got {ce.get('type')}")
                return False
            cp  = ce["payload"]
            idx = cp["chunk_index"]
            ct  = b64d(cp["data"])
            try:
                plain = decrypt_chunk(
                    session.rx_key, session.rx_nonce_base, idx, ct,
                    file_id, total_ch, transfer_id,
                )
            except Exception:
                print(
                    f"\n[SECURITY] Chunk {idx} AES-GCM auth FAILED for '{filename}'!\n"
                    f"  File may have been tampered with in transit. DISCARDING."
                )
                return False
            chunks[idx] = plain

        done = recv_frame(sock)
        if done.get("type") != MSG_TRANSFER_DONE:
            print(f"\n[ERROR] Expected TRANSFER_DONE, got {done.get('type')}")
            return False

        data = b"".join(chunks[i] for i in range(total_ch))
        actual_sha = hashlib.sha256(data).hexdigest()
        if actual_sha != exp_sha:
            print(
                f"\n[SECURITY] SHA-256 mismatch for '{filename}'!\n"
                f"  Expected : {exp_sha}\n  Got      : {actual_sha}\n"
                f"  DISCARDING — file has been tampered with."
            )
            return False

        meta = {
            "filename": filename, "sha256_hex": exp_sha, "size": size,
            "original_owner": owner_fp, "manifest_sig": manif_sig,
            "timestamp": timestamp,
        }
        self.received_store.save(file_id, data, meta)
        print(f"\n[OK] '{filename}' received and verified ({size} bytes). Saved securely.")
        return True

    # ------------------------------------------------------------------
    # Proxy download
    # ------------------------------------------------------------------
    def _proxy_download(self, offline_fp: str, file_id: str) -> bool:
        # Find any contact that has the file in their cached list
        for contact in self.contacts.all():
            if contact.fingerprint == offline_fp or contact.revoked:
                continue
            cached = self._read_cache(contact.fingerprint)
            if not cached:
                continue
            if not any(f.get("file_id") == file_id for f in cached):
                continue

            print(f"[PROXY] Trying {contact.fingerprint[:16]}...")
            try:
                sock = _connect_tls(contact.host, contact.port)
                try:
                    session = perform_handshake_initiator(
                        sock, self.identity, contact.fingerprint, contact.raw_pub_bytes(),
                    )
                    send_frame(sock, build_envelope(self.identity, MSG_FILE_REQUEST, {"file_id": file_id}))
                    reply = recv_frame(sock)
                    if reply.get("type") != MSG_FILE_APPROVE:
                        print(f"  Proxy denied: {reply.get('type')}")
                        sock.close()
                        continue
                    start_env = recv_frame(sock)
                    if start_env.get("type") != MSG_TRANSFER_START:
                        sock.close()
                        continue
                    if not verify_envelope(start_env, contact.raw_pub_bytes()):
                        print(f"  [SECURITY] TRANSFER_START from proxy {contact.fingerprint[:16]} invalid")
                        sock.close()
                        continue
                    ok = self._recv_transfer(sock, session, start_env)
                    if ok:
                        return True
                finally:
                    try: sock.close()
                    except: pass
            except Exception as e:
                print(f"  [WARN] Proxy failed: {e}")

        print(f"[ERROR] Could not retrieve file_id={file_id} from any proxy.")
        return False

    # ------------------------------------------------------------------
    # Key rotation
    # ------------------------------------------------------------------
    def notify_key_rotation(self, old_identity, new_identity):
        env = build_envelope(old_identity, MSG_KEY_ROTATE_NOTICE, {
            "new_fingerprint": new_identity.fingerprint,
            "new_raw_pub": b64e(new_identity.raw_public_key),
        })
        success = 0
        for contact in self.contacts.all():
            if contact.revoked:
                continue
            try:
                sock = _connect_tls(contact.host, contact.port)
                try:
                    send_frame(sock, env)
                    reply = recv_frame(sock)
                    if reply.get("type") in (MSG_CONTACT_ACCEPT, MSG_ERROR):
                        success += 1
                        print(f"[OK] Notified {contact.alias or contact.fingerprint[:16]}")
                finally:
                    sock.close()
            except Exception as e:
                print(f"[WARN] Could not notify {contact.alias or contact.fingerprint[:16]}: {e}")
        return success

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _require_contact(self, host: str, port: int) -> Contact:
        for c in self.contacts.all():
            if c.host == host and c.port == port:
                return c
        raise ValueError(f"No contact found for {host}:{port}. Use add-contact first.")

    def _cache_dir(self):
        d = os.path.join(os.path.dirname(self.received_store._dir), "file_list_cache")
        os.makedirs(d, exist_ok=True)
        return d

    def _cache_path(self, fp: str):
        return os.path.join(self._cache_dir(), f"{fp[:16]}.json")

    def _read_cache(self, fp: str):
        p = self._cache_path(fp)
        if not os.path.exists(p):
            return None
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            return None

    def _write_cache(self, fp: str, files: list):
        with open(self._cache_path(fp), "w") as f:
            json.dump(files, f)
