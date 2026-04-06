"""
storage.py — Persistent storage for p2pshare.

Contact storage:
  contacts.json.enc   — AES-256-GCM ciphertext
  contacts.json.meta  — JSON { nonce: b64 }

Share index:
  share_index.json  — plaintext JSON, maps file_id -> SharedFile dict

Received files:
  files/<file_id>.enc   — ciphertext
  files/<file_id>.meta  — JSON { nonce, filename, sha256_hex, size, original_owner, manifest_sig, timestamp }
"""

import os
import json
import base64
import hashlib
import uuid
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timezone

from crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt, b64e, b64d


@dataclass
class Contact:
    fingerprint: str
    raw_pub: str        # base64 raw Ed25519 pubkey
    host: str
    port: int
    alias: str = ""
    verified: bool = False
    revoked: bool = False
    successor_fp: Optional[str] = None

    def raw_pub_bytes(self) -> bytes:
        return b64d(self.raw_pub)


@dataclass
class SharedFile:
    file_id: str
    filename: str
    path: str
    sha256_hex: str
    size: int
    original_owner: str
    manifest_sig: str
    timestamp: str

    def to_public_dict(self) -> dict:
        return {
            "file_id": self.file_id,
            "filename": self.filename,
            "sha256_hex": self.sha256_hex,
            "size": self.size,
            "original_owner": self.original_owner,
            "manifest_sig": self.manifest_sig,
            "timestamp": self.timestamp,
        }


class ContactStore:
    def __init__(self, data_dir: str, file_key: bytes):
        self._dir = data_dir
        self._key = file_key
        self._contacts: Dict[str, Contact] = {}
        self._load()

    def _enc_path(self): return os.path.join(self._dir, "contacts.json.enc")
    def _meta_path(self): return os.path.join(self._dir, "contacts.json.meta")

    def _load(self):
        if not os.path.exists(self._enc_path()):
            return
        with open(self._meta_path()) as f:
            meta = json.load(f)
        nonce = b64d(meta["nonce"])
        with open(self._enc_path(), "rb") as f:
            ct = f.read()
        plaintext = aes_gcm_decrypt(self._key, nonce, ct)
        data = json.loads(plaintext)
        for fp, d in data.items():
            self._contacts[fp] = Contact(**d)

    def _save(self):
        data = {fp: asdict(c) for fp, c in self._contacts.items()}
        plaintext = json.dumps(data, separators=(',', ':')).encode()
        nonce, ct = aes_gcm_encrypt(self._key, plaintext)
        with open(self._enc_path(), "wb") as f:
            f.write(ct)
        with open(self._meta_path(), "w") as f:
            json.dump({"nonce": b64e(nonce)}, f)
        os.chmod(self._enc_path(), 0o600)
        os.chmod(self._meta_path(), 0o600)

    def get(self, fingerprint: str) -> Optional[Contact]:
        fp = fingerprint.lower()
        if fp in self._contacts:
            return self._contacts[fp]
        matches = [c for k, c in self._contacts.items() if k.startswith(fp)]
        return matches[0] if len(matches) == 1 else None

    def all(self) -> List[Contact]:
        return list(self._contacts.values())

    def add(self, contact: Contact):
        self._contacts[contact.fingerprint] = contact
        self._save()

    def update(self, contact: Contact):
        self._contacts[contact.fingerprint] = contact
        self._save()

    def mark_verified(self, fingerprint: str) -> bool:
        c = self.get(fingerprint)
        if c is None:
            return False
        c.verified = True
        self._save()
        return True

    def mark_revoked(self, fingerprint: str, successor_fp: Optional[str] = None):
        c = self.get(fingerprint)
        if c:
            c.revoked = True
            c.successor_fp = successor_fp
            self._save()

    def update_address(self, fingerprint: str, host: str, port: int):
        c = self.get(fingerprint)
        if c:
            c.host = host
            c.port = port
            self._save()


class ShareIndex:
    def __init__(self, data_dir: str):
        self._path = os.path.join(data_dir, "share_index.json")
        self._files: Dict[str, dict] = {}
        self._load()

    def _load(self):
        if os.path.exists(self._path):
            with open(self._path) as f:
                self._files = json.load(f)

    def _save(self):
        with open(self._path, "w") as f:
            json.dump(self._files, f, indent=2)

    def add(self, sf: SharedFile):
        self._files[sf.file_id] = asdict(sf)
        self._save()

    def remove(self, file_id: str) -> bool:
        if file_id in self._files:
            del self._files[file_id]
            self._save()
            return True
        return False

    def get(self, file_id: str) -> Optional[SharedFile]:
        d = self._files.get(file_id)
        return SharedFile(**d) if d else None

    def all(self) -> List[SharedFile]:
        return [SharedFile(**d) for d in self._files.values()]

    def public_list(self) -> List[dict]:
        return [SharedFile(**d).to_public_dict() for d in self._files.values()]


class ReceivedFileStore:
    def __init__(self, data_dir: str, file_key: bytes):
        self._dir = os.path.join(data_dir, "files")
        os.makedirs(self._dir, mode=0o700, exist_ok=True)
        self._key = file_key

    def _enc_path(self, file_id: str) -> str:
        return os.path.join(self._dir, f"{file_id}.enc")

    def _meta_path(self, file_id: str) -> str:
        return os.path.join(self._dir, f"{file_id}.meta")

    def save(self, file_id: str, plaintext: bytes, meta: dict):
        nonce, ct = aes_gcm_encrypt(self._key, plaintext)
        with open(self._enc_path(file_id), "wb") as f:
            f.write(ct)
        meta_copy = dict(meta)
        meta_copy["nonce"] = b64e(nonce)
        with open(self._meta_path(file_id), "w") as f:
            json.dump(meta_copy, f)
        os.chmod(self._enc_path(file_id), 0o600)
        os.chmod(self._meta_path(file_id), 0o600)

    def load(self, file_id: str) -> Tuple[bytes, dict]:
        with open(self._meta_path(file_id)) as f:
            meta = json.load(f)
        nonce = b64d(meta["nonce"])
        with open(self._enc_path(file_id), "rb") as f:
            ct = f.read()
        return aes_gcm_decrypt(self._key, nonce, ct), meta

    def exists(self, file_id: str) -> bool:
        return os.path.exists(self._enc_path(file_id))

    def list_files(self) -> List[dict]:
        result = []
        for fname in os.listdir(self._dir):
            if fname.endswith(".meta"):
                fid = fname[:-5]
                with open(os.path.join(self._dir, fname)) as f:
                    meta = json.load(f)
                result.append({"file_id": fid, **meta})
        return result

    def get_meta(self, file_id: str) -> Optional[dict]:
        p = self._meta_path(file_id)
        if not os.path.exists(p):
            return None
        with open(p) as f:
            return json.load(f)

    def read_raw(self, file_id: str) -> bytes:
        data, _ = self.load(file_id)
        return data


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(65536)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_file_id() -> str:
    return str(uuid.uuid4())
