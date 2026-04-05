"""
Share index: tracks which files this node shares, their hashes and signatures,
and a cache of file lists obtained from other peers (for offline proxy downloads).
"""

import json
import os
import hashlib
from typing import Optional, List, Dict

from .crypto import encode_b64, decode_b64, sha256_hex, Identity


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class SharedFile:
    """A file this node is offering to share."""

    def __init__(
        self,
        filename: str,
        path: str,
        sha256: str,
        signature: str,  # base64-encoded Ed25519 sig over (filename + sha256)
        owner_fp: str,   # fingerprint of the signer
        size: int = 0,
    ):
        self.filename = filename
        self.path = path
        self.sha256 = sha256
        self.signature = signature
        self.owner_fp = owner_fp
        self.size = size

    @staticmethod
    def sign_payload(filename: str, sha256: str) -> bytes:
        return f"file:{filename}:{sha256}".encode()

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "path": self.path,
            "sha256": self.sha256,
            "signature": self.signature,
            "owner_fp": self.owner_fp,
            "size": self.size,
        }

    def to_public_dict(self) -> dict:
        """Dict safe to send to peers (no local path)."""
        return {
            "filename": self.filename,
            "sha256": self.sha256,
            "signature": self.signature,
            "owner_fp": self.owner_fp,
            "size": self.size,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SharedFile":
        return cls(
            filename=d["filename"],
            path=d.get("path", ""),
            sha256=d["sha256"],
            signature=d["signature"],
            owner_fp=d["owner_fp"],
            size=d.get("size", 0),
        )


class PeerFileCache:
    """
    Cache of file lists reported by each peer.
    Used so peer B can find files from offline peer A via peer C.
    Keyed by owner fingerprint -> list of SharedFile (public info only).
    """

    def __init__(self, path: str):
        self._path = path
        self._cache: Dict[str, List[dict]] = {}
        self._load()

    def _load(self):
        if not os.path.exists(self._path):
            return
        with open(self._path) as f:
            self._cache = json.load(f)

    def _save(self):
        tmp = self._path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._cache, f, indent=2)
        os.replace(tmp, self._path)
        os.chmod(self._path, 0o600)

    def update(self, owner_fp: str, files: List[dict]):
        self._cache[owner_fp] = files
        self._save()

    def get(self, owner_fp: str) -> List[dict]:
        return self._cache.get(owner_fp, [])

    def find_file(self, owner_fp: str, filename: str) -> Optional[dict]:
        for f in self.get(owner_fp):
            if f["filename"] == filename:
                return f
        return None

    def all_known_owners(self) -> List[str]:
        return list(self._cache.keys())


class ShareIndex:
    """Manages files this node is sharing."""

    def __init__(self, path: str):
        self._path = path
        self._files: Dict[str, SharedFile] = {}  # filename -> SharedFile
        self._load()

    def _load(self):
        if not os.path.exists(self._path):
            return
        with open(self._path) as f:
            data = json.load(f)
        for d in data:
            sf = SharedFile.from_dict(d)
            self._files[sf.filename] = sf

    def _save(self):
        data = [sf.to_dict() for sf in self._files.values()]
        tmp = self._path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self._path)
        os.chmod(self._path, 0o600)

    def add(self, sf: SharedFile):
        self._files[sf.filename] = sf
        self._save()

    def get(self, filename: str) -> Optional[SharedFile]:
        return self._files.get(filename)

    def all(self) -> List[SharedFile]:
        return list(self._files.values())

    def public_list(self) -> List[dict]:
        return [sf.to_public_dict() for sf in self._files.values()]
