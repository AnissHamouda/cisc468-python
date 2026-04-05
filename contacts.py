"""
Contact store: persists known peers and their public keys.
"""

import json
import os
from typing import Optional, List, Dict

from .crypto import fingerprint, encode_b64, decode_b64


class Contact:
    def __init__(
        self,
        pub_bytes: bytes,
        host: str,
        port: int,
        alias: str = "",
        verified: bool = False,
        revoked: bool = False,
        successor_fp: Optional[str] = None,   # fingerprint of new key after rotation
    ):
        self.pub_bytes = pub_bytes
        self.host = host
        self.port = port
        self.alias = alias
        self.verified = verified
        self.revoked = revoked
        self.successor_fp = successor_fp

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.pub_bytes)

    def to_dict(self) -> dict:
        return {
            "pub_bytes": encode_b64(self.pub_bytes),
            "host": self.host,
            "port": self.port,
            "alias": self.alias,
            "verified": self.verified,
            "revoked": self.revoked,
            "successor_fp": self.successor_fp,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Contact":
        return cls(
            pub_bytes=decode_b64(d["pub_bytes"]),
            host=d.get("host", ""),
            port=d.get("port", 0),
            alias=d.get("alias", ""),
            verified=d.get("verified", False),
            revoked=d.get("revoked", False),
            successor_fp=d.get("successor_fp"),
        )

    def display(self) -> str:
        status = "✓ verified" if self.verified else "? unverified"
        if self.revoked:
            status = "✗ REVOKED"
        addr = f"{self.host}:{self.port}"
        fp = self.fingerprint
        name = self.alias or "(no alias)"
        return (
            f"  {name}\n"
            f"    fingerprint : {fp}\n"
            f"    address     : {addr}\n"
            f"    status      : {status}"
        )


class ContactStore:
    def __init__(self, path: str):
        self._path = path
        self._contacts: Dict[str, Contact] = {}  # keyed by fingerprint
        self._load()

    def _load(self):
        if not os.path.exists(self._path):
            return
        with open(self._path) as f:
            data = json.load(f)
        for fp_key, d in data.items():
            c = Contact.from_dict(d)
            self._contacts[c.fingerprint] = c

    def _save(self):
        data = {fp: c.to_dict() for fp, c in self._contacts.items()}
        tmp = self._path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, self._path)
        os.chmod(self._path, 0o600)

    def add(self, contact: Contact):
        self._contacts[contact.fingerprint] = contact
        self._save()

    def get(self, fp: str) -> Optional[Contact]:
        # support partial fingerprint matching
        fp = fp.upper()
        if fp in self._contacts:
            return self._contacts[fp]
        matches = [c for k, c in self._contacts.items() if k.replace(":", "").startswith(fp.replace(":", ""))]
        if len(matches) == 1:
            return matches[0]
        return None

    def get_by_host_port(self, host: str, port: int) -> Optional[Contact]:
        for c in self._contacts.values():
            if c.host == host and c.port == port:
                return c
        return None

    def all(self) -> List[Contact]:
        return list(self._contacts.values())

    def verify(self, fp: str) -> bool:
        c = self.get(fp)
        if c is None:
            return False
        c.verified = True
        self._save()
        return True

    def mark_revoked(self, fp: str, successor_fp: Optional[str] = None):
        c = self.get(fp)
        if c:
            c.revoked = True
            c.successor_fp = successor_fp
            self._save()

    def update_address(self, fp: str, host: str, port: int):
        c = self.get(fp)
        if c:
            c.host = host
            c.port = port
            self._save()
