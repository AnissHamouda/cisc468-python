"""
CLI command dispatcher for P2P Share.
"""

import os
import sys
import json
import getpass
import hashlib
import logging
import threading
from typing import Optional

from .config import Config
from .crypto import Identity, FileKeyStore, fingerprint as fp_of, encode_b64, decode_b64
from .contacts import ContactStore, Contact
from .share_index import ShareIndex, SharedFile, PeerFileCache, file_sha256
from .server import Server
from .client import Client
from .discovery import advertise_service, discover_peers

log = logging.getLogger(__name__)

IDENTITY_FILE = "identity.json"
STATE_FILE = "state.json"


class CLI:
    def __init__(self, config: Config):
        self.config = config
        self._identity: Optional[Identity] = None
        self._contacts: Optional[ContactStore] = None
        self._share_index: Optional[ShareIndex] = None
        self._peer_cache: Optional[PeerFileCache] = None
        self._file_key_store: Optional[FileKeyStore] = None

    # -----------------------------------------------------------------------
    # Command dispatch
    # -----------------------------------------------------------------------

    def run(self, args):
        cmd = args.command
        if cmd == "serve":
            self.cmd_serve(args)
        elif cmd == "discover":
            self.cmd_discover()
        elif cmd == "add-contact":
            self.cmd_add_contact(args.host_port)
        elif cmd == "list-contacts":
            self.cmd_list_contacts()
        elif cmd == "verify-contact":
            self.cmd_verify_contact(args.fingerprint)
        elif cmd == "share":
            self.cmd_share(args.path)
        elif cmd == "request":
            self.cmd_request(args.fingerprint, args.filename)
        elif cmd == "send":
            self.cmd_send(args.fingerprint, args.path)
        elif cmd == "list-files":
            self.cmd_list_files(args.fingerprint)
        elif cmd == "rotate-key":
            self.cmd_rotate_key()
        else:
            print(f"[ERROR] Unknown command: {cmd}")
            sys.exit(1)

    # -----------------------------------------------------------------------
    # serve
    # -----------------------------------------------------------------------

    def cmd_serve(self, args):
        identity = self._load_or_create_identity()
        contacts, share_index, peer_cache, fks = self._load_stores(identity)

        port = self.config.port
        server = Server(
            identity=identity,
            contacts=contacts,
            share_index=share_index,
            peer_cache=peer_cache,
            file_key_store=fks,
            received_dir=self.config.received_dir,
            port=port,
        )
        actual_port = server.start()
        self._save_state(actual_port)

        # Advertise via mDNS
        zc = None
        try:
            zc, info = advertise_service(identity.fingerprint, actual_port)
        except ImportError:
            print("[WARN] zeroconf not installed. mDNS advertisement disabled.")
        except Exception as e:
            print(f"[WARN] mDNS advertisement failed: {e}")

        print(
            f"\n P2P Share Server running\n"
            f"  fingerprint : {identity.fingerprint}\n"
            f"  port        : {actual_port}\n"
            f"  shared files: {len(share_index.all())}\n"
            f"  contacts    : {len(contacts.all())}\n"
            f"\nPress Ctrl+C to stop."
        )
        try:
            threading.Event().wait()
        finally:
            server.stop()
            if zc:
                zc.close()

    # -----------------------------------------------------------------------
    # discover
    # -----------------------------------------------------------------------

    def cmd_discover(self):
        print("Scanning LAN for peers (5 seconds)...")
        try:
            peers = discover_peers(timeout=5.0)
        except ImportError:
            print("[ERROR] zeroconf not installed. Run: pip install zeroconf")
            return

        if not peers:
            print("No peers found.")
            return

        print(f"\nFound {len(peers)} peer(s):")
        for p in peers:
            print(f"  {p['host']}:{p['port']}  fingerprint={p['fingerprint']}")
        print("\nUse 'add-contact <host:port>' to connect.")

    # -----------------------------------------------------------------------
    # add-contact
    # -----------------------------------------------------------------------

    def cmd_add_contact(self, host_port: str):
        identity = self._load_or_create_identity()
        contacts, share_index, peer_cache, fks = self._load_stores(identity)

        try:
            host, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        except ValueError:
            print("[ERROR] Invalid address. Use format: host:port")
            return

        client = Client(identity, contacts, share_index, peer_cache, fks, self.config.received_dir)
        try:
            contact = client.add_contact(host, port)
        except Exception as e:
            print(f"[ERROR] {e}")
            return

        print(
            f"\n[OK] Contact added:\n"
            f"  fingerprint : {contact.fingerprint}\n"
            f"  address     : {host}:{port}\n"
            f"\n[!] To confirm this contact is who you think it is, share the fingerprint\n"
            f"    out-of-band (e.g., in person or via Signal), then run:\n"
            f"    verify-contact {contact.fingerprint}"
        )

    # -----------------------------------------------------------------------
    # list-contacts
    # -----------------------------------------------------------------------

    def cmd_list_contacts(self):
        identity = self._load_or_create_identity()
        contacts, _, _, _ = self._load_stores(identity)
        all_contacts = contacts.all()
        if not all_contacts:
            print("No contacts.")
            return
        print(f"\n{len(all_contacts)} contact(s):\n")
        for c in all_contacts:
            print(c.display())
            print()

    # -----------------------------------------------------------------------
    # verify-contact
    # -----------------------------------------------------------------------

    def cmd_verify_contact(self, fp_str: str):
        identity = self._load_or_create_identity()
        contacts, _, _, _ = self._load_stores(identity)
        contact = contacts.get(fp_str)
        if contact is None:
            print(f"[ERROR] No contact with fingerprint matching: {fp_str}")
            return

        print(
            f"\nContact to verify:\n"
            f"  fingerprint : {contact.fingerprint}\n"
            f"  address     : {contact.host}:{contact.port}\n"
        )
        print("To verify, confirm that the fingerprint above matches what the contact")
        print("shows you out-of-band (in person, via Signal, etc.).")
        ans = input("Mark as verified? [y/N]: ").strip().lower()
        if ans == "y":
            contacts.verify(contact.fingerprint)
            print(f"[OK] Contact {contact.fingerprint[:16]}... marked as verified.")
        else:
            print("Verification cancelled.")

    # -----------------------------------------------------------------------
    # share
    # -----------------------------------------------------------------------

    def cmd_share(self, path: str):
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            print(f"[ERROR] File not found: {path}")
            return

        identity = self._load_or_create_identity()
        _, share_index, _, fks = self._load_stores(identity)

        filename = os.path.basename(path)
        print(f"Computing SHA-256 of '{filename}'...")
        sha = file_sha256(path)

        sig_payload = f"file:{filename}:{sha}".encode()
        sig = encode_b64(identity.sign(sig_payload))

        size = os.path.getsize(path)
        sf = SharedFile(
            filename=filename,
            path=path,
            sha256=sha,
            signature=sig,
            owner_fp=identity.fingerprint,
            size=size,
        )
        share_index.add(sf)

        print(
            f"\n[OK] Now sharing '{filename}':\n"
            f"  SHA-256     : {sha}\n"
            f"  size        : {size} bytes\n"
            f"  signed by   : {identity.fingerprint}"
        )

    # -----------------------------------------------------------------------
    # request
    # -----------------------------------------------------------------------

    def cmd_request(self, peer_fp: str, filename: str):
        identity = self._load_or_create_identity()
        contacts, share_index, peer_cache, fks = self._load_stores(identity)
        client = Client(identity, contacts, share_index, peer_cache, fks, self.config.received_dir)
        try:
            client.request_file(peer_fp, filename)
        except Exception as e:
            print(f"[ERROR] {e}")

    # -----------------------------------------------------------------------
    # send
    # -----------------------------------------------------------------------

    def cmd_send(self, peer_fp: str, path: str):
        identity = self._load_or_create_identity()
        contacts, share_index, peer_cache, fks = self._load_stores(identity)
        client = Client(identity, contacts, share_index, peer_cache, fks, self.config.received_dir)
        try:
            client.send_file(peer_fp, os.path.expanduser(path))
        except Exception as e:
            print(f"[ERROR] {e}")

    # -----------------------------------------------------------------------
    # list-files
    # -----------------------------------------------------------------------

    def cmd_list_files(self, peer_fp: str):
        identity = self._load_or_create_identity()
        contacts, share_index, peer_cache, fks = self._load_stores(identity)
        client = Client(identity, contacts, share_index, peer_cache, fks, self.config.received_dir)
        try:
            files = client.list_files(peer_fp)
        except Exception as e:
            print(f"[ERROR] {e}")
            return

        if not files:
            print("No files available from that peer.")
            return

        print(f"\n{len(files)} file(s):\n")
        for f in files:
            owner = f.get("owner_fp", "?")[:16]
            print(f"  {f['filename']}")
            print(f"    SHA-256   : {f.get('sha256', '?')}")
            print(f"    size      : {f.get('size', 0)} bytes")
            print(f"    owner     : {owner}...")
            print()

    # -----------------------------------------------------------------------
    # rotate-key
    # -----------------------------------------------------------------------

    def cmd_rotate_key(self):
        print(
            "\n[KEY ROTATION]\n"
            "This will generate a new identity key. Your old key will be revoked.\n"
            "All contacts will be notified. They will need to re-verify you.\n"
        )
        ans = input("Continue? [y/N]: ").strip().lower()
        if ans != "y":
            print("Cancelled.")
            return

        old_identity = self._load_or_create_identity()
        contacts, share_index, peer_cache, fks = self._load_stores(old_identity)

        # Generate new key
        new_identity = Identity.generate()
        print(f"\n  Old fingerprint: {old_identity.fingerprint}")
        print(f"  New fingerprint: {new_identity.fingerprint}")

        # Save new identity
        pw = self._get_password(confirm=True)
        self._save_identity(new_identity, pw)
        self._identity = new_identity

        # Notify all contacts using old identity's session
        client = Client(old_identity, contacts, share_index, peer_cache, fks, self.config.received_dir)
        print("\nNotifying contacts...")
        client.notify_key_rotation(old_identity, new_identity)

        print(
            f"\n[OK] Key rotation complete.\n"
            f"  Share your new fingerprint out-of-band so contacts can re-verify you:\n"
            f"  {new_identity.fingerprint}"
        )

    # -----------------------------------------------------------------------
    # Identity management
    # -----------------------------------------------------------------------

    def _load_or_create_identity(self) -> Identity:
        if self._identity:
            return self._identity

        identity_path = os.path.join(self.config.keys_dir, IDENTITY_FILE)

        if os.path.exists(identity_path):
            pw = getpass.getpass("Password: ")
            with open(identity_path) as f:
                data = json.load(f)
            try:
                identity = Identity.from_encrypted_dict(data, pw)
            except ValueError as e:
                print(f"[ERROR] {e}")
                sys.exit(1)
        else:
            print("[SETUP] No identity found. Creating a new one.")
            identity = Identity.generate()
            pw = self._get_password(confirm=True)
            self._save_identity(identity, pw)
            print(f"\n[OK] Identity created. Your fingerprint:\n  {identity.fingerprint}\n")

        self._identity = identity
        return identity

    def _save_identity(self, identity: Identity, password: str):
        identity_path = os.path.join(self.config.keys_dir, IDENTITY_FILE)
        data = identity.to_encrypted_dict(password)
        tmp = identity_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, identity_path)
        os.chmod(identity_path, 0o600)

    @staticmethod
    def _get_password(confirm: bool = False) -> str:
        while True:
            pw = getpass.getpass("Choose a password to protect your identity key: ")
            if not pw:
                print("[ERROR] Password cannot be empty.")
                continue
            if confirm:
                pw2 = getpass.getpass("Confirm password: ")
                if pw != pw2:
                    print("[ERROR] Passwords do not match.")
                    continue
            return pw

    def _load_stores(self, identity: Identity):
        if self._contacts is None:
            self._contacts = ContactStore(self.config.contacts_file)
        if self._share_index is None:
            self._share_index = ShareIndex(self.config.share_index_file)
        if self._peer_cache is None:
            self._peer_cache = PeerFileCache(self.config.peer_cache_file)
        if self._file_key_store is None:
            fks_path = os.path.join(self.config.keys_dir, "file_keys.bin")
            self._file_key_store = FileKeyStore(identity, fks_path)
        return self._contacts, self._share_index, self._peer_cache, self._file_key_store

    def _save_state(self, port: int):
        state = {"port": port}
        with open(self.config.state_file, "w") as f:
            json.dump(state, f)
