#!/usr/bin/env python3
"""
p2pshare.py — Secure P2P File Sharing CLI

Commands:
  serve
  discover
  add-contact <host:port>
  list-contacts
  verify-contact <fingerprint>
  share <path>
  unshare <file_id>
  list-files <host:port>
  request-file <host:port> <file_id>
  rotate-key
"""

import os
import sys
import json
import getpass
import argparse
import logging
import threading
import hashlib

# Ensure local imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from crypto_utils import (
    Identity, argon2id_derive, b64e, b64d,
    fingerprint_from_bytes, ARGON2_TIME, ARGON2_MEMORY, ARGON2_THREADS,
)
from protocol import canonical_manifest
from storage import (
    ContactStore, ShareIndex, ReceivedFileStore,
    Contact, SharedFile, sha256_file, utc_now, new_file_id,
)
from server import Server
from client import Client
from discovery import MDNSAdvertiser, discover_peers

log = logging.getLogger(__name__)
DATA_DIR = os.path.expanduser("~/.p2pshare")


# ---------------------------------------------------------------------------
# App context
# ---------------------------------------------------------------------------

class App:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(data_dir, mode=0o700, exist_ok=True)
        self._identity: Identity = None
        self._contacts: ContactStore = None
        self._share_index: ShareIndex = None
        self._received: ReceivedFileStore = None
        self._file_key: bytes = None

    def _derive_file_key(self, password: str) -> bytes:
        """Derive a separate AES-256 key for contacts/files from the password + a fixed salt file."""
        salt_path = os.path.join(self.data_dir, "storage.salt")
        if os.path.exists(salt_path):
            with open(salt_path, "rb") as f:
                salt = f.read()
        else:
            import os as _os
            salt = _os.urandom(32)
            with open(salt_path, "wb") as f:
                f.write(salt)
            os.chmod(salt_path, 0o600)
        return argon2id_derive(password.encode(), salt)

    def load_or_create_identity(self, password: str = None) -> Identity:
        if self._identity is not None:
            return self._identity
        if Identity.exists(self.data_dir):
            if password is None:
                password = getpass.getpass("Password: ")
            try:
                self._identity = Identity.load(self.data_dir, password)
            except Exception as e:
                print(f"[ERROR] Failed to unlock identity: {e}")
                sys.exit(1)
        else:
            if password is None:
                print("[SETUP] No identity found. Creating a new one.")
                password = getpass.getpass("Choose a password: ")
                pw2 = getpass.getpass("Confirm password: ")
                if password != pw2:
                    print("[ERROR] Passwords do not match.")
                    sys.exit(1)
            self._identity = Identity.generate()
            self._identity.save(self.data_dir, password)
            print(f"[OK] New identity created.")
            print(f"  Fingerprint: {self._identity.fingerprint}")

        self._file_key = self._derive_file_key(password if password else "")
        return self._identity

    def load_stores(self, password: str = None):
        identity = self.load_or_create_identity(password)
        if self._file_key is None:
            self._file_key = self._derive_file_key(password or "")
        self._contacts    = ContactStore(self.data_dir, self._file_key)
        self._share_index = ShareIndex(self.data_dir)
        self._received    = ReceivedFileStore(self.data_dir, self._file_key)
        return identity, self._contacts, self._share_index, self._received


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_serve(args, app: App):
    pw = getpass.getpass("Password: ")
    identity, contacts, share_index, received = app.load_stores(pw)

    port = args.port
    server = Server(
        identity, contacts, share_index,
        data_dir=app.data_dir,
        port=port,
    )
    actual_port = server.start()

    # mDNS advertisement
    mdns = MDNSAdvertiser(identity.fingerprint, actual_port)
    mdns.start()

    print(
        f"\n P2P Share Server\n"
        f"  fingerprint : {identity.fingerprint}\n"
        f"  port        : {actual_port}\n"
        f"  shared files: {len(share_index.all())}\n"
        f"  contacts    : {len(contacts.all())}\n"
        f"\nCtrl+C to stop."
    )
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        mdns.stop()
        server.stop()


def cmd_discover(args, app: App):
    print("Scanning LAN for peers (5 s)...")
    try:
        peers = discover_peers(timeout=5.0)
    except Exception as e:
        print(f"[ERROR] Discovery failed: {e}")
        return
    if not peers:
        print("No peers found.")
        return
    print(f"\nFound {len(peers)} peer(s):\n")
    for p in peers:
        print(f"  {p['host']}:{p['port']}")
        print(f"    fingerprint: {p['fingerprint']}")
    print(f"\nUse: add-contact <host:port>")


def cmd_add_contact(args, app: App):
    pw = getpass.getpass("Password: ")
    identity, contacts, share_index, received = app.load_stores(pw)

    # Parse host:port — handle IPv6 [::1]:port
    target = args.host_port
    try:
        if target.startswith("["):
            host, port_s = target.rsplit(":", 1)
            host = host.strip("[]")
        else:
            host, port_s = target.rsplit(":", 1)
        port = int(port_s)
    except ValueError:
        print(f"[ERROR] Invalid address format. Use host:port")
        return

    # We need a server running to receive the CONTACT_ACCEPT response listener port
    # For add-contact we use a temporary server just to get our listen port
    # If serve is running we'd use that port; here we pick a temporary port
    listen_port = getattr(args, "listen_port", 0)

    client = Client(identity, contacts, share_index, received, listen_port=listen_port)
    try:
        contact = client.add_contact(host, port)
        print(f"\n[OK] Contact added:")
        print(f"  Fingerprint : {contact.fingerprint}")
        print(f"  Address     : {host}:{contact.port}")
        print(f"\n[!] Verify out-of-band:")
        print(f"    verify-contact {contact.fingerprint}")
    except Exception as e:
        print(f"[ERROR] {e}")


def cmd_list_contacts(args, app: App):
    pw = getpass.getpass("Password: ")
    _, contacts, _, _ = app.load_stores(pw)
    all_c = contacts.all()
    if not all_c:
        print("No contacts.")
        return
    print(f"\n{len(all_c)} contact(s):\n")
    for c in all_c:
        status = "✓ verified" if c.verified else "? unverified"
        if c.revoked:
            status = "✗ REVOKED"
            if c.successor_fp:
                status += f" → {c.successor_fp[:16]}..."
        print(f"  {c.alias or '(no alias)'}")
        print(f"    fingerprint : {c.fingerprint}")
        print(f"    address     : {c.host}:{c.port}")
        print(f"    status      : {status}")
        print()


def cmd_verify_contact(args, app: App):
    pw = getpass.getpass("Password: ")
    _, contacts, _, _ = app.load_stores(pw)
    fp = args.fingerprint.lower()
    contact = contacts.get(fp)
    if contact is None:
        print(f"[ERROR] No contact matching fingerprint: {fp}")
        return
    print(f"\nContact to verify:")
    print(f"  Fingerprint : {contact.fingerprint}")
    print(f"  Address     : {contact.host}:{contact.port}")
    print(f"\nConfirm this fingerprint matches what the contact shows you out-of-band.")
    ans = input("Mark as verified? [y/N]: ").strip().lower()
    if ans == "y":
        contacts.mark_verified(contact.fingerprint)
        print(f"[OK] {contact.fingerprint[:16]}... marked as verified.")
    else:
        print("Cancelled.")


def cmd_share(args, app: App):
    pw = getpass.getpass("Password: ")
    identity, _, share_index, _ = app.load_stores(pw)

    path = os.path.expanduser(args.path)
    if not os.path.isfile(path):
        print(f"[ERROR] File not found: {path}")
        return

    filename  = os.path.basename(path)
    sha       = sha256_file(path)
    size      = os.path.getsize(path)
    file_id   = new_file_id()
    timestamp = utc_now()

    manifest_json = canonical_manifest(
        file_id, filename, identity.fingerprint, sha, size, timestamp,
    )
    manifest_sig = b64e(identity.sign(manifest_json))

    sf = SharedFile(
        file_id=file_id, filename=filename, path=path,
        sha256_hex=sha, size=size,
        original_owner=identity.fingerprint,
        manifest_sig=manifest_sig, timestamp=timestamp,
    )
    share_index.add(sf)
    print(f"\n[OK] Now sharing '{filename}'")
    print(f"  file_id  : {file_id}")
    print(f"  SHA-256  : {sha}")
    print(f"  size     : {size} bytes")


def cmd_unshare(args, app: App):
    pw = getpass.getpass("Password: ")
    _, _, share_index, _ = app.load_stores(pw)
    if share_index.remove(args.file_id):
        print(f"[OK] Removed {args.file_id} from share index.")
    else:
        print(f"[ERROR] file_id not found: {args.file_id}")


def cmd_list_files(args, app: App):
    pw = getpass.getpass("Password: ")
    identity, contacts, share_index, received = app.load_stores(pw)

    target = args.host_port
    try:
        host, port_s = target.rsplit(":", 1)
        port = int(port_s)
    except ValueError:
        print(f"[ERROR] Invalid address: {target}")
        return

    client = Client(identity, contacts, share_index, received)
    try:
        files = client.list_files(host, port)
    except Exception as e:
        print(f"[ERROR] {e}")
        return

    if not files:
        print("No files available from that peer.")
        return

    print(f"\n{len(files)} file(s):\n")
    for f in files:
        owner_short = f.get("original_owner", "?")[:16]
        print(f"  {f['filename']}")
        print(f"    file_id  : {f['file_id']}")
        print(f"    SHA-256  : {f['sha256_hex']}")
        print(f"    size     : {f['size']} bytes")
        print(f"    owner    : {owner_short}...")
        print()


def cmd_request_file(args, app: App):
    pw = getpass.getpass("Password: ")
    identity, contacts, share_index, received = app.load_stores(pw)

    target = args.host_port
    try:
        host, port_s = target.rsplit(":", 1)
        port = int(port_s)
    except ValueError:
        print(f"[ERROR] Invalid address: {target}")
        return

    client = Client(identity, contacts, share_index, received)
    try:
        ok = client.request_file(host, port, args.file_id)
        if not ok:
            sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)


def cmd_rotate_key(args, app: App):
    pw = getpass.getpass("Password: ")
    identity, contacts, share_index, received = app.load_stores(pw)

    print(
        "\n[KEY ROTATION]\n"
        "This generates a new identity key. All contacts will be notified.\n"
        "They must re-verify your new fingerprint out-of-band.\n"
    )
    ans = input("Continue? [y/N]: ").strip().lower()
    if ans != "y":
        print("Cancelled.")
        return

    old_identity = identity
    new_identity = Identity.generate()

    print(f"  Old fingerprint: {old_identity.fingerprint}")
    print(f"  New fingerprint: {new_identity.fingerprint}")

    new_pw  = getpass.getpass("Password for new key: ")
    new_pw2 = getpass.getpass("Confirm password: ")
    if new_pw != new_pw2:
        print("[ERROR] Passwords do not match.")
        return

    # Save new identity
    new_identity.save(app.data_dir, new_pw)
    app._identity = new_identity

    # Notify contacts using old identity
    client = Client(old_identity, contacts, share_index, received)
    print("\nNotifying contacts...")
    client.notify_key_rotation(old_identity, new_identity)

    print(
        f"\n[OK] Key rotation complete.\n"
        f"  Share your new fingerprint out-of-band:\n"
        f"  {new_identity.fingerprint}"
    )


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(prog="p2pshare", description="Secure P2P File Sharing")
    parser.add_argument("--data-dir", default=DATA_DIR,
                        help="Data directory (default: ~/.p2pshare)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    sub = parser.add_subparsers(dest="command")

    # serve
    p_serve = sub.add_parser("serve", help="Start the P2P server")
    p_serve.add_argument("--port", type=int, default=0, help="Listen port (default: auto)")

    # discover
    sub.add_parser("discover", help="Scan LAN for peers via mDNS")

    # add-contact
    p_ac = sub.add_parser("add-contact", help="Exchange keys with a peer")
    p_ac.add_argument("host_port", metavar="host:port")
    p_ac.add_argument("--listen-port", type=int, default=0,
                      help="Our listening port to advertise")

    # list-contacts
    sub.add_parser("list-contacts", help="Print all contacts")

    # verify-contact
    p_vc = sub.add_parser("verify-contact", help="Mark a contact as verified")
    p_vc.add_argument("fingerprint")

    # share
    p_sh = sub.add_parser("share", help="Add a file to the share index")
    p_sh.add_argument("path")

    # unshare
    p_us = sub.add_parser("unshare", help="Remove a file from the share index")
    p_us.add_argument("file_id")

    # list-files
    p_lf = sub.add_parser("list-files", help="List files available from a peer")
    p_lf.add_argument("host_port", metavar="host:port")

    # request-file
    p_rf = sub.add_parser("request-file", help="Download a file from a peer")
    p_rf.add_argument("host_port", metavar="host:port")
    p_rf.add_argument("file_id")

    # rotate-key
    sub.add_parser("rotate-key", help="Generate new identity key and notify contacts")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.WARNING)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    app = App(data_dir=os.path.expanduser(args.data_dir))

    dispatch = {
        "serve":          cmd_serve,
        "discover":       cmd_discover,
        "add-contact":    cmd_add_contact,
        "list-contacts":  cmd_list_contacts,
        "verify-contact": cmd_verify_contact,
        "share":          cmd_share,
        "unshare":        cmd_unshare,
        "list-files":     cmd_list_files,
        "request-file":   cmd_request_file,
        "rotate-key":     cmd_rotate_key,
    }

    fn = dispatch.get(args.command)
    if fn is None:
        print(f"[ERROR] Unknown command: {args.command}")
        sys.exit(1)

    try:
        fn(args, app)
    except KeyboardInterrupt:
        print("\n[interrupted]")
    except SystemExit:
        raise
    except Exception as e:
        print(f"\n[ERROR] {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
