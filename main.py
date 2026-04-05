#!/usr/bin/env python3
"""
P2P File Sharing Application - Main Entry Point
"""

import argparse
import sys
import os
import logging

# Ensure the package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from p2p.cli import CLI
from p2p.config import Config

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

def main():
    parser = argparse.ArgumentParser(
        prog="p2p-share",
        description="Secure Peer-to-Peer File Sharing"
    )
    parser.add_argument("--data-dir", default="~/.p2p_share",
                        help="Directory for storing app data (default: ~/.p2p_share)")
    parser.add_argument("--port", type=int, default=0,
                        help="Port to listen on (default: auto)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # serve
    subparsers.add_parser("serve", help="Start the P2P server")

    # discover
    subparsers.add_parser("discover", help="Scan LAN for peers using mDNS")

    # add-contact
    p_add = subparsers.add_parser("add-contact", help="Connect to a peer and exchange keys")
    p_add.add_argument("host_port", metavar="host:port", help="Peer address")

    # list-contacts
    subparsers.add_parser("list-contacts", help="List all known contacts")

    # verify-contact
    p_verify = subparsers.add_parser("verify-contact", help="Mark a contact as verified")
    p_verify.add_argument("fingerprint", help="Fingerprint of the contact to verify")

    # share
    p_share = subparsers.add_parser("share", help="Add a file to the share index")
    p_share.add_argument("path", help="Path to file to share")

    # request
    p_req = subparsers.add_parser("request", help="Request a file from a contact")
    p_req.add_argument("fingerprint", help="Contact fingerprint")
    p_req.add_argument("filename", help="Filename to request")

    # send
    p_send = subparsers.add_parser("send", help="Send a file to a contact")
    p_send.add_argument("fingerprint", help="Contact fingerprint")
    p_send.add_argument("path", help="Path to file to send")

    # list-files
    p_lf = subparsers.add_parser("list-files", help="List files shared by a contact")
    p_lf.add_argument("fingerprint", help="Contact fingerprint")

    # rotate-key
    subparsers.add_parser("rotate-key", help="Generate a new identity key and notify contacts")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    config = Config(data_dir=os.path.expanduser(args.data_dir), port=args.port)
    cli = CLI(config)

    try:
        cli.run(args)
    except KeyboardInterrupt:
        print("\n[interrupted]")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
