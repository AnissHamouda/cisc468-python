# P2P Share — Secure Peer-to-Peer File Sharing

A command-line P2P file sharing application built with security at every layer.

---

## Features

| Feature | Implementation |
|---|---|
| Peer discovery | mDNS via `python-zeroconf` |
| Mutual authentication | Ed25519 signed handshake (TOFU + manual verification) |
| Consent for transfers | Interactive prompts before any file is sent or received |
| File listing (no consent) | `LIST_FILES` message, no consent required |
| Offline proxy downloads | Peer cache + origin signature verification |
| Key rotation | New key signed by old key, all contacts notified |
| Confidentiality & integrity | ChaCha20-Poly1305 (transport) + AES-256-GCM (storage) |
| Perfect Forward Secrecy | Ephemeral X25519 ECDH per session, HKDF-derived keys |
| Secure local storage | Files encrypted with per-file AES-256-GCM keys |
| Error reporting | Descriptive messages for all error and security events |

---

## Installation

```bash
cd p2p_share
pip install -r requirements.txt
```

---

## Quick Start

### On Machine A
```bash
# Start the server
python main.py serve

# Share a file
python main.py share ~/Documents/report.pdf
```

### On Machine B
```bash
# Discover peers on the LAN
python main.py discover

# Add Machine A as a contact
python main.py add-contact 192.168.1.10:PORT

# Verify the contact fingerprint (out-of-band, e.g. in person)
python main.py verify-contact AA:BB:CC:DD:...

# List files A is sharing
python main.py list-files AA:BB:CC:DD:...

# Request a file
python main.py request AA:BB:CC:DD:... report.pdf

# Send a file to A
python main.py send AA:BB:CC:DD:... ~/photos/vacation.jpg
```

---

## Commands

| Command | Description |
|---|---|
| `serve` | Start the P2P server (listens + advertises via mDNS) |
| `discover` | Scan the LAN for peers (5-second mDNS browse) |
| `add-contact <host:port>` | Connect to a peer and exchange public keys |
| `list-contacts` | Print all known contacts and their status |
| `verify-contact <fingerprint>` | Mark a contact as verified after out-of-band confirmation |
| `share <path>` | Add a file to your share index |
| `list-files <fingerprint>` | List files available from a contact |
| `request <fingerprint> <filename>` | Download a file from a contact |
| `send <fingerprint> <path>` | Push a file to a contact |
| `rotate-key` | Generate a new identity key and notify all contacts |

---

## Security Design

### Identity

Each user has a long-term **Ed25519** key pair. The 32-byte public key is hashed with SHA-256 to produce a human-readable colon-separated **fingerprint**:

```
AA:BB:CC:DD:EE:FF:00:11
```

The fingerprint is used to identify contacts everywhere in the application.

### Handshake (Mutual Authentication + PFS)

Every TCP session uses a Noise-inspired handshake:

1. **Initiator** sends `HELLO`: ephemeral X25519 public key + Ed25519 public key + Ed25519 signature over `(my_eph_pub || zeros || "hello")`
2. **Responder** sends `HELLO_REPLY`: same structure, with the initiator's ephemeral pub bound into the signature
3. Both sides perform **X25519 ECDH** on the ephemeral keys
4. Session keys are derived via **HKDF-SHA256**, binding both identity public keys into the info field
5. All further messages are encrypted with **ChaCha20-Poly1305**

Because session keys are derived from **ephemeral** key material, compromise of a long-term Ed25519 key does not allow decryption of past sessions (**Perfect Forward Secrecy**).

### File Integrity (including proxy downloads)

When a file is added to the share index:
- Its **SHA-256** hash is computed
- The owner signs `"file:<filename>:<sha256>"` with their Ed25519 key

When a file is received (whether directly or via a proxy):
1. The SHA-256 of the received bytes is recomputed and compared
2. The Ed25519 signature is verified against the **origin owner's** public key

This means even if you download through an untrusted third party, you can verify the file came untampered from the original owner.

### Local Storage Encryption

- Each file stored on disk is encrypted with a unique **AES-256-GCM** key
- All per-file keys are stored in an encrypted key store, protected by a **master key** derived from the identity private key via HKDF
- The identity private key is protected by a **password** (scrypt KDF → AES-256-GCM)
- All sensitive files are stored with mode `0o600`

### Key Rotation

1. User runs `rotate-key`
2. A new Ed25519 key pair is generated
3. The rotation announcement (`"key-rotation:" + new_pub_bytes`) is signed by the **old** private key
4. All online contacts are notified; they verify the announcement against the old key
5. Contacts mark the old key as **REVOKED** and add the new key as **unverified**
6. Contacts are prompted to re-verify the new fingerprint out-of-band

### Trust Model

Contact verification uses **TOFU (Trust On First Use)** with manual out-of-band confirmation:

1. `add-contact` performs the handshake and stores the peer's public key
2. The user is shown the fingerprint and instructed to verify it out-of-band
3. `verify-contact` marks the contact as verified

Unverified contacts can still exchange files, but a warning is shown. Revoked keys are rejected immediately.

---

## Architecture

```
main.py
└── p2p/
    ├── config.py        — Data directories and paths
    ├── crypto.py        — Ed25519, X25519, AES-GCM, ChaCha20, HKDF, scrypt
    ├── contacts.py      — Contact store (JSON, encrypted at rest)
    ├── share_index.py   — Share index + peer file cache
    ├── protocol.py      — Wire protocol: message framing, type constants
    ├── session.py       — Handshake, encrypted session layer
    ├── server.py        — TCP server, request/consent handlers
    ├── client.py        — Outbound connections, file transfer client
    ├── discovery.py     — mDNS advertisement and discovery
    └── cli.py           — Command-line interface
```

---

## Data Directory (`~/.p2p_share/`)

```
~/.p2p_share/
├── keys/
│   ├── identity.json      # Encrypted Ed25519 private key (scrypt + AES-GCM)
│   └── file_keys.bin      # Encrypted per-file key store (AES-GCM)
├── shared/                # Files you are sharing (originals, read directly)
├── received/              # Files you received (AES-256-GCM encrypted)
├── contacts.json          # Contact store (fingerprint → public key + metadata)
├── share_index.json       # Your share index (filename, sha256, signature)
└── peer_cache.json        # Cached file lists from other peers
```

All files are stored with permissions `0o600`. Directory permissions are `0o700`.

---

## Limitations & Future Work

- **No NAT traversal**: works on a local network. For internet use, add a relay or use a VPN.
- **Single-threaded consent**: the server pauses all connections during a consent prompt. A production system would use non-blocking I/O.
- **No alias management**: add an `alias-contact` command to name contacts.
- **No resumable transfers**: large file transfers start over on failure.
- **Argon2id** would be preferable over scrypt for password hashing (requires `argon2-cffi`).
