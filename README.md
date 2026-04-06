# p2pshare — Secure P2P File Sharing

A peer-to-peer encrypted file-sharing tool built for CISC 468. Supports mDNS discovery, mutal authentication, encrypted transfers, offline relay and key rotation. Designed to interoperate with the Go reference client via a shared protocol spec.

## Installation

```bash
pip install cryptography zeroconf
python p2pshare.py --help
```

## Commands

| Command | Description |
|---|---|
| `serve [--port PORT]` | Start TLS 1.3 server + mDNS advertisement |
| `discover` | Scan LAN for peers via mDNS (_cisc468._tcp) |
| `add-contact host:port` | Exchange Ed25519 keys with a peer |
| `list-contacts` | Print all contacts with status |
| `verify-contact <fingerprint>` | Mark contact as verified (after out-of-band confirmation) |
| `share <path>` | Sign and add file to share index |
| `unshare <file_id>` | Remove file from share index |
| `list-files host:port` | List peer's shared files (no consent) |
| `request-file host:port <file_id>` | Download file (with PFS, integrity verify) |
| `rotate-key` | Generate new key, notify all contacts |

## Spec Compliance

### Protocol

| Feature | Implementation |
|---|---|
| mDNS service type | `_cisc468._tcp.local.` |
| Service name | First 16 hex chars of fingerprint |
| TXT record | `fingerprint=<64-char hex>` |
| Fingerprint | `hex(sha256(raw_ed25519_pubkey))` → 64 hex chars |
| Frame format | `[4-byte big-endian uint32][UTF-8 JSON]`, max 4 MB |
| Transport | TLS 1.3 via Python `ssl` module |

### Envelope format (sorted keys)

```json
{
  "from": "<64-char fingerprint>",
  "id": "<uuid>",
  "payload": {},
  "sig": "<base64 Ed25519>",
  "type": "MESSAGE_TYPE",
  "v": 1
}
```

Canonical for signing: `{"v":1,"type":"...","id":"...","from":"...","payload":{...}}`

Signed types: `HELLO`, `CONTACT_REQUEST`, `CONTACT_ACCEPT`, `HANDSHAKE_INIT`, `HANDSHAKE_RESP`, `KEY_ROTATE_NOTICE`, `TRANSFER_START`

### Cryptography

| Feature | Algorithm |
|---|---|
| Identity keys | Ed25519 |
| Session key derivation | HKDF-SHA256, 4 labels: TX/RX/NTX/NRX |
| Transport encryption | AES-256-GCM (chunk-level) |
| Password KDF | Argon2id (time=3, mem=64MB, threads=4) |
| File integrity | SHA-256 + Ed25519 manifest signature |

### HKDF labels (exact spec)

```
salt      = initiator_nonce XOR responder_nonce
info_base = "CISC468-SESSION-V1" + init_fp + resp_fp

TX key   : info_base + "TX"   → 32 bytes  (init→resp)
RX key   : info_base + "RX"   → 32 bytes  (resp→init)
NTX base : info_base + "NTX"  → 12 bytes
NRX base : info_base + "NRX"  → 12 bytes
```

### Chunk nonce

```
chunk_nonce = nonce_base XOR pad_left(uint64_be(chunk_index), 12)
XOR applied to last 8 bytes of 12-byte nonce_base
```

Chunk AAD: `"<file_id>:<chunk_index>:<total_chunks>:<message_id>"`
Chunk size: 512 KB (524,288 bytes)

### Handshake transcript

```
"CISC468-HANDSHAKE-V1"
+ initiator_fp (64 hex chars)
+ responder_fp (64 hex chars)
+ initiator_ephemeral_x25519_pubkey (32 bytes)
+ responder_ephemeral_x25519_pubkey (32 bytes)
+ initiator_nonce (32 bytes)
+ responder_nonce (32 bytes)
+ 0x00000001 (protocol version uint32 big-endian)
```

### Manifest canonical JSON (alphabetically sorted keys)

```json
{
  "file_id": "...",
  "filename": "...",
  "original_owner": "...",
  "sha256_hex": "...",
  "size": 12345,
  "timestamp": "2025-01-01T00:00:00Z"
}
```

### Storage layout (`~/.p2pshare/`)

```
identity.key          nonce || AES-GCM ciphertext of Ed25519 seed
identity.key.meta     JSON { salt: b64, pubkey: b64 }
contacts.json.enc     AES-GCM ciphertext of contacts JSON
contacts.json.meta    JSON { nonce: b64 }
share_index.json      Plaintext JSON { file_id → SharedFile }
files/<id>.enc        AES-GCM ciphertext of received file
files/<id>.meta       JSON { nonce, filename, sha256_hex, size, ... }
storage.salt          32-byte salt for storage key derivation
file_list_cache/      Cached peer file lists for proxy download
```