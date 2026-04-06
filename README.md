# p2pshare — Secure P2P File Sharing

Fully spec-compliant implementation of CISC468 P2P file sharing protocol.

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
| Key exchange | X25519 ephemeral ECDH |
| Session key derivation | HKDF-SHA256, 4 labels: TX/RX/NTX/NRX |
| Transport encryption | AES-256-GCM (chunk-level) |
| File encryption at rest | AES-256-GCM |
| Contact encryption at rest | AES-256-GCM |
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

## Security Properties

1. **Mutual authentication** — Ed25519 signatures on all handshake messages + CONTACT_REQUEST/ACCEPT; fingerprint = `hex(sha256(pubkey))` verified at key exchange
2. **Perfect Forward Secrecy** — fresh X25519 keypair per session; session keys via HKDF; compromise of long-term Ed25519 key cannot decrypt past sessions
3. **File integrity** — SHA-256 checked on receipt; Ed25519 manifest signature verified against original owner's key (works even through proxy peers)
4. **Chunk-level authentication** — each 512 KB chunk is AES-256-GCM encrypted with AAD binding it to `file_id:chunk_index:total_chunks:message_id`; replay/reorder attacks caught
5. **At-rest encryption** — received files and contacts stored AES-256-GCM encrypted; identity key Argon2id-password-protected
6. **Key rotation** — old key signs the rotation notice; contacts verify, mark old key revoked, add new key (unverified); user must re-verify out-of-band
7. **Proxy downloads** — original owner's Ed25519 manifest signature travels with the file and is verified regardless of which peer serves it
