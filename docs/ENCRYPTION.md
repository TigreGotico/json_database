# Encryption

## Overview

`EncryptedJsonStorage` and `EncryptedJsonStorageXDG` store data encrypted on
disk using AES-256-GCM (Galois/Counter Mode). The payload is also zlib-compressed
before encryption, so large datasets benefit from reduced file sizes.

The encryption layer is implemented in `json_database/crypto.py`.

## Algorithm Details

| Property | Value |
|---|---|
| Algorithm | AES-GCM |
| Key length | 16 bytes (128-bit) |
| Nonce | Random, generated per write by `AES.new` |
| Authentication tag | 16 bytes (GCM standard) |
| Pre-encryption compression | `zlib.compress` |
| Post-decryption decompression | `zlib.decompress` |

The on-disk format is a JSON object with three hex-encoded fields:

```json
{
    "ciphertext": "<hex>",
    "tag":        "<hex>",
    "nonce":      "<hex>"
}
```

The nonce is randomly generated each time `store()` is called, so every write
produces a different ciphertext even if the plaintext is unchanged.

## Key Rules

> **Warning:** Keys longer than 16 bytes are silently truncated.
> `encrypt_as_json` and `decrypt_from_json` slice the key to 16 bytes before
> use (`json_database/crypto.py:44-45`). The `EncryptedJsonStorage` constructor
> enforces `len(encrypt_key) == 16` with an `AssertionError`, but if you call
> the crypto functions directly this guard is absent.

- Use exactly 16 bytes (128-bit key).
- The key must be a `str`; it is encoded to `bytes` as UTF-8 internally.
- Keep your key out of source code. Read it from an environment variable or a
  secrets manager.

```python
import os
key = os.environ["APP_SECRET_KEY"]  # must be exactly 16 bytes when encoded UTF-8
assert len(key) == 16
```

## In-Memory Behaviour

The dict is always plaintext in memory. Encryption happens only at `store()`:

1. `store()` takes a snapshot of the plaintext dict.
2. Encrypts it.
3. Temporarily replaces the in-memory dict with the ciphertext.
4. Calls `JsonStorage.store()` to write the ciphertext to disk.
5. Restores the plaintext dict in memory.

`json_database/__init__.py:169-179`

This means you can read and write the dict normally at any time; the encrypted
representation never leaks into Python code that holds a reference to the object.

## Loading

On construction, `load_local` calls the parent loader (which reads the JSON
ciphertext blob), then immediately decrypts and replaces the dict contents with
plaintext. `json_database/__init__.py:155-167`

## Web Crypto Compatibility

`decrypt_from_json` has a compatibility path for payloads produced by browser
Web Crypto API, where the authentication tag is appended to the ciphertext
rather than stored separately. If the `"tag"` field is absent, the last 16 bytes
of `ciphertext` are treated as the tag. `json_database/crypto.py:58-60`

## XDG Variant

`EncryptedJsonStorageXDG` stores the encrypted file in
`~/.local/share/json_database/{name}.ejson` by default (XDG data home).

```python
from json_database import EncryptedJsonStorageXDG

key = "1234567890123456"
store = EncryptedJsonStorageXDG(key, "credentials")
# path: ~/.local/share/json_database/credentials.ejson

store["token"] = "abc123"
store.store()
```

The `.ejson` extension distinguishes encrypted files from plain `.json` files
in the same directory.

## Dependency

Encryption requires either `pycryptodomex` (preferred) or `pycryptodome`.
If neither is installed, `encrypt()` and `decrypt()` raise `ImportError`.
See [Installation](INSTALL.md#optional-encryption-dependency).

## What Encryption Does NOT Protect Against

- **Key exposure.** If an attacker obtains the key, all data is readable.
- **Metadata.** File name, size, and modification time are visible on disk.
- **Memory.** The plaintext dict lives in process memory unprotected.
- **Integrity of the key itself.** There is no key derivation, stretching, or
  salt; the raw key bytes are passed directly to AES. Use a high-entropy key.
