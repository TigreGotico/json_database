# Installation

## Python Version Support

Python 3.10, 3.11, 3.12, and 3.13 are tested in CI. Python 3.8 and 3.9 are not
officially tested but may work.

## Install from PyPI

```bash
pip install json_database
```

## Install from Source

```bash
git clone https://github.com/TigreGotico/json_database
cd json_database
pip install -e .
```

## Dependencies

| Package | Version | Purpose |
|---|---|---|
| `combo_lock` | `>=0.2.1,<1.0.0` | Cross-process file locking for safe concurrent access |

The lock dependency is mandatory. `combo_lock` creates a `.lock` file in the
system temp directory alongside each database file.

## Optional Encryption Dependency

Encryption features (`EncryptedJsonStorage`, `EncryptedJsonStorageXDG`) require
a `pycryptodome`-compatible AES implementation. Install one of:

```bash
pip install pycryptodomex   # preferred (Cryptodome namespace)
# or
pip install pycryptodome    # fallback (Crypto namespace)
```

If neither is installed, constructing an `EncryptedJsonStorage` succeeds but
calling `store()` or `load_local()` raises `ImportError: run pip install
pycryptodomex`.

## HiveMind Plugin Dependency

The `json_database.hpm` module (HiveMind plugin) additionally requires:

```bash
pip install "hivemind-plugin-manager>=0.5.0" ovos-utils
```

These are not installed by default and are only needed if you use the
`hivemind-json-db-plugin` entry point. `>=0.5.0` ships the `Client.metadata`
field that the plugin stores transparently — see [Architecture](ARCHITECTURE.md#hivemind-plugin).

## Verifying the Install

```python
import json_database
print(json_database.__version__)  # e.g. "0.10.2a1"
```
