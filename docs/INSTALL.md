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

## HiveMind Plugin

The HiveMind plugin previously bundled here as `json_database.hpm` was
extracted into its own package,
[`hivemind-json-db-plugin`](https://github.com/JarbasHiveMind/hivemind-json-db-plugin).
Install that package directly:

```bash
pip install hivemind-json-db-plugin
```

For the 1.x line, the legacy `[hpm]` extra is preserved as a transitive
shim — `pip install json_database[hpm]` keeps resolving to a working
install of `hivemind-json-db-plugin`, so the `hivemind.database`
entry point remains available without code changes:

```bash
pip install "json_database[hpm]"   # back-compat — still works in 1.x
```

The `[hpm]` extra will be **removed in 2.0.0**; existing users should
migrate to the direct install before then.

## Verifying the Install

```python
import json_database
print(json_database.__version__)  # e.g. "0.10.2a1"
```
