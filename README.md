# json_database

Searchable, persistent Python dict database backed by JSON files — for those
times when SQL is overkill.

[![Unit Tests](https://github.com/TigreGotico/json_database/actions/workflows/unit_tests.yml/badge.svg)](https://github.com/TigreGotico/json_database/actions/workflows/unit_tests.yml)
[![codecov](https://codecov.io/gh/TigreGotico/json_database/branch/master/graph/badge.svg)](https://codecov.io/gh/TigreGotico/json_database)
[![PyPI](https://img.shields.io/pypi/v/json_database)](https://pypi.org/project/json_database/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/json_database)](https://pypi.org/project/json_database/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Install

```bash
pip install json_database
```

Encryption features additionally require `pycryptodomex`:

```bash
pip install json_database pycryptodomex
```

## Quick Start

```python
from json_database import JsonStorage, JsonDatabase
from json_database.search import Query

# Persistent dict
with JsonStorage("/tmp/config.json") as cfg:
    cfg["host"] = "localhost"
    cfg["port"] = 5432
# auto-saved on exit

# Searchable list-of-records
with JsonDatabase("users", "/tmp/users.jsondb") as db:
    db.add_item({"name": "Alice", "role": "admin"})
    db.add_item({"name": "Bob",   "role": "user"})

admins = db.search_by_value("role", "admin")

# Fluent query builder
results = Query(db).equal("role", "user").build()
```

## Features

- Pure Python, minimal dependencies (`combo_lock` only)
- Persistent dict (`JsonStorage`) and list-of-records database (`JsonDatabase`)
- Recursive search by key and key/value pair, with optional fuzzy matching
- Fluent `Query` builder for multi-condition filtering
- AES-256-GCM encryption at rest (`EncryptedJsonStorage`)
- XDG Base Directory compliant variants for Linux applications
- File locking via `combo_lock` for safe concurrent access
- Supports commented JSON files (`//` and `#` line comments)
- Arbitrary Python objects stored via automatic `jsonify_recursively` conversion
- HiveMind plugin (`hivemind-json-db-plugin`) for voice assistant integration

## Configuration / Key Options

| Class | Default path | Use for |
|---|---|---|
| `JsonStorage(path)` | user-specified | any persistent dict |
| `JsonStorageXDG(name)` | `~/.cache/json_database/{name}.json` | cache / temp data |
| `JsonConfigXDG(name)` | `~/.config/json_database/{name}.json` | app settings |
| `JsonDatabaseXDG(name)` | `~/.local/share/json_database/{name}.jsondb` | persistent records |
| `EncryptedJsonStorage(key, path)` | user-specified | sensitive data at rest |

> **Note:** Item IDs in `JsonDatabase` are stable list indices. `add_item` and
> `append` return the zero-based slot index of the new item. Removing an item
> tombstones its slot rather than shifting subsequent IDs, so an ID obtained
> from `add_item` or `get_item_id` remains valid for the lifetime of the
> database file. Tombstoned slots are invisible to iteration, search,
> `__contains__`, and `__len__`; accessing one via `db[item_id]` raises
> `InvalidItemID`.

> **Warning:** Encryption keys longer than 16 bytes are silently truncated to
> 16 bytes. Always use exactly 16 bytes.

## Documentation

- [Installation](docs/INSTALL.md) — dependencies, Python version support
- [Quick Start](docs/QUICKSTART.md) — 5-minute walkthrough with examples
- [API Reference](docs/API.md) — all public classes and methods
- [Encryption](docs/ENCRYPTION.md) — AES-GCM details, key rules, security notes
- [XDG Paths](docs/XDG.md) — XDG spec support and path resolution
- [Search and Query](docs/SEARCH.md) — all filter methods, fuzzy matching
- [Development](docs/DEVELOPMENT.md) — running tests, CI, contributing
- [Architecture](docs/ARCHITECTURE.md) — class hierarchy, data flow, design

## HiveMind Integration

This project includes a native [hivemind-plugin-manager](https://github.com/JarbasHiveMind/hivemind-plugin-manager)
integration (`>=0.5.0`), providing JSON-backed storage for HiveMind client
credentials and permissions via the `hivemind-json-db-plugin` entry point.

The storage layer is schema-less: the entire `Client.__dict__` is persisted
per record, so new `Client` fields (e.g. the `metadata` dict added in
plugin-manager 0.5.0) round-trip transparently without changes here. See
[Architecture → HiveMind Plugin](docs/ARCHITECTURE.md#hivemind-plugin) for
the storage shape and the deep-copy aliasing contract.

## License

MIT
