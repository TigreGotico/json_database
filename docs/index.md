# json_database

Searchable, persistent Python dict database backed by JSON files.

## Overview

`json_database` provides two complementary abstractions built on plain Python dicts:

- **JsonStorage** — a `dict` subclass that transparently loads from and saves to a JSON file, with optional file locking for concurrent access.
- **JsonDatabase** — a list-of-records database on top of `JsonStorage` that supports CRUD operations, recursive search by key or value, and a fluent `Query` builder for complex filtering.

Both abstractions have XDG-compliant variants that resolve paths according to the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html). An `EncryptedJsonStorage` variant wraps AES-256-GCM encryption around the plain storage layer.

## Key Classes

| Class | Purpose | Source |
|---|---|---|
| `JsonStorage` | Persistent dict backed by a JSON file | `json_database/__init__.py:23` |
| `EncryptedJsonStorage` | AES-GCM encrypted variant of JsonStorage | `json_database/__init__.py:124` |
| `JsonDatabase` | Searchable list-of-records database | `json_database/__init__.py:182` |
| `JsonStorageXDG` | JsonStorage placed in XDG cache dir | `json_database/__init__.py:398` |
| `EncryptedJsonStorageXDG` | EncryptedJsonStorage in XDG data dir | `json_database/__init__.py:418` |
| `JsonDatabaseXDG` | JsonDatabase placed in XDG data dir | `json_database/__init__.py:434` |
| `JsonConfigXDG` | JsonStorage placed in XDG config dir | `json_database/__init__.py:453` |
| `Query` | Fluent filter builder for JsonDatabase | `json_database/search.py:5` |

## Contents

- [Installation](INSTALL.md)
- [Quick Start](QUICKSTART.md)
- [API Reference](API.md)
- [Encryption](ENCRYPTION.md)
- [XDG Paths](XDG.md)
- [Search and Query](SEARCH.md)
- [Development](DEVELOPMENT.md)
- [Architecture](ARCHITECTURE.md)
