# Architecture

## Design Goals

- **Zero schema.** Records are plain Python dicts. No migrations, no ORM.
- **Minimal dependencies.** Only `combo_lock` is required for core functionality.
- **Dict compatibility.** Storage classes are `dict` subclasses, so any code
  that works with a dict works with `JsonStorage`.
- **Optional layers.** Encryption and XDG path resolution are opt-in; the core
  is usable without them.

## Class Hierarchy

```
dict
├── JsonStorage                     (persistent dict + file locking)
│   ├── EncryptedJsonStorage        (AES-GCM encryption layer)
│   │   └── EncryptedJsonStorageXDG (XDG path resolution for data dir)
│   └── JsonStorageXDG              (XDG path resolution for cache dir)
│       └── JsonConfigXDG           (XDG path resolution for config dir)
└── JsonDatabase                    (list-of-records + search)
    └── JsonDatabaseXDG             (XDG path resolution for data dir)

Query                               (stateful filter builder, not a dict)
```

`json_database/__init__.py`

## Module Overview

| Module | Role |
|---|---|
| `json_database/__init__.py` | All public storage and database classes |
| `json_database/search.py` | `Query` builder |
| `json_database/crypto.py` | AES-GCM encrypt/decrypt, zlib compress/decompress |
| `json_database/utils.py` | `merge_dict`, fuzzy matching, recursive search helpers, `DummyLock` |
| `json_database/xdg_utils.py` | XDG path resolution (adapted from Scott Stevenson's xdg library) |
| `json_database/exceptions.py` | Custom exception classes |
| `json_database/version.py` | Version constants |

## Data Flow: JsonStorage

```
Construction
  └── load_local(path)
        └── load_commented_json(path)    # strips // and # comments
              └── json.loads(...)
                    └── dict.update(self, data)

store(path)
  └── json.dump(self, file, indent=4)    # writes full dict as JSON
```

File locking wraps both `load_local` and `store` via `ComboLock` (or
`DummyLock`). The lock file lives in `/tmp/{basename}.lock`.

### Aliasing semantics

`JsonStorage` is a thin `dict` subclass with no `__setitem__` override —
assigned values are stored *by reference*, matching plain `dict` semantics.
Mutating the original object after assignment is reflected in the JSON
written on the next `store()`:

```python
d = {"v": "original"}
storage["x"] = d
d["v"] = "mutated"
storage.store()  # writes {"v": "mutated"}
```

This is intentional. It supports the common pattern of building a nested
structure in place (`storage["x"] = {}; storage["x"]["k"] = v`) and avoids
hidden copy overhead. Callers that want isolation between in-memory state
and on-disk state must take their own snapshot before assignment (`dict(d)`,
`copy.deepcopy(d)`, etc.).

`JsonDatabase` chose the opposite default — see [Data Flow: JsonDatabase](#data-flow-jsondatabase)
below.

## Data Flow: EncryptedJsonStorage

```
Construction
  └── load_local(path)
        └── JsonStorage.load_local(path)   # loads ciphertext JSON blob
              └── decrypt_from_json(key, blob)
                    ├── unhexlify ciphertext, tag, nonce
                    ├── AES.new(key, GCM, nonce).decrypt_and_verify(...)
                    └── zlib.decompress(plaintext)
              └── dict.update(self, plaintext)

store(path)
  ├── snapshot plaintext = dict(self)
  ├── encrypt_as_json(key, plaintext)
  │     ├── zlib.compress(json.dumps(plaintext))
  │     ├── AES.new(key, GCM).encrypt_and_digest(compressed)
  │     └── json.dumps({"ciphertext": hex, "tag": hex, "nonce": hex})
  ├── dict.clear(self); dict.update(self, ciphertext_blob)
  ├── JsonStorage.store(path)              # writes ciphertext JSON
  └── dict.clear(self); dict.update(self, plaintext)  # restore
```

## Data Flow: JsonDatabase

`JsonDatabase` does not extend `JsonStorage`. It holds a `JsonStorage` instance
as `self.db` and treats the entry `self.db[self.name]` as its record list.

```
self.db = {
    "users": [
        {"name": "Alice", "age": 30},
        {"name": "Bob",   "age": 25},
    ]
}
```

Operations on the database manipulate `self.db[self.name]` (a Python list)
directly. `commit()` calls `self.db.store()` to flush changes to disk.

Item IDs are stable list indices. `remove_item` writes `None` (a tombstone) into
the slot rather than popping it, so higher indices are never shifted. Tombstoned
slots are skipped by `__iter__`, `__len__`, `search_by_key`, `search_by_value`,
and `__contains__`; a direct `db[item_id]` on a tombstone raises `InvalidItemID`
(`json_database/__init__.py:252`).

### Aliasing semantics

Unlike `JsonStorage`, `JsonDatabase` isolates stored records from caller
state. Every mutation entry point (`add_item`, `append`, `merge_item`,
`replace_item`, `update_item`, `__setitem__` via `update_item`) routes input
through `jsonify_recursively` (`utils.py:314`), which rebuilds every nested
`dict` and `list`. Mutating the caller-side object after insertion has no
effect on the stored record. This is the opposite default to `JsonStorage` —
see [Aliasing semantics](#aliasing-semantics) under `JsonStorage` above.

## Query Builder

`Query` is not a `dict` subclass. It holds a mutable list `self.result`
initialised from all records in a `JsonDatabase`. Each filter method applies
a `list` comprehension or loop to `self.result` in-place and returns `self`.

```
Query(db)
  └── self.result = list(db)   # shallow copy of all records

.equal("status", "active")
  └── self.result = [r for r in self.result if r["status"] == "active"]

.build()
  └── return self.result
```

Because each filter mutates the same list, chaining is zero-copy after the
initial snapshot.

## Locking Strategy

`ComboLock` (from the `combo_lock` package) provides both threading and
multiprocessing safety via a combination of a threading lock and a lockfile.
The lock file path is derived from the database file's basename and placed in
the system temp directory.

`DummyLock` (`json_database/utils.py:5`) is a no-op drop-in used when
`disable_lock=True`. Use only in single-threaded, single-process contexts.

## HiveMind Plugin

The HiveMind database-plugin adapter that used to live here as
`json_database/hpm.py` was extracted into its own package,
[`hivemind-json-db-plugin`](https://github.com/JarbasHiveMind/hivemind-json-db-plugin),
so it can release on a HiveMind-aligned cadence and `json_database` doesn't pull
`hivemind-plugin-manager` in for every consumer. See that repo's documentation
for the plugin's storage shape, schema-migration contract, and read/write
semantics.

## Serialisation Notes

`jsonify_recursively` (`json_database/utils.py:317`) converts arbitrary Python
objects to JSON-compatible structures before storage. It uses `hasattr(thing, '__dict__')`
(not `try/except`) to detect non-dict/list/scalar objects and reads `thing.__dict__`.
This means:

- Objects stored via `add_item` lose their class identity; they become plain dicts.
- If you need typed objects on retrieval, implement your own deserialisation layer
  or use an ORM.

The commented JSON loader (`load_commented_json`) allows `//` and `#` line
comments in stored JSON files. Files produced by `store()` contain no comments
(standard JSON), but hand-edited files may use them.
