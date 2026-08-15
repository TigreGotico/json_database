# API Reference

All public symbols are importable from `json_database` unless noted otherwise.

---

## JsonStorage

`json_database/__init__.py:23`

A `dict` subclass that persists its contents to a JSON file on disk.

### Constructor

```python
JsonStorage(path: str, disable_lock: bool = False)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `path` | `str` | required | Absolute or relative path to the JSON file. `~` is expanded. |
| `disable_lock` | `bool` | `False` | When `True` a no-op `DummyLock` is used instead of `ComboLock`. Disable only when you are certain there is no concurrent access. |

On construction the file is loaded immediately if it exists. If it does not
exist the instance is an empty dict and no error is raised.

A `.lock` file is placed in the system temp directory, named after the basename
of `path` (e.g. `/tmp/mydb.json.lock`). `combo_lock` makes the lock safe across
threads and OS processes.

### Methods

#### `load_local(path: str) -> None`

`json_database/__init__.py:54`

Clears the current dict and repopulates it from the file at `path`. Supports
commented JSON (lines starting with `//` or `#` are ignored). Silently skips
if the file does not exist.

#### `reload() -> None`

`json_database/__init__.py:80`

Reloads from `self.path`. Raises `DatabaseNotCommitted` if the file does not
exist.

#### `store(path: str = None) -> None`

`json_database/__init__.py:86`

Serialises the dict to JSON and writes it to `path` (defaults to `self.path`).
Creates parent directories if they are missing. Writes with `indent=4` and
`ensure_ascii=False`.

#### `remove() -> None`

`json_database/__init__.py:101`

Deletes the file at `self.path`. No-op if the file does not exist.

#### `merge(conf: dict, merge_lists=True, skip_empty=True, no_dupes=True, new_only=False) -> JsonStorage`

`json_database/__init__.py:106`

Recursively merges `conf` into this dict. Returns `self`. See
[`merge_dict`](#merge_dict) for parameter semantics.

#### Context manager

`__enter__` returns `self`. `__exit__` calls `store()` and raises `SessionError`
if `store()` fails.

---

## EncryptedJsonStorage

`json_database/__init__.py:124`

Extends `JsonStorage`. Data is encrypted with AES-256-GCM before being written
to disk and decrypted transparently on load. In memory the dict is always
plaintext.

> **Warning:** Keys longer than 16 bytes are silently truncated to 16 bytes
> inside `encrypt_as_json` and `decrypt_from_json` (`json_database/crypto.py:44`).
> This happens after the `AssertionError` guard in the constructor, so passing a
> 32-byte key does not raise an error — only the first 16 bytes are used.

### Constructor

```python
EncryptedJsonStorage(encrypt_key: str, path: str, disable_lock: bool = False)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `encrypt_key` | `str` | required | Encryption key. Must be exactly 16 bytes (raises `AssertionError` otherwise). |
| `path` | `str` | required | Path to the encrypted JSON file. |
| `disable_lock` | `bool` | `False` | Passed to `JsonStorage`. |

### Overridden Methods

#### `load_local(path: str) -> None`

`json_database/__init__.py:155`

Calls the parent `load_local`, then decrypts the loaded payload in-place.

#### `store(path: str = None) -> None`

`json_database/__init__.py:169`

Encrypts the current plaintext dict, writes it, then restores the plaintext
dict in memory. The file on disk always contains ciphertext.

---

## JsonDatabase

`json_database/__init__.py:182`

A searchable list-of-records database backed by a `JsonStorage`. Records are
stored as a JSON array under a named key inside the file.

> **Note:** Item IDs are stable list indices. `remove_item` tombstones the
> slot (`None`) rather than shifting subsequent IDs, so an ID obtained from
> `add_item` or `get_item_id` remains valid for the lifetime of the database
> file. Tombstoned slots are invisible to iteration, search, `__contains__`,
> and `__len__`; accessing one raises `InvalidItemID`.

### Constructor

```python
JsonDatabase(name: str, path: str = None, disable_lock: bool = False, extension: str = "json")
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `name` | `str` | required | Database name. Used as the key inside the JSON file and as the default filename stem. |
| `path` | `str` | `None` | File path. Defaults to `{name}.{extension}`. |
| `disable_lock` | `bool` | `False` | Passed to the underlying `JsonStorage`. |
| `extension` | `str` | `"json"` | File extension when `path` is not given. |

### Dunder Behaviour

| Operation | Behaviour |
|---|---|
| `len(db)` | Count of live (non-tombstoned) records — `json_database/__init__.py:239` |
| `db[item_id]` | Fetch live record by stable integer index; also accepts a string that can be cast to `int`; raises `InvalidItemID` for tombstoned slots — `json_database/__init__.py:241` |
| `db[item_id] = value` | Replace record at index (calls `update_item`); raises `InvalidItemID` if index is out of range — `json_database/__init__.py:256` |
| `item in db` | Exact equality check across all records (including tombstone slots, which are `None` and never equal a user item) |
| `iter(db)` | Yields only live (non-`None`) records in index order — `json_database/__init__.py:262` |
| `repr(db)` | JSON-serialisable string of all live records |

### CRUD Methods

#### `add_item(value, allow_duplicates: bool = False) -> int`

`json_database/__init__.py:290`

Adds `value` to the database. Objects are serialised via `jsonify_recursively`
before storage. Returns the new length of the database.

If `allow_duplicates=False` (default) and an exact match already exists, returns
the existing item's ID instead of adding a duplicate.

#### `update_item(item_id: int, new_item) -> None`

`json_database/__init__.py:357`

Replaces the record at `item_id` with `new_item`.

#### `remove_item(item_id: int)`

`json_database/__init__.py:362`

Tombstones the slot at `item_id` by setting it to `None`. The slot is retained
so that all higher item IDs remain stable. Raises `InvalidItemID` if `item_id`
is out of range. The removed entry becomes invisible to `__iter__`, `__len__`,
`search_by_key`, `search_by_value`, and `__contains__`; accessing it via
`db[item_id]` raises `InvalidItemID`.

#### `get_item_id(item) -> int`

`json_database/__init__.py:351`

Returns the index of `item` using exact equality, or `-1` if not found.

#### `match_item(value, match_strategy=None) -> list`

`json_database/__init__.py:300`

Returns a list of `(item, index)` tuples for all exact matches. `match_strategy`
is accepted but currently unused; only exact equality is implemented.

#### `merge_item(value, item_id=None, match_strategy=None, merge_strategy=None) -> None`

`json_database/__init__.py:322`

Finds the matching item and merges `value` into it using `merge_dict`. Raises
`MatchError` if no match is found and `item_id` is not provided. `merge_strategy`
is accepted but currently unused.

#### `replace_item(value, item_id=None, match_strategy=None) -> None`

`json_database/__init__.py:340`

Finds the matching item and replaces it entirely with `value`. Raises `MatchError`
if no match and no `item_id`.

#### `append(value) -> int`

`json_database/__init__.py:285`

Unconditionally appends `value` (serialised). Returns the new length. Prefer
`add_item` for duplicate control.

### Persistence

#### `commit() -> None`

`json_database/__init__.py:272`

Writes the database to disk via `JsonStorage.store()`. Must be called explicitly
when not using the context manager.

#### `reset() -> None`

`json_database/__init__.py:278`

Discards in-memory changes by reloading from disk. Raises `DatabaseNotCommitted`
if the file does not exist.

#### `print() -> None`

`json_database/__init__.py:281`

Pretty-prints all records to stdout.

#### Context manager

`__enter__` returns `self`. `__exit__` calls `commit()` and raises `SessionError`
on failure.

### Search Methods

#### `search_by_key(key: str, fuzzy: bool = False, thresh: float = 0.7, include_empty: bool = False) -> list`

`json_database/__init__.py:373`

Iterates only live (non-tombstoned) records and returns those containing `key`.

- Exact mode: returns a list of dicts (the records that contain the key).
- Fuzzy mode: returns a list of `(record, score)` tuples sorted by descending score.

#### `search_by_value(key: str, value, fuzzy: bool = False, thresh: float = 0.7) -> list`

`json_database/__init__.py:384`

Iterates only live (non-tombstoned) records and returns those where `key == value`.

- Exact mode: returns a list of matching records.
- Fuzzy mode: returns a list of `(record, score)` tuples sorted by descending score.

---

## XDG Variants

All XDG classes resolve their storage path from environment variables at
construction time. See [XDG Paths](XDG.md) for full details.

### JsonStorageXDG

`json_database/__init__.py:398`

```python
JsonStorageXDG(name: str, xdg_folder=xdg_cache_home(), disable_lock=False,
               subfolder="json_database", extension="json")
```

Stored at `{xdg_folder}/{subfolder}/{name}.{extension}`.
Default path: `~/.cache/json_database/{name}.json`.

### EncryptedJsonStorageXDG

`json_database/__init__.py:418`

```python
EncryptedJsonStorageXDG(encrypt_key: str, name: str, xdg_folder=xdg_data_home(),
                        disable_lock=False, subfolder="json_database", extension="ejson")
```

Default path: `~/.local/share/json_database/{name}.ejson`.

### JsonDatabaseXDG

`json_database/__init__.py:434`

```python
JsonDatabaseXDG(name: str, xdg_folder=xdg_data_home(), disable_lock=False,
                subfolder="json_database", extension="jsondb")
```

Default path: `~/.local/share/json_database/{name}.jsondb`.

### JsonConfigXDG

`json_database/__init__.py:453`

```python
JsonConfigXDG(name: str, xdg_folder=xdg_config_home(), disable_lock=False,
              subfolder="json_database", extension="json")
```

Default path: `~/.config/json_database/{name}.json`.

---

## Query

`json_database/search.py:5`

Fluent filter builder. Initialised from a `JsonDatabase` (or a single dict) and
narrowed by chaining filter methods. Each method mutates `self.result` and
returns `self`.

```python
from json_database.search import Query

results = Query(db).equal("status", "active").above("score", 50).build()
```

See [Search and Query](SEARCH.md) for all filter methods and their semantics.

---

## Exceptions

`json_database/exceptions.py`

| Exception | Base | Raised when |
|---|---|---|
| `InvalidItemID` | `ValueError` | `item_id` is out of range or invalid |
| `DatabaseNotCommitted` | `FileNotFoundError` | `reload()` called before the file exists |
| `SessionError` | `RuntimeError` | Context manager cannot commit/store |
| `MatchError` | `ValueError` | `merge_item` or `replace_item` finds no match |
| `DecryptionKeyError` | `KeyError` | Decryption fails (payload not raised by current code path) |
| `EncryptionKeyError` | `KeyError` | Encryption fails (payload not raised by current code path) |

---

## Utility Functions

`json_database/utils.py`

These are used internally by the storage and search layers. They are importable
but considered internal API.

### `merge_dict`

`json_database/utils.py:76`

```python
merge_dict(base: dict, delta: dict, merge_lists=True, skip_empty=True,
           no_dupes=True, new_only=False) -> dict
```

Recursively merges `delta` into `base`. Returns `base`.

| Parameter | Effect when `True` |
|---|---|
| `merge_lists` | Appends list items rather than replacing the list |
| `skip_empty` | Does not overwrite a non-empty `base` value with an empty `delta` value (except `False`) |
| `no_dupes` | Deduplicates when merging lists |
| `new_only` | Skips keys that already exist in `base` |

### `fuzzy_match`

`json_database/utils.py:38`

```python
fuzzy_match(x: str, against: str) -> float
```

Returns a similarity ratio in `[0.0, 1.0]` using `difflib.SequenceMatcher`.

### `match_one`

`json_database/utils.py:47`

```python
match_one(query: str, choices: list | dict) -> tuple[str, float]
```

Returns `(best_match, score)` from `choices` using `fuzzy_match`.

### `load_commented_json`

`json_database/utils.py:110`

```python
load_commented_json(filename: str) -> object
```

Loads a JSON file, stripping lines that start with `//` or `#`.

### `jsonify_recursively`

`json_database/utils.py:321`

```python
jsonify_recursively(thing) -> dict | list | scalar
```

Converts arbitrary Python objects to JSON-serialisable structures by calling
`__dict__` on objects that are not already dicts, lists, or scalars.

### `get_key_recursively` / `get_key_recursively_fuzzy`

`json_database/utils.py:182`, `json_database/utils.py:215`

Traverse nested dicts and lists to find all dicts that contain a given key.
The fuzzy variant returns `(dict, score)` tuples sorted by descending score.

### `get_value_recursively` / `get_value_recursively_fuzzy`

`json_database/utils.py:251`, `json_database/utils.py:283`

Same traversal as above, but also checks that `key == target_value`. Fuzzy
variant matches on string similarity.

---

## DummyLock

`json_database/utils.py:5`

A lock that does nothing. Used when `disable_lock=True` is passed to any
storage constructor. Implements the same interface as `combo_lock.ComboLock`
(`acquire`, `release`, `__enter__`, `__exit__`).
