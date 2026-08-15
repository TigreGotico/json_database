# Quick Start

## 1. Persistent Dictionary — JsonStorage

`JsonStorage` is a plain Python `dict` that automatically loads from and saves
to a JSON file.

```python
from json_database import JsonStorage

# Load (or create) a file on disk
config = JsonStorage("/tmp/my_config.json")

# Use it exactly like a dict
config["host"] = "localhost"
config["port"] = 5432

# Persist to disk
config.store()

# Reload from disk (discards in-memory changes)
config["port"] = 9999
config.reload()
assert config["port"] == 5432  # reverted

# Use as a context manager — store() is called automatically on exit
with JsonStorage("/tmp/my_config.json") as cfg:
    cfg["debug"] = True
```

The file is created (including any missing parent directories) on the first
`store()` call. If the file does not yet exist, `JsonStorage` starts as an empty
dict and no error is raised.

## 2. Searchable Database — JsonDatabase

`JsonDatabase` stores a list of records and supports search, filtering, and CRUD.

```python
from json_database import JsonDatabase

# Context manager commits automatically
with JsonDatabase("users", "/tmp/users.jsondb") as db:
    db.add_item({"name": "Alice", "age": 30, "role": "admin"})
    db.add_item({"name": "Bob",   "age": 25, "role": "user"})
    db.add_item({"name": "Carol", "age": 30, "role": "user"})

# Re-open the saved database
db = JsonDatabase("users", "/tmp/users.jsondb")

# Search by key (returns items that have the key set)
users_with_age = db.search_by_key("age")
# [{"name": "Alice", ...}, {"name": "Bob", ...}, {"name": "Carol", ...}]

# Search by key/value pair
admins = db.search_by_value("role", "admin")
# [{"name": "Alice", "age": 30, "role": "admin"}]

# Fuzzy search — returns (item, confidence_score) tuples
matches = db.search_by_value("name", "alic", fuzzy=True)
for item, score in matches:
    print(item["name"], score)  # Alice  0.888...
```

## 3. Fluent Query Builder

For multi-condition filtering use the `Query` builder from `json_database.search`.

```python
from json_database import JsonDatabase
from json_database.search import Query

db = JsonDatabase("products", "/tmp/products.jsondb")
db.add_item({"name": "Laptop",  "category": "Electronics", "price": 999.99, "in_stock": True})
db.add_item({"name": "Mouse",   "category": "Electronics", "price": 29.99,  "in_stock": True})
db.add_item({"name": "Notebook","category": "Stationery",  "price": 4.99,   "in_stock": True})
db.add_item({"name": "Monitor", "category": "Electronics", "price": 349.00, "in_stock": False})

# Chain filters — each call narrows the result set
results = (Query(db)
           .equal("category", "Electronics")
           .equal("in_stock", True)
           .below("price", 100)
           .build())
# [{"name": "Mouse", ...}]
```

See [Search and Query](SEARCH.md) for all available filter methods.

## 4. XDG-Compliant Storage

Use XDG variants to store files in standard Linux directories without specifying
absolute paths.

```python
from json_database import JsonStorageXDG, JsonDatabaseXDG, JsonConfigXDG

# ~/.cache/json_database/session.json
cache = JsonStorageXDG("session")
cache["token"] = "abc123"
cache.store()

# ~/.config/json_database/myapp.json
config = JsonConfigXDG("myapp")
config["theme"] = "dark"
config.store()

# ~/.local/share/json_database/users.jsondb
db = JsonDatabaseXDG("users")
db.add_item({"id": 1, "username": "alice"})
db.commit()
```

See [XDG Paths](XDG.md) for details on path resolution and customisation.

## 5. Encrypted Storage

```python
from json_database import EncryptedJsonStorage

key = "1234567890123456"  # exactly 16 bytes
store = EncryptedJsonStorage(key, "/tmp/secrets.ejson")
store["api_key"] = "sk-abc123"
store.store()  # written encrypted; plaintext never touches disk

# Re-open — decrypts transparently
store2 = EncryptedJsonStorage(key, "/tmp/secrets.ejson")
print(store2["api_key"])  # sk-abc123
```

See [Encryption](ENCRYPTION.md) for key rules and security considerations.
