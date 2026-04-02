# Json Database

Python dict based database with persistence and search capabilities

For those times when you need something simple and sql is overkill


## Features

- pure python
- save and load from file
- search recursively by key and key/value pairs
- fuzzy search
- supports arbitrary objects
- supports comments in saved files

## Install

```bash
pip install json_database
```


## 📡 HiveMind Integration

This project includes a native [hivemind-plugin-manager](https://github.com/JarbasHiveMind/hivemind-plugin-manager) integration, providing seamless interoperability with the HiveMind ecosystem.
- **Database Plugin**: Provides `hivemind-json-db-plugin` allowing to use JSON-based storage for client credentials and permissions
  
## 🐍 Usage


### JsonStorage

Sometimes you need persistent dicts that you can save and load from file

```python
from json_database import JsonStorage
from os.path import exists

save_path = "my_dict.conf"

my_config = JsonStorage(save_path)

my_config["lang"] = "pt"
my_config["secondary_lang"] = "en"
my_config["email"] = "jarbasai@mailfence.com"

# my_config is a python dict
assert isinstance(my_config, dict)

# save to file
my_config.store()

my_config["lang"] = "pt-pt"

# revert to previous saved file
my_config.reload()
assert my_config["lang"] == "pt"

# clear all fields
my_config.clear()
assert my_config == {}

# load from a specific path
my_config.load_local(save_path)
assert my_config == JsonStorage(save_path)

# delete stored file
my_config.remove()
assert not exists(save_path)

# keep working with dict in memory
print(my_config)
```

### JsonDatabase

Ever wanted to search a dict?

Let's create a dummy database with users

```python
from json_database import JsonDatabase

db_path = "users.db"

with JsonDatabase("users", db_path) as db:
    # add some users to the database

    for user in [
        {"name": "bob", "age": 12},
        {"name": "bobby"},
        {"name": ["joe", "jony"]},
        {"name": "john"},
        {"name": "jones", "age": 35},
        {"name": "joey", "birthday": "may 12"}]:
        db.add_item(user)
        
    # pretty print database contents
    db.print()


# auto saved when used with context manager
# db.commit()


```
         
search entries by key

```python
from json_database import JsonDatabase

db_path = "users.db"

db = JsonDatabase("users", db_path) # load db created in previous example

# search by exact key match
users_with_defined_age = db.search_by_key("age")

for user in users_with_defined_age:
    print(user["name"], user["age"])
    
# fuzzy search
users = db.search_by_key("birth", fuzzy=True)
for user, conf in users:
    print("matched with confidence", conf)
    print(user["name"], user["birthday"])
```

search by key value pair

```python
# search by key/value pair
users_12years_old = db.search_by_value("age", 12)

for user in users_12years_old:
    assert user["age"] == 12

# fuzzy search
jon_users = db.search_by_value("name", "jon", fuzzy=True)
for user, conf in jon_users:
    print(user["name"])
    print("matched with confidence", conf)
    # NOTE that one of the users has a list instead of a string in the name, it also matches
```

updating an existing entry

```python
# get database item
item = {"name": "bobby"}

item_id = db.get_item_id(item)

if item_id >= 0:
    new_item = {"name": "don't call me bobby"}
    db.update_item(item_id, new_item)
else:
    print("item not found in database")

# clear changes since last commit
db.reset()
```

You can save arbitrary objects to the database

```python
from json_database import JsonDatabase

db = JsonDatabase("users", "~/databases/users.json")


class User:
    def __init__(self, email, key=None, data=None):
        self.email = email
        self.secret_key = key
        self.data = data

user1 = User("first@mail.net", data={"name": "jonas", "birthday": "12 May"})
user2 = User("second@mail.net", "secret", data={"name": ["joe", "jony"], "age": 12})

# objects will be "jsonified" here, they will no longer be User objects
# if you need them to be a specific class use some ORM lib instead (SQLAlchemy is great)
db.add_item(user1)
db.add_item(user2)

# search entries with non empty key
print(db.search_by_key("secret_key"))

# search in user provided data
print(db.search_by_key("birth", fuzzy=True))

# search entries with a certain value
print(db.search_by_value("age", 12))
print(db.search_by_value("name", "jon", fuzzy=True))

```

## Query API

For more advanced filtering and searching, use the fluent Query builder API:

```python
from json_database import JsonDatabase
from json_database.search import Query

db = JsonDatabase("products", "products.db")

# Add some products
db.add_item({"id": 1, "name": "Laptop", "category": "Electronics", "price": 999.99, "in_stock": True})
db.add_item({"id": 2, "name": "Mouse", "category": "Electronics", "price": 29.99, "in_stock": True})
db.add_item({"id": 3, "name": "Book", "category": "Books", "price": 19.99, "in_stock": False})

# Chain multiple filters
query = Query(db)
results = (query
    .equal("category", "Electronics")
    .equal("in_stock", True)
    .below("price", 100)
    .build())

print(results)  # [Laptop, Mouse]

# Available filter methods:
# - contains_key(key, fuzzy=False, thresh=0.7, ignore_case=False)
# - contains_value(key, value, fuzzy=False, thresh=0.75, ignore_case=False)
# - value_contains(key, value, ignore_case=False)
# - value_contains_token(key, value, fuzzy=False, thresh=0.75, ignore_case=False)
# - equal(key, value, ignore_case=False)
# - below(key, value) / above(key, value)
# - below_or_equal(key, value) / above_or_equal(key, value)
# - in_range(key, min_value, max_value)
# - all() - no-op, returns all items
```

## Encryption

Store sensitive data encrypted on disk using AES-256-GCM:

```python
from json_database import EncryptedJsonStorage

# Create encrypted storage with 16-byte key
key = "1234567890123456"  # Must be exactly 16 bytes
encrypted_storage = EncryptedJsonStorage(key, "secrets.json")

# Data is readable in memory
encrypted_storage["api_key"] = "sk-1234567890abcdef"
encrypted_storage["password"] = "super_secret_password"

# But stored encrypted on disk
encrypted_storage.store()

# Decrypt on load
encrypted_storage2 = EncryptedJsonStorage(key, "secrets.json")
print(encrypted_storage2["api_key"])  # "sk-1234567890abcdef"

# Encrypted databases work the same way
from json_database import EncryptedJsonStorageXDG

# Uses XDG data directory for secure storage
encrypted_db = EncryptedJsonStorageXDG(key, "user_secrets")
encrypted_db["oauth_token"] = "token_value"
encrypted_db.store()
```

**Important:** Keys are truncated to 16 bytes if longer. Always use exactly 16 bytes.

## XDG Paths

Follow Linux XDG Base Directory specification for storing files in standard locations:

```python
from json_database import JsonStorageXDG, JsonDatabaseXDG, JsonConfigXDG

# Cache (temporary data, can be deleted)
cache = JsonStorageXDG("app_cache")  # ~/.cache/json_database/app_cache.json

# Data (persistent application data)
db = JsonDatabaseXDG("users")  # ~/.local/share/json_database/users.jsondb
db.add_item({"id": 1, "username": "alice"})
db.commit()

# Config (user preferences and settings)
config = JsonConfigXDG("myapp")  # ~/.config/json_database/myapp.json
config["theme"] = "dark"
config["language"] = "en"
config.store()

# Custom locations
from json_database import JsonStorageXDG

custom_cache = JsonStorageXDG("app", xdg_folder="/custom/path")
```

This ensures your application respects user preferences for where application data should be stored.

## HiveMind Integration

This library provides a persistent JSON database plugin for the HiveMind voice assistant ecosystem.

**HiveMind Plugin Features:**
- `hivemind-json-db-plugin` entry point for seamless integration with HiveMind plugin manager
- User database for storing client credentials and access control lists (ACLs)
- Flexible key-value storage for HiveMind configuration and user management
- Optional AES-GCM encryption support for sensitive credential storage
- Recursive search and filtering capabilities for finding users and permissions

The json_database serves as the backend storage for HiveMind's user authentication and permission system, allowing distributed voice assistant networks to manage client identities and ACLs consistently across nodes.

See [HiveMind documentation](https://github.com/JarbasHiveMind) for integration details and configuration examples.
