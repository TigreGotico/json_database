# XDG Base Directory Support

## What is XDG?

The [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html)
is a standard for where Linux applications should store their files. It lets
users and system administrators control storage locations via environment
variables instead of hard-coded paths like `~/.myapp`.

| Directory type | Default path | Environment variable |
|---|---|---|
| User cache | `~/.cache` | `XDG_CACHE_HOME` |
| User config | `~/.config` | `XDG_CONFIG_HOME` |
| User data | `~/.local/share` | `XDG_DATA_HOME` |
| User state | `~/.local/state` | `XDG_STATE_HOME` |
| Runtime | _(not set by default)_ | `XDG_RUNTIME_DIR` |

## Path Resolution

All XDG classes in `json_database` resolve their storage path at construction
time. The path has the form:

```
{xdg_dir}/{subfolder}/{name}.{extension}
```

Where `xdg_dir` is read from the appropriate environment variable (falling back
to the default if the variable is unset, empty, or contains a relative path).

This resolution is done by helper functions in `json_database/xdg_utils.py`,
which implement the full spec including the requirement to ignore relative paths
in environment variables.

## XDG Classes

### JsonStorageXDG

`json_database/__init__.py:385`

Persistent dict stored in the XDG **cache** directory. Use for data that can be
safely deleted (e.g. session tokens, temporary application state).

```python
from json_database import JsonStorageXDG

# Default: ~/.cache/json_database/session.json
store = JsonStorageXDG("session")

# Custom XDG folder
store = JsonStorageXDG("session", xdg_folder="/mnt/fast_cache")

# Custom subfolder (avoids collisions with other packages)
store = JsonStorageXDG("session", subfolder="myapp")
# path: ~/.cache/myapp/session.json

# Custom extension
store = JsonStorageXDG("session", extension="cache")
# path: ~/.cache/json_database/session.cache
```

**Constructor:**

```python
JsonStorageXDG(name, xdg_folder=xdg_cache_home(), disable_lock=False,
               subfolder="json_database", extension="json")
```

### JsonConfigXDG

`json_database/__init__.py:440`

Persistent dict stored in the XDG **config** directory. Use for user
preferences and settings.

```python
from json_database import JsonConfigXDG

# Default: ~/.config/json_database/myapp.json
config = JsonConfigXDG("myapp")
config["theme"] = "dark"
config.store()
```

**Constructor:**

```python
JsonConfigXDG(name, xdg_folder=xdg_config_home(), disable_lock=False,
              subfolder="json_database", extension="json")
```

### JsonDatabaseXDG

`json_database/__init__.py:421`

Searchable list-of-records database stored in the XDG **data** directory.
Use for persistent application data.

```python
from json_database import JsonDatabaseXDG

# Default: ~/.local/share/json_database/users.jsondb
db = JsonDatabaseXDG("users")
db.add_item({"id": 1, "username": "alice"})
db.commit()
```

**Constructor:**

```python
JsonDatabaseXDG(name, xdg_folder=xdg_data_home(), disable_lock=False,
                subfolder="json_database", extension="jsondb")
```

### EncryptedJsonStorageXDG

`json_database/__init__.py:405`

Encrypted persistent dict stored in the XDG **data** directory. Use for
sensitive data such as API keys or credentials.

```python
from json_database import EncryptedJsonStorageXDG

key = "1234567890123456"

# Default: ~/.local/share/json_database/secrets.ejson
store = EncryptedJsonStorageXDG(key, "secrets")
store["api_key"] = "sk-abc"
store.store()
```

**Constructor:**

```python
EncryptedJsonStorageXDG(encrypt_key, name, xdg_folder=xdg_data_home(),
                        disable_lock=False, subfolder="json_database",
                        extension="ejson")
```

## Overriding Paths via Environment Variables

Set the relevant environment variable before starting your application:

```bash
export XDG_DATA_HOME=/mnt/external/data
export XDG_CONFIG_HOME=/etc/myapp
```

`json_database` will then use the overridden paths automatically. The variables
are read at the time each XDG class is instantiated, not at import time (the
module-level `XDG_*` constants in `xdg_utils.py` are legacy aliases and are set
at import time — prefer calling the functions directly).

## XDG Helper Functions

`json_database/xdg_utils.py`

These are the underlying path resolution functions. They return `pathlib.Path`
objects.

| Function | Returns | Default |
|---|---|---|
| `xdg_cache_home()` | `Path` | `~/.cache` |
| `xdg_config_home()` | `Path` | `~/.config` |
| `xdg_data_home()` | `Path` | `~/.local/share` |
| `xdg_state_home()` | `Path` | `~/.local/state` |
| `xdg_runtime_dir()` | `Path \| None` | `None` if `XDG_RUNTIME_DIR` unset |
| `xdg_config_dirs()` | `List[Path]` | `[/etc/xdg]` |
| `xdg_data_dirs()` | `List[Path]` | `[/usr/local/share, /usr/share]` |

All functions silently fall back to the default if the corresponding environment
variable contains a relative path, as required by the spec.
