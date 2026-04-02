import json
import logging
import os
from os import makedirs, remove
from os.path import expanduser, isdir, dirname, exists, isfile, join
from pprint import pprint
from tempfile import gettempdir

from combo_lock import ComboLock

from json_database.crypto import decrypt_from_json, encrypt_as_json
from json_database.exceptions import InvalidItemID, DatabaseNotCommitted, \
    SessionError, MatchError
from json_database.utils import DummyLock, load_commented_json, merge_dict, \
    jsonify_recursively, get_key_recursively, get_key_recursively_fuzzy, \
    get_value_recursively_fuzzy, get_value_recursively
from json_database.xdg_utils import xdg_cache_home, xdg_data_home, xdg_config_home

LOG = logging.getLogger("JsonDatabase")
LOG.setLevel("INFO")


class JsonStorage(dict):
    """Persistent Python dictionary stored as JSON on disk.

    A dict subclass that automatically loads and saves data to a JSON file.
    Supports file locking for concurrent access and commented JSON loading.

    Attributes:
        path (str): File path where data is stored
        lock: Lock object (ComboLock or DummyLock) for thread/process safety

    Example:
        storage = JsonStorage("config.json")
        storage["key"] = "value"
        storage.store()  # Save to disk

        # Context manager auto-saves on exit
        with JsonStorage("config.json") as storage:
            storage["setting"] = 123
    """

    def __init__(self, path, disable_lock=False):
        super().__init__()
        lock_path = join(gettempdir(), path.split("/")[-1] + ".lock")
        if disable_lock:
            self.lock = DummyLock(lock_path)
        else:
            self.lock = ComboLock(lock_path)
        self.path = path
        if self.path:
            self.load_local(self.path)

    def load_local(self, path):
        """
            Load local json file into self.

            Args:
                path (str): file to load
        """
        with self.lock:
            path = expanduser(path)
            if exists(path) and isfile(path):
                self.clear()
                try:
                    config = load_commented_json(path)
                    for key in config:
                        self[key] = config[key]
                    LOG.debug("Json {} loaded".format(path))
                except Exception as e:
                    LOG.error("Error loading json '{}'".format(path))
                    LOG.error(repr(e))
            else:
                LOG.debug("Json '{}' not defined, skipping".format(path))

    def clear(self):
        for k in dict(self):
            self.pop(k)

    def reload(self):
        if exists(self.path) and isfile(self.path):
            self.load_local(self.path)
        else:
            raise DatabaseNotCommitted

    def store(self, path=None):
        """
            store the json db locally.
        """
        with self.lock:
            path = path or self.path
            if not path:
                LOG.warning("json db path not set")
                return
            path = expanduser(path)
            if dirname(path) and not isdir(dirname(path)):
                makedirs(dirname(path))
            with open(path, 'w', encoding="utf-8") as f:
                json.dump(self, f, indent=4, ensure_ascii=False)

    def remove(self):
        with self.lock:
            if isfile(self.path):
                remove(self.path)

    def merge(self, conf, merge_lists=True, skip_empty=True, no_dupes=True,
              new_only=False):
        merge_dict(self, conf, merge_lists, skip_empty, no_dupes, new_only)
        return self

    def __enter__(self):
        """ Context handler """
        return self

    def __exit__(self, _type, value, traceback):
        """ Commits changes and Closes the session """
        try:
            self.store()
        except Exception as e:
            LOG.error(e)
            raise SessionError


class EncryptedJsonStorage(JsonStorage):
    """Encrypted persistent Python dictionary using AES-GCM encryption.

    Extends JsonStorage to encrypt data with AES-256-GCM (symmetric encryption).
    Data is decrypted in memory but stored encrypted on disk.

    **WARNING:** Keys must be exactly 16 bytes; any other length raises AssertionError.
    **WARNING:** Item IDs (indices) are not stable across sessions.

    Attributes:
        encrypt_key (str): Encryption key (must be exactly 16 bytes)

    Raises:
        AssertionError: If encrypt_key is not exactly 16 bytes

    Example:
        key = "1234567890123456"  # 16 bytes
        storage = EncryptedJsonStorage(key, "secret.json")
        storage["password"] = "mypassword"
        storage.store()  # Stored encrypted on disk

        # Reload decrypts automatically
        storage2 = EncryptedJsonStorage(key, "secret.json")
        print(storage2["password"])  # "mypassword"
    """

    def __init__(self, encrypt_key: str, path: str, disable_lock=False):
        assert len(encrypt_key) == 16
        self.encrypt_key = encrypt_key
        super().__init__(path, disable_lock)

    def load_local(self, path):
        """
            Load local json file into self.

            Args:
                path (str): file to load
        """
        super().load_local(path)
        # decrypt after load
        if self:
            decrypted = json.loads(decrypt_from_json(self.encrypt_key, dict(self)))
            self.clear()
            self.update(decrypted)

    def store(self, path=None):
        """
            store the json db locally.
        """
        decrypted = dict(self)
        encrypted = json.loads(encrypt_as_json(self.encrypt_key, decrypted))
        self.clear()
        self.merge(encrypted)  # encrypt before storage
        super().store()
        self.clear()
        self.update(decrypted)  # keep it decrypted in memory


class JsonDatabase(dict):
    """Searchable persistent list-of-records database backed by JSON.

    A dict-like database that stores a list of records (items) and provides
    search, filtering, and CRUD operations. All changes must be committed
    to disk with commit() or via context manager.

    **WARNING:** Item IDs are indices and shift when items are removed.
    Do not persist item IDs across sessions.

    Attributes:
        name (str): Database name (dict key in JSON file)
        path (str): File path where database is stored
        db (JsonStorage): Underlying storage

    Example:
        db = JsonDatabase("users", path="db.json")
        db.add_item({"id": 1, "name": "Alice"})
        db.add_item({"id": 2, "name": "Bob"})

        # Search and filter
        from json_database.search import Query
        query = Query(db).equal("name", "Alice")
        results = query.build()

        db.commit()  # Save to disk
    """

    def __init__(self,
                 name,
                 path=None,
                 disable_lock=False,
                 extension="json"):
        super().__init__()
        self.name = name
        self.path = path or f"{name}.{extension}"
        self.db = JsonStorage(self.path, disable_lock=disable_lock)
        self.db[name] = []
        self.db.load_local(self.path)

    # operator overloads
    def __enter__(self):
        """ Context handler """
        return self

    def __exit__(self, _type, value, traceback):
        """ Commits changes and Closes the session """
        try:
            self.commit()
        except Exception as e:
            LOG.error(e)
            raise SessionError

    def __repr__(self):
        return str(jsonify_recursively(self))

    def __len__(self):
        return len(self.db.get(self.name, []))

    def __getitem__(self, item):
        if not isinstance(item, int):
            try:
                item_id = int(item)
            except Exception as e:
                item_id = self.get_item_id(item)
                if item_id < 0:
                    raise InvalidItemID
        else:
            item_id = item
        if item_id >= len(self.db[self.name]):
            raise InvalidItemID
        return self.db[self.name][item_id]

    def __setitem__(self, item_id, value):
        if not isinstance(item_id, int) or item_id >= len(self) or item_id < 0:
            raise InvalidItemID
        else:
            self.update_item(item_id, value)

    def __iter__(self):
        for item in self.db[self.name]:
            if item is not None:
                yield item

    def __contains__(self, item):
        item = jsonify_recursively(item)
        return item in self.db[self.name]

    # database
    def commit(self):
        """
            store the json db locally.
        """
        self.db.store(self.path)

    def reset(self):
        self.db.reload()

    def print(self):
        pprint(jsonify_recursively(self))

    # item manipulations
    def append(self, value):
        value = jsonify_recursively(value)
        self.db[self.name].append(value)
        return len(self)

    def add_item(self, value, allow_duplicates=False):
        """ add an item to database
         if allow_duplicates is True, item is added unconditionally,
         else only if no exact match is present
         """
        if allow_duplicates or value not in self:
            self.append(value)
            return len(self)
        return self.get_item_id(value)

    def match_item(self, value, match_strategy=None):
        """ match value to some item in database
        returns a list of matched items
        """
        value = jsonify_recursively(value)
        matches = []
        for idx, item in enumerate(self.db[self.name]):
            if item is None:
                continue

            # TODO match strategy
            # - require exact match
            # - require list of keys to match
            # - require at least one of key list to match
            # - require at exactly one of key list to match

            # by default check for exact matches
            if item == value:
                matches.append((item, idx))

        return matches

    def merge_item(self, value, item_id=None, match_strategy=None,
                   merge_strategy=None):
        """ search an item according to match criteria, merge fields"""
        if item_id is None:
            matches = self.match_item(value, match_strategy)
            if not matches:
                raise MatchError
            match, item_id = matches[0]
        else:
            match = self[item_id]
        # TODO merge strategy
        # - only merge some keys
        # - dont merge some keys
        # - merge all keys
        # - dont overwrite keys
        value = jsonify_recursively(value)
        self[item_id] = merge_dict(match, value)

    def replace_item(self, value, item_id=None, match_strategy=None):
        """ search an item according to match criteria, replace it"""
        if item_id is None:
            matches = self.match_item(value, match_strategy)
            if not matches:
                raise MatchError
            match, item_id = matches[0]
        value = jsonify_recursively(value)
        self[item_id] = value

    # item_id
    def get_item_id(self, item):
        """Return the stable list index of item, or -1 if not found."""
        for match, idx in self.match_item(item):
            return idx
        return -1

    def update_item(self, item_id, new_item):
        """Replace the item at item_id with new_item (stable index)."""
        new_item = jsonify_recursively(new_item)
        self.db[self.name][item_id] = new_item

    def remove_item(self, item_id):
        """Mark item_id as revoked (None tombstone).

        The slot is retained so all subsequent item IDs remain stable.
        Revoked entries are invisible to iteration, search, and __contains__.
        """
        if item_id < 0 or item_id >= len(self.db[self.name]):
            raise InvalidItemID
        self.db[self.name][item_id] = None

    # search
    def search_by_key(self, key, fuzzy=False, thresh=0.7, include_empty=False):
        results = []
        for item in self:  # skips None tombstones
            if not isinstance(item, dict):
                continue
            if fuzzy:
                results += get_key_recursively_fuzzy(item, key, thresh, not include_empty)
            else:
                results += get_key_recursively(item, key, not include_empty)
        return results

    def search_by_value(self, key, value, fuzzy=False, thresh=0.7):
        results = []
        for item in self:  # skips None tombstones
            if not isinstance(item, dict):
                continue
            if fuzzy:
                results += get_value_recursively_fuzzy(item, key, value, thresh)
            else:
                results += get_value_recursively(item, key, value)
        return results


# XDG aware classes

class JsonStorageXDG(JsonStorage):
    """XDG-compliant persistent dictionary using system cache directory.

    Stores data in XDG_CACHE_HOME/json_database/ following Linux XDG spec.
    Useful for application cache and temporary data.

    Example:
        storage = JsonStorageXDG("cache")  # ~/.cache/json_database/cache.json
    """

    def __init__(self,
                 name,
                 xdg_folder=xdg_cache_home(),
                 disable_lock=False, subfolder="json_database",
                 extension="json"):
        self.name = name
        path = join(xdg_folder, subfolder, f"{name}.{extension}")
        super().__init__(path, disable_lock=disable_lock)


class EncryptedJsonStorageXDG(EncryptedJsonStorage):
    """ xdg respectful persistent dicts """

    def __init__(self,
                 encrypt_key: str,
                 name: str,
                 xdg_folder=xdg_data_home(),
                 disable_lock=False,
                 subfolder="json_database",
                 extension="ejson"):
        self.name = name
        path = join(xdg_folder, subfolder, f"{name}.{extension}")
        super().__init__(encrypt_key=encrypt_key, path=path,
                         disable_lock=disable_lock)


class JsonDatabaseXDG(JsonDatabase):
    """XDG-compliant searchable database using system data directory.

    Stores database in XDG_DATA_HOME/json_database/ following Linux XDG spec.
    Useful for application data that should persist across reboots.

    Example:
        db = JsonDatabaseXDG("users")  # ~/.local/share/json_database/users.jsondb
        db.add_item({"id": 1, "name": "Alice"})
        db.commit()
    """

    def __init__(self, name, xdg_folder=xdg_data_home(),
                 disable_lock=False, subfolder="json_database",
                 extension="jsondb"):
        path = join(xdg_folder, subfolder, f"{name}.{extension}")
        super().__init__(name, path, disable_lock=disable_lock, extension=extension)


class JsonConfigXDG(JsonStorageXDG):
    """XDG-compliant config storage using system config directory.

    Stores configuration in XDG_CONFIG_HOME/json_database/ following Linux XDG spec.
    Useful for application settings and preferences.

    Example:
        config = JsonConfigXDG("myapp")  # ~/.config/json_database/myapp.json
        config["theme"] = "dark"
        config.store()
    """

    def __init__(self, name, xdg_folder=xdg_config_home(),
                 disable_lock=False, subfolder="json_database",
                 extension="json"):
        super().__init__(name, xdg_folder, disable_lock, subfolder, extension)


if __name__ == "__main__":
    # quick test
    os.remove("/tmp/test.json")
    db = EncryptedJsonStorage("S" * 16, "/tmp/test.json")
    db["A"] = "42"
    print(db)  # {'A': '42'} - not encrypted in memory
    db.store()
    print(db)  # {'A': '42'} - still decrypted
    db.reload()
    print(db)  # {'A': '42'} - still decrypted
    db = EncryptedJsonStorage("S" * 16, "/tmp/test.json")
    print(db)  # {'A': '42'} - still not encrypted

    db = JsonStorage("/tmp/test.json")
    print(db)  # encrypted
    # {'ciphertext': 'ad0da72dc412d6b1240e478560354893d62caf',
    # 'tag': '3bc39dbfad7b0d7e50f3e652ee341819',
    # 'nonce': '3020ddafc9853e7686ee0368f9be6e25'}
