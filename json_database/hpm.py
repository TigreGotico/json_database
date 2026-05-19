import copy
import json
import os
from hivemind_plugin_manager.database import Client, AbstractDB, cast2client
from ovos_utils.log import LOG
from ovos_utils.xdg_utils import xdg_data_home
from typing import Union, Iterable, List, Optional
from json_database import JsonStorageXDG, EncryptedJsonStorageXDG
from dataclasses import dataclass


@dataclass
class JsonDB(AbstractDB):
    """HiveMind Database implementation using JSON files."""
    name: str = "clients"
    subfolder: str = "hivemind-core"
    password: Optional[str] = None

    def __post_init__(self):
        if self.password:
            self._db = EncryptedJsonStorageXDG(encrypt_key=self.password,
                                               name=self.name,
                                               subfolder=self.subfolder,
                                               xdg_folder=xdg_data_home())
        else:
            self._db = JsonStorageXDG(self.name,
                                      subfolder=self.subfolder,
                                      xdg_folder=xdg_data_home())
        LOG.debug(f"json database path: {self._db.path}")
        self._maybe_migrate()

    def _schema_version_path(self) -> str:
        """Sibling file next to the JSON store, kept out-of-band so the
        store's dict shape stays unchanged (keys are still client_ids).
        """
        return os.path.join(os.path.dirname(self._db.path),
                            f"{self.name}.schema_version")

    def _read_schema_version(self) -> int:
        path = self._schema_version_path()
        try:
            with open(path, "r", encoding="utf-8") as f:
                return int(f.read().strip() or "1")
        except (FileNotFoundError, ValueError, OSError):
            return 1

    def _write_schema_version(self, version: int) -> None:
        path = self._schema_version_path()
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(str(int(version)))
        except OSError as e:
            LOG.warning("JsonDB: failed to write schema_version sentinel: %s", e)

    def _maybe_migrate(self) -> None:
        """Run schema migration if the on-disk version is behind
        ``SCHEMA_VERSION``. Tolerates older HPM that predates the constant.
        """
        target = getattr(AbstractDB, "SCHEMA_VERSION", 1)
        stored = self._read_schema_version()
        if stored < target:
            LOG.info("JsonDB: migrating schema v%d -> v%d", stored, target)
            self.migrate(from_version=stored)
            self._write_schema_version(target)

    def migrate(self, from_version: int) -> None:
        """Migrate stored client records to the current ``SCHEMA_VERSION``.

        Idempotent and crash-safe: a partial migration re-run produces
        the same final state. A record with no legacy top-level keys is
        left untouched.

        v1 -> v2: fold each record's top-level ``intent_blacklist`` /
        ``skill_blacklist`` values into the record's ``metadata`` dict
        (``setdefault`` — explicit metadata values are never clobbered),
        then remove the legacy top-level keys. ``message_blacklist`` is
        **purged without carry-forward** — the field was a 2024-12-20
        design mistake that contradicted the deny-by-default whitelist
        model and was removed from the Client data model in HPM. Any
        residual ``metadata["message_blacklist"]`` from a prior
        migration run is also stripped. The store is committed once at
        the end.
        """
        if from_version >= 2:
            return
        legacy_keys = ("intent_blacklist", "skill_blacklist")
        changed_any = False
        for client_id, record in list(self._db.items()):
            if not isinstance(record, dict):
                continue
            metadata = record.get("metadata") if isinstance(
                record.get("metadata"), dict) else {}
            changed = False
            # Strip message_blacklist outright (top-level + metadata).
            if "message_blacklist" in record:
                record.pop("message_blacklist", None)
                changed = True
            if metadata.pop("message_blacklist", None) is not None:
                changed = True
            for lk in legacy_keys:
                if lk in record:
                    val = record.pop(lk)
                    changed = True
                    if val and lk not in metadata:
                        metadata[lk] = list(val) if isinstance(
                            val, (list, tuple)) else val
            if changed:
                record["metadata"] = metadata
                self._db[client_id] = record
                changed_any = True
        if changed_any:
            try:
                self._db.store()
            except Exception as e:
                LOG.error("JsonDB: failed to persist migration: %s", e)

    def sync(self):
        """update db from disk if needed"""
        self._db.reload()

    def add_item(self, client: Client) -> bool:
        """
        Add a client to the JSON database.

        Args:
            client: The client to be added.

        Returns:
            True if the addition was successful, False otherwise.
        """
        # Deep copy to break aliasing: dict(client.__dict__) is shallow, so
        # mutable fields (metadata dict, intent/skill/message/allowed lists)
        # would otherwise reference caller state and pick up later mutations
        # on the next commit. Snapshot once on insert.
        client_data = copy.deepcopy(client.__dict__)
        self._db[client.client_id] = client_data
        return True

    def search_by_value(self, key: str, val: Union[str, bool, int, float]) -> List[Client]:
        """
        Search for clients by a specific key-value pair in the JSON database.

        Args:
            key: The key to search by.
            val: The value to search for.

        Returns:
            A list of clients that match the search criteria.
        """
        res = []
        if key == "client_id":
            v = self._db.get(val)
            if v:
                res.append(cast2client(v))
        else:
            for client in self._db.values():
                v = client.get(key)
                if v == val:
                    res.append(cast2client(client))
        return res

    def __len__(self) -> int:
        """
        Get the number of clients in the database.

        Returns:
            The number of clients in the database.
        """
        return len(self._db)

    def __iter__(self) -> Iterable['Client']:
        """
        Iterate over all clients in the JSON database.

        Returns:
            An iterator over the clients in the database.
        """
        for item in self._db.values():
            yield cast2client(item)

    def commit(self) -> bool:
        """
        Commit changes to the JSON database.

        Returns:
            True if the commit was successful, False otherwise.
        """
        try:
            self._db.store()
            return True
        except Exception as e:
            LOG.error(f"Failed to save {self._db.path} - {e}")
            return False
