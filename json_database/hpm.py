from hivemind_plugin_manager.database import Client, AbstractDB, cast2client
from ovos_utils.log import LOG
from ovos_utils.xdg_utils import xdg_data_home
from typing import Union, Iterable, List
from json_database import JsonStorageXDG


class JsonDB(AbstractDB):
    """HiveMind Database implementation using JSON files."""

    def __init__(self, name="clients", subfolder="hivemind-core"):
        self._db = JsonStorageXDG(name, subfolder=subfolder, xdg_folder=xdg_data_home())
        LOG.debug(f"json database path: {self._db.path}")

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
        self._db[client.client_id] = client.__dict__
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
            yield Client.deserialize(item)

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
