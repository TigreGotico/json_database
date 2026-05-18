from hivemind_plugin_manager.database import Client

import json_database.hpm as hpm
from json_database.hpm import JsonDB


def make_db(tmp_path, monkeypatch) -> JsonDB:
    """Return an initialized JsonDB backed by a temp XDG data path."""
    monkeypatch.setattr(hpm, "xdg_data_home", lambda: str(tmp_path))
    return JsonDB()


def make_client(*, metadata=None, **kwargs) -> Client:
    """Build a Client with optional metadata."""
    client = Client(**kwargs)
    if metadata is not None:
        client.metadata = metadata
    return client


def test_hivemind_client_metadata_survives_search_round_trip(tmp_path, monkeypatch):
    """Client metadata survives add and search in JsonDB."""
    db = make_db(tmp_path, monkeypatch)
    client = make_client(
        client_id=1,
        api_key="alpha-key",
        name="alpha",
        metadata={"owner_id": "owner-123"},
    )

    assert db.add_item(client)
    found = db.search_by_value("api_key", "alpha-key")

    assert len(found) == 1
    assert found[0].metadata == {"owner_id": "owner-123"}


def test_hivemind_client_metadata_survives_iteration(tmp_path, monkeypatch):
    """Client metadata survives iteration in JsonDB."""
    db = make_db(tmp_path, monkeypatch)
    client = make_client(
        client_id=1,
        api_key="alpha-key",
        name="alpha",
        metadata={"owner_id": "owner-123"},
    )

    assert db.add_item(client)
    found = list(db)

    assert len(found) == 1
    assert found[0].metadata == {"owner_id": "owner-123"}


def test_hivemind_client_metadata_record_round_trips(tmp_path, monkeypatch):
    """Stored metadata round-trips through search_by_value."""
    db = make_db(tmp_path, monkeypatch)
    db._db[1] = {
        "client_id": 1,
        "api_key": "alpha-key",
        "name": "alpha",
        "metadata": {"owner_id": "owner-123"},
    }

    found = db.search_by_value("api_key", "alpha-key")

    assert len(found) == 1
    assert found[0].api_key == "alpha-key"
    assert found[0].metadata == {"owner_id": "owner-123"}
