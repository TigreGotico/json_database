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


def test_metadata_defaults_to_empty_when_missing(tmp_path, monkeypatch):
    """Clients added without a metadata dict get persisted with metadata={}."""
    db = make_db(tmp_path, monkeypatch)
    db.add_item(Client(client_id=1, api_key="k", name="a"))
    assert db._db[1]["metadata"] == {}
    found = db.search_by_value("api_key", "k")
    assert found[0].metadata == {}


def test_non_dict_metadata_coerced_to_empty_on_add(tmp_path, monkeypatch):
    """A non-dict metadata value on the Client must not corrupt storage."""
    db = make_db(tmp_path, monkeypatch)
    client = Client(client_id=1, api_key="k", name="a")
    client.metadata = "not a dict"  # bypasses __post_init__
    db.add_item(client)
    assert db._db[1]["metadata"] == {}


def test_search_by_client_id_returns_metadata(tmp_path, monkeypatch):
    """The client_id search path also preserves metadata."""
    db = make_db(tmp_path, monkeypatch)
    db.add_item(make_client(client_id=1, api_key="k", name="a",
                            metadata={"tier": "gold"}))
    found = db.search_by_value("client_id", 1)
    assert len(found) == 1
    assert found[0].metadata == {"tier": "gold"}


def test_nested_and_non_ascii_metadata_round_trip(tmp_path, monkeypatch):
    """Nested structures and non-ASCII characters survive add → iterate."""
    db = make_db(tmp_path, monkeypatch)
    meta = {
        "owner": {"id": "owner-1", "tags": ["a", "b"]},
        "name": "Zé Ninguém",
        "emoji": "🚀",
    }
    db.add_item(make_client(client_id=1, api_key="k", name="a", metadata=meta))
    found = list(db)
    assert found[0].metadata == meta


def test_metadata_survives_commit_and_reload(tmp_path, monkeypatch):
    """add_item → commit → new JsonDB pointed at the same path reads metadata back."""
    db = make_db(tmp_path, monkeypatch)
    db.add_item(make_client(client_id=1, api_key="k", name="a",
                            metadata={"owner": "owner-1"}))
    assert db.commit()

    # Fresh JsonDB instance against the same xdg_data_home path
    fresh = make_db(tmp_path, monkeypatch)
    found = fresh.search_by_value("api_key", "k")
    assert len(found) == 1
    assert found[0].metadata == {"owner": "owner-1"}


def test_add_item_snapshots_metadata_against_caller_mutation(tmp_path, monkeypatch):
    """Caller mutations to client.metadata after add_item must not leak into
    the stored record — including mutations of nested dicts."""
    db = make_db(tmp_path, monkeypatch)
    meta = {"v": "original", "nested": {"k": "n_original"}}
    client = make_client(client_id=1, api_key="k", name="a", metadata=meta)
    db.add_item(client)

    meta["v"] = "mutated"
    meta["nested"]["k"] = "n_mutated"
    client.metadata["added"] = "later"

    found = db.search_by_value("api_key", "k")
    assert found[0].metadata == {"v": "original", "nested": {"k": "n_original"}}


def test_add_item_overwrites_metadata_for_same_client_id(tmp_path, monkeypatch):
    """Re-adding a client with the same client_id replaces stored metadata."""
    db = make_db(tmp_path, monkeypatch)
    db.add_item(make_client(client_id=1, api_key="k", name="a",
                            metadata={"v": "old"}))
    db.add_item(make_client(client_id=1, api_key="k", name="a",
                            metadata={"v": "new", "extra": "x"}))
    found = db.search_by_value("api_key", "k")
    assert len(found) == 1
    assert found[0].metadata == {"v": "new", "extra": "x"}
