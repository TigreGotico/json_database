import pytest
from dataclasses import fields

from hivemind_plugin_manager.database import Client

from json_database.hpm import JsonDB


CLIENT_SUPPORTS_METADATA = any(field.name == "metadata" for field in fields(Client))
METADATA_SUPPORT_REQUIRED = "Client.metadata requires hivemind-plugin-manager metadata support"


def make_db() -> JsonDB:
    db = object.__new__(JsonDB)
    db._db = {}
    return db


def make_client(*, metadata=None, **kwargs) -> Client:
    client = Client(**kwargs)
    if metadata is not None:
        client.metadata = metadata
    return client


@pytest.mark.skipif(not CLIENT_SUPPORTS_METADATA, reason=METADATA_SUPPORT_REQUIRED)
def test_hivemind_client_metadata_survives_search_round_trip():
    db = make_db()
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


@pytest.mark.skipif(not CLIENT_SUPPORTS_METADATA, reason=METADATA_SUPPORT_REQUIRED)
def test_hivemind_client_metadata_survives_iteration():
    db = make_db()
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


def test_hivemind_client_metadata_record_does_not_break_old_client_model():
    db = make_db()
    db._db[1] = {
        "client_id": 1,
        "api_key": "alpha-key",
        "name": "alpha",
        "metadata": {"owner_id": "owner-123"},
    }

    found = db.search_by_value("api_key", "alpha-key")

    assert len(found) == 1
    assert found[0].api_key == "alpha-key"
    if CLIENT_SUPPORTS_METADATA:
        assert found[0].metadata == {"owner_id": "owner-123"}
    else:
        assert not hasattr(found[0], "metadata")
