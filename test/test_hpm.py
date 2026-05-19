import os

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


def test_add_item_snapshots_list_fields_against_caller_mutation(tmp_path, monkeypatch):
    """Same aliasing bug applied to all mutable list fields: caller mutation
    of intent_blacklist / skill_blacklist / message_blacklist / allowed_types
    after add_item must not leak into the stored record."""
    db = make_db(tmp_path, monkeypatch)
    intents = ["skill:a"]
    skills = ["skill:b"]
    messages = ["msg:c"]
    allowed = ["recognizer_loop:utterance", "speak:b64_audio"]
    client = Client(
        client_id=1, api_key="k", name="a",
        intent_blacklist=intents,
        skill_blacklist=skills,
        message_blacklist=messages,
        allowed_types=allowed,
    )
    db.add_item(client)

    # mutate the caller-side lists and the lists still on the client
    intents.append("skill:leaked")
    client.skill_blacklist.append("skill:leaked")
    messages.append("msg:leaked")
    client.allowed_types.append("speak:leaked")

    found = db.search_by_value("api_key", "k")
    # Skill/intent surface via property shims (read from metadata).
    # message_blacklist has no read-side shim — fetch via metadata.
    assert found[0].intent_blacklist == ["skill:a"]
    assert found[0].skill_blacklist == ["skill:b"]
    assert found[0].metadata.get("message_blacklist") == ["msg:c"]
    # allowed_types: __post_init__ guarantees "recognizer_loop:utterance" is
    # in the list, so verify the leaked entry isn't there.
    assert "speak:leaked" not in found[0].allowed_types


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


# ---------------------------------------------------------------------------
# v1 -> v2 schema migration (legacy blacklist fields -> metadata)
# ---------------------------------------------------------------------------


def _seed_v1_record(db, *, with_explicit_metadata=False):
    """Inject a v1-shape record (legacy keys at top level) bypassing
    Client.__init__ migration, then commit so it's on disk for reload."""
    record = {
        "client_id": 7,
        "api_key": "legacy-key",
        "name": "alpha",
        "intent_blacklist": ["i:1"],
        "skill_blacklist": ["s:1"],
        "message_blacklist": ["m:1"],
        "allowed_types": [],
        "metadata": {"owner": "u"},
    }
    if with_explicit_metadata:
        record["metadata"]["skill_blacklist"] = ["explicit"]
    db._db[7] = record
    db._db.store()


def test_migrate_folds_legacy_keys_into_metadata(tmp_path, monkeypatch):
    db = make_db(tmp_path, monkeypatch)
    _seed_v1_record(db)

    db.migrate(from_version=1)

    record = db._db[7]
    assert "intent_blacklist" not in record
    assert "skill_blacklist" not in record
    assert "message_blacklist" not in record
    assert record["metadata"]["owner"] == "u"
    assert record["metadata"]["intent_blacklist"] == ["i:1"]
    assert record["metadata"]["skill_blacklist"] == ["s:1"]
    assert record["metadata"]["message_blacklist"] == ["m:1"]


def test_migrate_setdefault_does_not_clobber_explicit_metadata(tmp_path, monkeypatch):
    db = make_db(tmp_path, monkeypatch)
    _seed_v1_record(db, with_explicit_metadata=True)

    db.migrate(from_version=1)

    assert db._db[7]["metadata"]["skill_blacklist"] == ["explicit"]


def test_migrate_is_idempotent(tmp_path, monkeypatch):
    db = make_db(tmp_path, monkeypatch)
    _seed_v1_record(db)
    db.migrate(from_version=1)
    snapshot = dict(db._db[7])
    db.migrate(from_version=1)  # second run is a no-op
    assert db._db[7] == snapshot


def test_migrate_skips_when_already_at_target(tmp_path, monkeypatch):
    db = make_db(tmp_path, monkeypatch)
    _seed_v1_record(db)
    db.migrate(from_version=2)
    assert "intent_blacklist" in db._db[7]


def test_maybe_migrate_writes_schema_version_sentinel(tmp_path, monkeypatch):
    db = make_db(tmp_path, monkeypatch)
    _seed_v1_record(db)
    db._maybe_migrate()
    assert db._read_schema_version() == 2
    # second call: no-op
    db._maybe_migrate()
    assert db._read_schema_version() == 2


def test_post_init_runs_migration_on_existing_db(tmp_path, monkeypatch):
    """End-to-end: a v1-shape DB on disk gets migrated automatically when
    JsonDB opens it. Simulates an existing operator DB."""
    # First open: seed a v1 record, do NOT bump schema_version sentinel.
    db1 = make_db(tmp_path, monkeypatch)
    _seed_v1_record(db1)
    # Roll back the sentinel that _maybe_migrate just wrote, then
    # rewrite the record to its v1 shape (the previous _maybe_migrate
    # call already migrated it).
    os.remove(db1._schema_version_path())
    _seed_v1_record(db1)

    # Re-open via a fresh JsonDB — should migrate.
    db2 = make_db(tmp_path, monkeypatch)
    assert db2._read_schema_version() == 2
    # On-disk JSON coerces int keys to strings; pick the only record.
    record = next(iter(db2._db.values()))
    assert "intent_blacklist" not in record
    assert record["metadata"]["intent_blacklist"] == ["i:1"]
