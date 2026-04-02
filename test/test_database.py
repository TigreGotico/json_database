"""Unit tests for JsonDatabase class."""

import os
import pytest
from json_database import JsonDatabase
from json_database.exceptions import InvalidItemID, SessionError, MatchError


class TestJsonDatabase:
    """Test suite for JsonDatabase searchable persistent list."""

    def test_create_new_database(self, temp_db_path):
        """Test creating a new JsonDatabase."""
        db = JsonDatabase("users", path=temp_db_path, disable_lock=True)
        assert db.name == "users"
        assert len(db) == 0
        assert db.path == temp_db_path

    def test_add_single_item(self, temp_db_path):
        """Test adding a single item to database."""
        db = JsonDatabase("products", path=temp_db_path, disable_lock=True)
        result = db.add_item({"name": "Widget", "price": 9.99})

        assert len(db) == 1
        # add_item returns len(self) after adding
        assert result == 1
        assert db[0] == {"name": "Widget", "price": 9.99}

    def test_add_multiple_items(self, temp_db_path, sample_list_data):
        """Test adding multiple items."""
        db = JsonDatabase("records", path=temp_db_path, disable_lock=True)

        for item in sample_list_data:
            db.add_item(item)

        assert len(db) == len(sample_list_data)

    def test_add_item_with_duplicates_disabled(self, temp_db_path):
        """Test that add_item rejects duplicates by default."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)

        item = {"id": 1, "name": "Duplicate"}
        result1 = db.add_item(item)  # Returns len(self) = 1
        result2 = db.add_item(item)  # Returns get_item_id() = 0

        # add_item returns len() when adding new, get_item_id() when duplicate
        assert result1 == 1  # New item returns len
        assert result2 == 0  # Duplicate returns index
        assert len(db) == 1  # Only one item

    def test_add_item_with_duplicates_allowed(self, temp_db_path):
        """Test adding duplicate items when allowed."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)

        item = {"id": 1, "name": "Duplicate"}
        id1 = db.add_item(item, allow_duplicates=True)
        id2 = db.add_item(item, allow_duplicates=True)

        assert id1 != id2
        assert len(db) == 2

    def test_get_item_by_index(self, temp_db_path, sample_list_data):
        """Test retrieving items by index."""
        db = JsonDatabase("records", path=temp_db_path, disable_lock=True)
        for item in sample_list_data:
            db.add_item(item)

        assert db[0] == sample_list_data[0]
        assert db[1] == sample_list_data[1]
        assert db[2] == sample_list_data[2]

    def test_get_item_by_invalid_index(self, temp_db_path):
        """Test that accessing out-of-bounds index raises InvalidItemID."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1})

        with pytest.raises(InvalidItemID):
            _ = db[999]

    def test_update_item(self, temp_db_path):
        """Test updating an item by index."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "status": "active"})

        db[0] = {"id": 1, "status": "inactive"}

        assert db[0]["status"] == "inactive"

    def test_update_item_invalid_index(self, temp_db_path):
        """Test that updating invalid index raises InvalidItemID."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1})

        with pytest.raises(InvalidItemID):
            db[999] = {"id": 1, "new_data": "value"}

    def test_remove_item(self, temp_db_path):
        """Test removing an item leaves a tombstone and active count drops."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "First"})
        db.add_item({"id": 2, "name": "Second"})
        db.add_item({"id": 3, "name": "Third"})

        assert len(db) == 3
        db.remove_item(1)  # Revoke "Second" — slot becomes None tombstone

        assert len(db) == 2          # active items only
        assert db[0]["id"] == 1      # First unchanged
        assert db[2]["id"] == 3      # Third still at index 2 (stable)
        with pytest.raises(InvalidItemID):
            _ = db[1]                # tombstone slot raises InvalidItemID

    def test_remove_item_stable_indices(self, temp_db_path):
        """Test that removing an item does NOT shift remaining item IDs."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 10, "name": "A"})
        db.add_item({"id": 20, "name": "B"})
        db.add_item({"id": 30, "name": "C"})

        c_id = db.get_item_id({"id": 30, "name": "C"})
        assert c_id == 2

        # Remove item "B"
        db.remove_item(1)

        # C is still at index 2 — IDs are stable
        c_new_id = db.get_item_id({"id": 30, "name": "C"})
        assert c_new_id == 2
        assert c_new_id == c_id  # IDs ARE stable after tombstone removal

    def test_get_item_id(self, temp_db_path, sample_list_data):
        """Test getting item ID (index) for an item."""
        db = JsonDatabase("records", path=temp_db_path, disable_lock=True)
        for item in sample_list_data:
            db.add_item(item)

        # Find Alice
        alice_id = db.get_item_id(sample_list_data[0])
        assert alice_id == 0

        # Find Diana
        diana_id = db.get_item_id(sample_list_data[3])
        assert diana_id == 3

        # Non-existent item returns -1
        nonexistent_id = db.get_item_id({"id": 999, "name": "Unknown"})
        assert nonexistent_id == -1

    def test_iteration(self, temp_db_path, sample_list_data):
        """Test iterating over database items."""
        db = JsonDatabase("records", path=temp_db_path, disable_lock=True)
        for item in sample_list_data:
            db.add_item(item)

        items = list(db)
        assert len(items) == len(sample_list_data)
        assert items == sample_list_data

    def test_contains(self, temp_db_path, sample_list_data):
        """Test __contains__ (in operator)."""
        db = JsonDatabase("records", path=temp_db_path, disable_lock=True)
        db.add_item(sample_list_data[0])

        assert sample_list_data[0] in db
        assert sample_list_data[1] not in db

    def test_length(self, temp_db_path, sample_list_data):
        """Test __len__."""
        db = JsonDatabase("records", path=temp_db_path, disable_lock=True)

        assert len(db) == 0

        for item in sample_list_data:
            db.add_item(item)

        assert len(db) == len(sample_list_data)

    def test_repr(self, temp_db_path):
        """Test __repr__ for string representation."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Test"})

        repr_str = repr(db)
        assert isinstance(repr_str, str)
        assert "Test" in repr_str or "id" in repr_str

    def test_commit_and_persistence(self, temp_db_path):
        """Test that commit saves data to disk."""
        db1 = JsonDatabase("users", path=temp_db_path, disable_lock=True)
        db1.add_item({"id": 1, "name": "Alice"})
        db1.add_item({"id": 2, "name": "Bob"})
        db1.commit()

        # Create new instance and verify data persisted
        db2 = JsonDatabase("users", path=temp_db_path, disable_lock=True)
        assert len(db2) == 2
        assert db2[0]["name"] == "Alice"
        assert db2[1]["name"] == "Bob"

    def test_reset(self, temp_db_path):
        """Test reset reloads data from disk, discarding in-memory changes."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Original"})
        db.commit()

        # Modify in memory
        db.add_item({"id": 2, "name": "In-Memory"})
        assert len(db) == 2

        # Reset should reload from disk
        db.reset()
        assert len(db) == 1
        assert db[0]["name"] == "Original"

    def test_context_manager(self, temp_db_path):
        """Test database context manager commits on exit."""
        with JsonDatabase("items", path=temp_db_path, disable_lock=True) as db:
            db.add_item({"id": 1, "name": "Test"})

        # Verify file was created and data persisted
        assert os.path.exists(temp_db_path)

        db2 = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        assert len(db2) == 1

    def test_match_item_exact(self, temp_db_path):
        """Test match_item finds exact matches."""
        db = JsonDatabase("records", path=temp_db_path, disable_lock=True)
        item1 = {"id": 1, "name": "Alice", "status": "active"}
        item2 = {"id": 2, "name": "Bob", "status": "inactive"}

        db.add_item(item1)
        db.add_item(item2)

        matches = db.match_item(item1)
        assert len(matches) == 1
        assert matches[0][0] == item1
        assert matches[0][1] == 0

    def test_match_item_no_match(self, temp_db_path):
        """Test match_item returns empty when no match found."""
        db = JsonDatabase("records", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Alice"})

        matches = db.match_item({"id": 999, "name": "Unknown"})
        assert len(matches) == 0

    def test_replace_item(self, temp_db_path):
        """Test replace_item by item_id."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        original = {"id": 1, "name": "Original"}
        replacement = {"id": 1, "name": "Replaced"}

        db.add_item(original)
        db.replace_item(replacement, item_id=0)

        assert db[0] == replacement

    def test_replace_item_updates_entire_record(self, temp_db_path):
        """Test that replace_item replaces the entire record."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Alice", "age": 30})
        db.add_item({"id": 2, "name": "Bob", "age": 25})

        # Replace with new data at specific index
        new_item = {"id": 1, "name": "Alice Updated", "age": 31}
        db[0] = new_item
        assert db[0] == new_item

    def test_replace_item_no_match(self, temp_db_path):
        """Test replace_item raises MatchError when no match found."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Alice"})

        with pytest.raises(MatchError):
            db.replace_item({"id": 999, "name": "Unknown"})

    def test_merge_item(self, temp_db_path):
        """Test merge_item updates fields in an item."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        original = {"id": 1, "name": "Alice", "age": 30, "city": "NYC"}
        db.add_item(original)

        # Merge new data
        db.merge_item({"age": 31, "city": "LA"}, item_id=0)

        merged = db[0]
        assert merged["id"] == 1
        assert merged["name"] == "Alice"
        assert merged["age"] == 31
        assert merged["city"] == "LA"

    def test_search_by_key(self, temp_db_path):
        """Test search_by_key finds items with specific key."""
        db = JsonDatabase("records", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Alice", "role": "admin"})
        db.add_item({"id": 2, "name": "Bob"})  # No role
        db.add_item({"id": 3, "name": "Charlie", "role": "user"})

        matches = db.search_by_key("role")
        assert len(matches) >= 2  # At least Alice and Charlie

    def test_search_by_value(self, temp_db_path):
        """Test search_by_value finds items with specific key-value pair."""
        db = JsonDatabase("records", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "status": "active"})
        db.add_item({"id": 2, "status": "inactive"})
        db.add_item({"id": 3, "status": "active"})

        matches = db.search_by_value("status", "active")
        assert len(matches) >= 2  # At least items 1 and 3

    def test_print(self, temp_db_path, capsys):
        """Test print method outputs database contents."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Test"})

        db.print()
        # Just verify it doesn't crash; output is captured by capsys

    def test_append_vs_add_item(self, temp_db_path):
        """Test that append adds items unconditionally, unlike add_item."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)

        # append adds unconditionally
        id1 = db.append({"id": 1, "name": "Item"})
        id2 = db.append({"id": 1, "name": "Item"})  # Duplicate allowed

        assert id1 != id2
        assert len(db) == 2

    def test_empty_database(self, temp_db_path):
        """Test operations on empty database."""
        db = JsonDatabase("empty", path=temp_db_path, disable_lock=True)

        assert len(db) == 0
        assert list(db) == []

        matches = db.search_by_key("any_key")
        assert len(matches) == 0

    def test_database_with_nested_data(self, temp_db_path, nested_dict_data):
        """Test adding items with nested structures."""
        db = JsonDatabase("nested", path=temp_db_path, disable_lock=True)
        db.add_item(nested_dict_data)

        retrieved = db[0]
        assert retrieved["level1"]["level2"]["level3"]["value"] == "deep"

    def test_database_name_mismatch(self, temp_db_path):
        """Test loading database with same file but different name."""
        db1 = JsonDatabase("users", path=temp_db_path, disable_lock=True)
        db1.add_item({"id": 1, "name": "Alice"})
        db1.commit()

        # Create with different name - should have empty list
        db2 = JsonDatabase("products", path=temp_db_path, disable_lock=True)
        assert len(db2) == 0  # products list is empty
        assert "users" in db2.db  # But users data is loaded from file
        assert db2.db["users"] == [{"id": 1, "name": "Alice"}]

    def test_item_id_stable_after_removal(self, temp_db_path):
        """Test that item IDs are stable after removal (tombstone behaviour)."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": "A"})
        db.add_item({"id": "B"})
        db.add_item({"id": "C"})

        id_a = db.get_item_id({"id": "A"})
        id_b = db.get_item_id({"id": "B"})
        id_c = db.get_item_id({"id": "C"})

        assert id_a == 0
        assert id_b == 1
        assert id_c == 2

        # Remove middle item — slot becomes None, not popped
        db.remove_item(1)

        # C is still at index 2 — IDs are stable
        new_id_c = db.get_item_id({"id": "C"})
        assert new_id_c == 2        # unchanged
        assert new_id_c == id_c     # stable across removal

        # Revoked slot raises InvalidItemID
        with pytest.raises(InvalidItemID):
            _ = db[1]

        # Active count reflects live items only
        assert len(db) == 2


class TestJsonDatabaseErrorHandling:
    """Test error handling and edge cases in JsonDatabase."""

    def test_getitem_with_string_index(self, temp_db_path):
        """Test __getitem__ with string index that converts to int."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1})
        db.add_item({"id": 2})
        # String index that converts to int
        assert db["0"] == {"id": 1}
        assert db["1"] == {"id": 2}

    def test_getitem_with_invalid_int_index(self, temp_db_path):
        """Test __getitem__ raises InvalidItemID for out-of-bounds int."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1})
        with pytest.raises(InvalidItemID):
            _ = db[99]

    def test_getitem_with_dict_lookup(self, temp_db_path):
        """Test __getitem__ with dict lookup (get_item_id)."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Alice"})
        db.add_item({"id": 2, "name": "Bob"})
        # Lookup by exact item match
        item = db[{"id": 1, "name": "Alice"}]
        assert item == {"id": 1, "name": "Alice"}

    def test_getitem_with_missing_dict(self, temp_db_path):
        """Test __getitem__ raises InvalidItemID when dict not found."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1})
        with pytest.raises(InvalidItemID):
            _ = db[{"id": 999}]

    def test_setitem_invalid_index_negative(self, temp_db_path):
        """Test __setitem__ with negative index raises InvalidItemID."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1})
        with pytest.raises(InvalidItemID):
            db[-1] = {"id": 2}

    def test_setitem_out_of_bounds(self, temp_db_path):
        """Test __setitem__ with out-of-bounds index raises InvalidItemID."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1})
        with pytest.raises(InvalidItemID):
            db[10] = {"id": 2}

    def test_setitem_with_non_int(self, temp_db_path):
        """Test __setitem__ with non-int string raises InvalidItemID."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1})
        with pytest.raises(InvalidItemID):
            db["invalid"] = {"id": 2}

    def test_context_manager_exception_handling(self, tmp_path):
        """Test context manager raises SessionError on commit failure."""
        test_db = str(tmp_path / "test.json")
        db = JsonDatabase("test", path=test_db, disable_lock=True)
        # First create the db file
        db.add_item({"id": 1})
        db.commit()
        # Remove permissions to cause failure
        import os
        try:
            with pytest.raises(SessionError):
                os.chmod(test_db, 0o444)  # Read-only
                with db:
                    db.add_item({"id": 2})
        finally:
            os.chmod(test_db, 0o644)  # Restore

    def test_merge_item_with_explicit_match(self, temp_db_path):
        """Test merge_item with explicit item_id to avoid match logic."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Alice", "age": 25})

        # Using explicit item_id avoids the match_item logic
        new_value = {"id": 1, "name": "Alice", "age": 26}
        db.merge_item(new_value, item_id=0)

        # Verify merge happened
        item = db[0]
        assert item["age"] == 26
        assert item["name"] == "Alice"

    def test_merge_item_no_match_raises_matcherror(self, temp_db_path):
        """Test merge_item raises MatchError when no match found."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Alice"})

        with pytest.raises(MatchError):
            db.merge_item({"id": 999})

    def test_merge_item_with_explicit_item_id(self, temp_db_path):
        """Test merge_item with explicit item_id bypasses matching."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Alice", "age": 25})

        # Merge at index 0 regardless of field matching
        db.merge_item({"age": 30}, item_id=0)

        assert db[0]["age"] == 30
        assert db[0]["name"] == "Alice"

    def test_replace_item_no_match_raises_matcherror(self, temp_db_path):
        """Test replace_item raises MatchError when no match found."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Alice"})

        with pytest.raises(MatchError):
            db.replace_item({"id": 999})

    def test_replace_item_with_explicit_item_id(self, temp_db_path):
        """Test replace_item with explicit item_id."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "Alice"})

        db.replace_item({"id": 2, "name": "Bob"}, item_id=0)

        assert db[0] == {"id": 2, "name": "Bob"}

    def test_append_and_add_item_difference(self, temp_db_path):
        """Test difference between append (always adds) and add_item (checks duplicates)."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        item = {"id": 1}

        # append always adds
        db.append(item)
        assert len(db) == 1

        # add_item with duplicates=False returns existing index
        result = db.add_item(item)
        assert result == 0  # Returns index of existing
        assert len(db) == 1  # No new item added

    def test_get_item_id_not_found_returns_negative(self, temp_db_path):
        """Test get_item_id returns -1 when item not found."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1})

        item_id = db.get_item_id({"id": 999})
        assert item_id == -1

    def test_database_repr(self, temp_db_path):
        """Test __repr__ returns string representation."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "test"})

        repr_str = repr(db)
        assert isinstance(repr_str, str)
        assert "test" in repr_str or "1" in repr_str

    def test_database_iteration_with_objects(self, temp_db_path):
        """Test iteration through database items."""
        db = JsonDatabase("test", path=temp_db_path, disable_lock=True)
        items = [{"id": i} for i in range(3)]
        for item in items:
            db.add_item(item)

        # Iterate and verify
        iterated_items = list(db)
        assert len(iterated_items) == 3
        for i, item in enumerate(iterated_items):
            assert item["id"] == i

    def test_iter_skips_tombstones(self, temp_db_path):
        """__iter__ must not yield None tombstone slots."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"n": 0})
        db.add_item({"n": 1})
        db.add_item({"n": 2})
        db.remove_item(1)
        result = list(db)
        assert len(result) == 2
        assert {"n": 0} in result
        assert {"n": 2} in result
        assert None not in result

    def test_setitem(self, temp_db_path):
        """__setitem__ replaces an existing item by index."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"x": 1})
        db.add_item({"x": 2})
        db[0] = {"x": 99}
        assert db[0]["x"] == 99
        assert db[1]["x"] == 2

    def test_setitem_invalid(self, temp_db_path):
        """__setitem__ raises InvalidItemID for out-of-bounds or non-int index."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"x": 1})
        with pytest.raises(InvalidItemID):
            db[5] = {"x": 99}
        with pytest.raises(InvalidItemID):
            db[-1] = {"x": 99}

    def test_get_item_id_existing(self, temp_db_path):
        """get_item_id returns correct index for a known item."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"name": "alice"})
        db.add_item({"name": "bob"})
        assert db.get_item_id({"name": "alice"}) == 0
        assert db.get_item_id({"name": "bob"}) == 1
        assert db.get_item_id({"name": "unknown"}) == -1

    def test_update_item_replaces_slot(self, temp_db_path):
        """update_item replaces slot contents directly."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"v": 1})
        db.add_item({"v": 2})
        db.update_item(0, {"v": 100})
        assert db[0]["v"] == 100
        assert db[1]["v"] == 2

    def test_remove_item_out_of_bounds(self, temp_db_path):
        """remove_item raises InvalidItemID for out-of-range index."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"x": 1})
        with pytest.raises(InvalidItemID):
            db.remove_item(5)
        with pytest.raises(InvalidItemID):
            db.remove_item(-1)

    def test_search_by_key_returns_matching(self, temp_db_path):
        """search_by_key returns items containing the given key."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"name": "alice", "age": 30})
        db.add_item({"name": "bob"})
        db.add_item({"age": 25})
        results = db.search_by_key("name")
        assert len(results) == 2
        names = [r["name"] for r in results]
        assert "alice" in names
        assert "bob" in names

    def test_search_by_key_fuzzy(self, temp_db_path):
        """search_by_key with fuzzy=True matches approximate key names."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"username": "alice"})
        db.add_item({"age": 30})
        results = db.search_by_key("username", fuzzy=True, thresh=0.5)
        # fuzzy returns (dict, score) tuples
        assert any("username" in r[0] for r in results)

    def test_search_by_key_skips_tombstones(self, temp_db_path):
        """search_by_key does not return results from revoked slots."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"name": "alice"})
        db.add_item({"name": "bob"})
        db.remove_item(1)
        results = db.search_by_key("name")
        assert len(results) == 1
        assert results[0]["name"] == "alice"

    def test_search_by_value_returns_matching(self, temp_db_path):
        """search_by_value returns items where key == value."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"role": "admin", "name": "alice"})
        db.add_item({"role": "user", "name": "bob"})
        db.add_item({"role": "admin", "name": "carol"})
        results = db.search_by_value("role", "admin")
        assert len(results) == 2
        names = [r["name"] for r in results]
        assert "alice" in names
        assert "carol" in names

    def test_search_by_value_fuzzy(self, temp_db_path):
        """search_by_value with fuzzy=True matches approximate values."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"tag": "administrator"})
        db.add_item({"tag": "guest"})
        results = db.search_by_value("tag", "admin", fuzzy=True, thresh=0.5)
        assert len(results) >= 1

    def test_search_by_value_skips_tombstones(self, temp_db_path):
        """search_by_value ignores revoked slots."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"role": "admin", "name": "alice"})
        db.add_item({"role": "admin", "name": "bob"})
        db.remove_item(1)
        results = db.search_by_value("role", "admin")
        assert len(results) == 1
        assert results[0]["name"] == "alice"

    def test_search_by_key_skips_non_dict_items(self, temp_db_path):
        """search_by_key ignores non-dict items (string/int entries)."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.append("plain_string")         # non-dict — should be skipped
        db.add_item({"name": "alice"})
        results = db.search_by_key("name")
        assert len(results) == 1
        assert results[0]["name"] == "alice"

    def test_search_by_value_skips_non_dict_items(self, temp_db_path):
        """search_by_value ignores non-dict items."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.append(42)                     # non-dict — should be skipped
        db.add_item({"role": "admin"})
        results = db.search_by_value("role", "admin")
        assert len(results) == 1
