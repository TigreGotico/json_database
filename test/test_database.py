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
        """Test removing an item."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 1, "name": "First"})
        db.add_item({"id": 2, "name": "Second"})
        db.add_item({"id": 3, "name": "Third"})

        assert len(db) == 3
        db.remove_item(1)  # Remove "Second"

        assert len(db) == 2
        assert db[0]["id"] == 1
        assert db[1]["id"] == 3

    def test_remove_item_shifts_indices(self, temp_db_path):
        """Test that removing item shifts remaining indices (ephemeral ID warning)."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": 10, "name": "A"})
        db.add_item({"id": 20, "name": "B"})
        db.add_item({"id": 30, "name": "C"})

        # Get ID of item with name "C"
        c_id = db.get_item_id({"id": 30, "name": "C"})
        assert c_id == 2

        # Remove item "B"
        db.remove_item(1)

        # Now item "C" has shifted down to index 1
        c_new_id = db.get_item_id({"id": 30, "name": "C"})
        assert c_new_id == 1
        assert c_id != c_new_id  # IDs are NOT stable

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

    def test_item_id_ephemerality_warning(self, temp_db_path):
        """Test documentation of item_id ephemeral nature."""
        db = JsonDatabase("items", path=temp_db_path, disable_lock=True)
        db.add_item({"id": "A"})
        db.add_item({"id": "B"})
        db.add_item({"id": "C"})

        # Store IDs
        id_a = db.get_item_id({"id": "A"})
        id_b = db.get_item_id({"id": "B"})
        id_c = db.get_item_id({"id": "C"})

        assert id_a == 0
        assert id_b == 1
        assert id_c == 2

        # Remove middle item
        db.remove_item(1)

        # IDs shift - B no longer exists, C moved
        new_id_c = db.get_item_id({"id": "C"})
        assert new_id_c == 1  # Shifted from 2
        assert new_id_c != id_c  # NOT stable!
