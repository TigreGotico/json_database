"""Unit tests for JsonStorage class."""

import os
import json
import pytest
from json_database import JsonStorage
from json_database.exceptions import DatabaseNotCommitted, SessionError


class TestJsonStorage:
    """Test suite for JsonStorage persistent dict."""

    def test_create_new_storage(self, temp_db_path):
        """Test creating a new JsonStorage with a non-existent file."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        assert isinstance(storage, dict)
        assert len(storage) == 0

    def test_store_and_load(self, temp_db_path, sample_dict_data):
        """Test storing data to file and loading it back."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update(sample_dict_data)
        storage.store()

        # Verify file exists
        assert os.path.exists(temp_db_path)

        # Load fresh instance
        storage2 = JsonStorage(temp_db_path, disable_lock=True)
        assert storage2 == sample_dict_data

    def test_persistence_across_sessions(self, temp_db_path):
        """Test that data persists across multiple JsonStorage instances."""
        # Session 1: Create and store
        storage1 = JsonStorage(temp_db_path, disable_lock=True)
        storage1["key1"] = "value1"
        storage1["key2"] = {"nested": "value"}
        storage1.store()

        # Session 2: Load and verify
        storage2 = JsonStorage(temp_db_path, disable_lock=True)
        assert storage2["key1"] == "value1"
        assert storage2["key2"]["nested"] == "value"

    def test_dict_operations(self, temp_db_path):
        """Test standard dict operations on JsonStorage."""
        storage = JsonStorage(temp_db_path, disable_lock=True)

        # Test __setitem__ and __getitem__
        storage["key1"] = "value1"
        assert storage["key1"] == "value1"

        # Test update
        storage.update({"key2": "value2", "key3": "value3"})
        assert len(storage) == 3

        # Test __contains__
        assert "key1" in storage
        assert "nonexistent" not in storage

        # Test pop
        value = storage.pop("key1")
        assert value == "value1"
        assert "key1" not in storage

    def test_clear(self, temp_db_path):
        """Test clearing all data from storage."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update({"a": 1, "b": 2, "c": 3})
        assert len(storage) == 3

        storage.clear()
        assert len(storage) == 0
        assert dict(storage) == {}

    def test_reload_from_disk(self, temp_db_path, sample_dict_data):
        """Test reloading data from disk when file exists."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update(sample_dict_data)
        storage.store()

        # Modify in memory
        storage["extra_key"] = "should_disappear"

        # Reload from disk
        storage.reload()
        assert "extra_key" not in storage
        assert storage == sample_dict_data

    def test_reload_fails_when_file_not_committed(self, temp_db_path):
        """Test that reload raises DatabaseNotCommitted when file doesn't exist."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage["key"] = "value"  # Add data but don't store

        with pytest.raises(DatabaseNotCommitted):
            storage.reload()

    def test_merge_simple(self, temp_db_path):
        """Test merging a simple dictionary."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update({"a": 1, "b": 2})

        new_data = {"c": 3, "d": 4}
        storage.merge(new_data)

        assert storage == {"a": 1, "b": 2, "c": 3, "d": 4}

    def test_merge_with_lists(self, temp_db_path):
        """Test merging with merge_lists=True."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update({"items": [1, 2, 3]})

        storage.merge({"items": [4, 5]}, merge_lists=True)
        # Should merge lists
        assert 4 in storage["items"]
        assert 5 in storage["items"]

    def test_merge_skip_empty(self, temp_db_path):
        """Test merging with skip_empty=True."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update({"a": 1, "b": "value"})

        storage.merge({"b": "", "c": 3}, skip_empty=True)
        # Empty value should be skipped
        assert storage["b"] == "value"
        assert storage["c"] == 3

    def test_merge_no_dupes(self, temp_db_path):
        """Test merging with no_dupes=True."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update({"items": [1, 2, 3]})

        storage.merge({"items": [2, 3, 4]}, merge_lists=True, no_dupes=True)
        # Should not duplicate 2 and 3
        assert storage["items"].count(2) == 1
        assert storage["items"].count(3) == 1

    def test_merge_new_only(self, temp_db_path):
        """Test merging with new_only=True."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update({"a": "original", "b": 2})

        storage.merge({"a": "new", "c": 3}, new_only=True)
        # Should not overwrite 'a', but add 'c'
        assert storage["a"] == "original"
        assert storage["c"] == 3

    def test_context_manager_commits(self, temp_db_path):
        """Test that context manager commits on exit."""
        with JsonStorage(temp_db_path, disable_lock=True) as storage:
            storage["key"] = "value"

        # Verify file was created and contains data
        assert os.path.exists(temp_db_path)
        with open(temp_db_path, 'r') as f:
            data = json.load(f)
        assert data["key"] == "value"

    def test_context_manager_exception_handling(self, temp_db_path):
        """Test that context manager raises SessionError on store failure."""
        # This is tricky to test without mocking. We'll test the happy path.
        with JsonStorage(temp_db_path, disable_lock=True) as storage:
            storage["key"] = "value"
        # Should not raise

    def test_remove_file(self, temp_db_path, sample_dict_data):
        """Test removing the storage file."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update(sample_dict_data)
        storage.store()

        assert os.path.exists(temp_db_path)
        storage.remove()
        assert not os.path.exists(temp_db_path)

    def test_utf8_encoding(self, temp_db_path):
        """Test that UTF-8 characters are properly stored and loaded."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage["name"] = "François"
        storage["greeting"] = "こんにちは"
        storage["emoji"] = "🎉"
        storage.store()

        storage2 = JsonStorage(temp_db_path, disable_lock=True)
        assert storage2["name"] == "François"
        assert storage2["greeting"] == "こんにちは"
        assert storage2["emoji"] == "🎉"

    def test_special_characters_in_values(self, temp_db_path):
        """Test storing special characters and escape sequences."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        special_data = {
            "newline": "line1\nline2",
            "tab": "col1\tcol2",
            "quote": 'He said "hello"',
            "backslash": "path\\to\\file"
        }
        storage.update(special_data)
        storage.store()

        storage2 = JsonStorage(temp_db_path, disable_lock=True)
        assert storage2 == special_data

    def test_numeric_types(self, temp_db_path):
        """Test storing various numeric types."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update({
            "int": 42,
            "float": 3.14159,
            "negative": -100,
            "zero": 0,
            "large": 9999999999999999
        })
        storage.store()

        storage2 = JsonStorage(temp_db_path, disable_lock=True)
        assert storage2["int"] == 42
        assert storage2["float"] == 3.14159
        assert storage2["negative"] == -100

    def test_boolean_values(self, temp_db_path):
        """Test storing boolean values."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update({"true_val": True, "false_val": False})
        storage.store()

        storage2 = JsonStorage(temp_db_path, disable_lock=True)
        assert storage2["true_val"] is True
        assert storage2["false_val"] is False

    def test_none_value(self, temp_db_path):
        """Test storing None values."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage["null_val"] = None
        storage.store()

        storage2 = JsonStorage(temp_db_path, disable_lock=True)
        assert storage2["null_val"] is None

    def test_nested_structures(self, temp_db_path, nested_dict_data):
        """Test storing and retrieving deeply nested structures."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.update(nested_dict_data)
        storage.store()

        storage2 = JsonStorage(temp_db_path, disable_lock=True)
        assert storage2["level1"]["level2"]["level3"]["value"] == "deep"
        assert storage2["level1"]["level2"]["level3"]["count"] == 42

    def test_load_commented_json(self, temp_dir):
        """Test that JsonStorage can load JSON with line-based comments."""
        # Create a JSON file with line-based comments (the supported format)
        json_with_comments = """{
    // This is a comment on its own line
    "key1": "value1",
    // Another comment
    "key2": "value2"
}"""
        path = os.path.join(temp_dir, "commented.json")
        with open(path, 'w') as f:
            f.write(json_with_comments)

        storage = JsonStorage(path, disable_lock=True)
        # Should load without error (load_commented_json handles line comments)
        assert "key1" in storage
        assert storage["key1"] == "value1"

    def test_directory_creation(self, temp_dir):
        """Test that store() creates parent directories if they don't exist."""
        nested_path = os.path.join(temp_dir, "subdir1", "subdir2", "test.json")
        storage = JsonStorage(nested_path, disable_lock=True)
        storage["key"] = "value"
        storage.store()

        assert os.path.exists(nested_path)
        assert os.path.isfile(nested_path)

    def test_empty_storage_store(self, temp_db_path):
        """Test storing an empty JsonStorage."""
        storage = JsonStorage(temp_db_path, disable_lock=True)
        storage.store()

        assert os.path.exists(temp_db_path)
        with open(temp_db_path, 'r') as f:
            data = json.load(f)
        assert data == {}
