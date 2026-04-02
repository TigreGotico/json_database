"""Unit tests for EncryptedJsonStorage class."""

import os
import json
import pytest
from json_database import EncryptedJsonStorage, JsonStorage
from json_database.exceptions import DatabaseNotCommitted, SessionError


class TestEncryptedJsonStorage:
    """Test suite for EncryptedJsonStorage encrypted persistent dict."""

    def test_create_with_valid_key(self, temp_db_path, encryption_key):
        """Test creating EncryptedJsonStorage with valid 16-byte key."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        assert isinstance(storage, dict)
        assert storage.encrypt_key == encryption_key

    def test_create_with_invalid_key_length(self, temp_db_path):
        """Test that EncryptedJsonStorage rejects invalid key lengths."""
        # Key must be exactly 16 bytes
        with pytest.raises(AssertionError):
            EncryptedJsonStorage("short_key", temp_db_path, disable_lock=True)

        with pytest.raises(AssertionError):
            EncryptedJsonStorage("this_key_is_way_too_long_for_aes", temp_db_path, disable_lock=True)

    def test_store_encrypts_data(self, temp_db_path, encryption_key):
        """Test that data is actually encrypted when stored."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        storage["secret"] = "confidential_value"
        storage.store()

        # Read raw file content
        with open(temp_db_path, 'r') as f:
            file_content = f.read()

        # Data should NOT be readable as plaintext
        assert "confidential_value" not in file_content
        assert "secret" not in file_content
        # But encryption metadata should be present
        assert "ciphertext" in file_content or "tag" in file_content

    def test_load_and_decrypt(self, temp_db_path, encryption_key):
        """Test that encrypted data is decrypted on load."""
        # Create and encrypt
        storage1 = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        storage1["username"] = "alice"
        storage1["password"] = "secret123"
        storage1.store()

        # Load and decrypt
        storage2 = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        assert storage2["username"] == "alice"
        assert storage2["password"] == "secret123"

    def test_data_remains_decrypted_in_memory(self, temp_db_path, encryption_key):
        """Test that data is decrypted in memory (not encrypted at rest in memory)."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        storage["key"] = "value"
        storage.store()

        # Data should be readable in memory after store
        assert storage["key"] == "value"

        # Reload and verify data is still readable
        storage.reload()
        assert storage["key"] == "value"

    def test_encryption_decryption_roundtrip(self, temp_db_path, encryption_key):
        """Test multiple encrypt/decrypt cycles."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)

        test_data = {
            "string": "test_value",
            "number": 42,
            "nested": {"deep": "value"},
            "list": [1, 2, 3]
        }

        storage.update(test_data)
        storage.store()

        # Create new instance and load
        storage2 = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        assert storage2 == test_data

        # Modify and store again
        storage2["string"] = "modified_value"
        storage2.store()

        # Load again
        storage3 = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        assert storage3["string"] == "modified_value"

    def test_wrong_key_fails_decryption(self, temp_db_path, encryption_key):
        """Test that decryption fails with wrong key."""
        # Store with one key
        storage1 = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        storage1["secret"] = "value"
        storage1.store()

        # Try to load with different key
        wrong_key = "D" * 16

        # Creating EncryptedJsonStorage with wrong key and loading triggers decryption
        # which will fail because the MAC tag won't match
        with pytest.raises(ValueError):
            storage2 = EncryptedJsonStorage(wrong_key, temp_db_path, disable_lock=True)

    def test_context_manager_encrypts_and_stores(self, temp_db_path, encryption_key):
        """Test that context manager stores encrypted data on exit."""
        with EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True) as storage:
            storage["key"] = "encrypted_value"

        # File should exist and contain encrypted data
        assert os.path.exists(temp_db_path)
        with open(temp_db_path, 'r') as f:
            content = f.read()
        assert "encrypted_value" not in content

    def test_merge_with_encryption(self, temp_db_path, encryption_key):
        """Test merging data in EncryptedJsonStorage."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        storage.update({"a": 1, "b": 2})
        storage.merge({"c": 3, "d": 4})

        assert storage == {"a": 1, "b": 2, "c": 3, "d": 4}

        storage.store()
        storage.reload()
        assert storage == {"a": 1, "b": 2, "c": 3, "d": 4}

    def test_encryption_with_special_characters(self, temp_db_path, encryption_key):
        """Test encrypting data with special characters and unicode."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        storage.update({
            "french": "François",
            "japanese": "こんにちは",
            "emoji": "🚀💻",
            "special": "line1\nline2\ttab"
        })
        storage.store()

        storage2 = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        assert storage2["french"] == "François"
        assert storage2["japanese"] == "こんにちは"
        assert storage2["emoji"] == "🚀💻"

    def test_encryption_with_large_data(self, temp_db_path, encryption_key):
        """Test encrypting reasonably large amounts of data."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)

        # Create a large dataset
        large_data = {
            f"key_{i}": f"value_{i}" * 10
            for i in range(100)
        }
        storage.update(large_data)
        storage.store()

        storage2 = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        assert len(storage2) == 100
        assert storage2["key_50"] == "value_50" * 10

    def test_empty_encrypted_storage(self, temp_db_path, encryption_key):
        """Test storing an empty EncryptedJsonStorage."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        storage.store()

        # Reload empty storage
        storage2 = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        assert len(storage2) == 0

    def test_reload_encrypted_data(self, temp_db_path, encryption_key):
        """Test reloading encrypted data from disk."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        storage.update({"a": 1, "b": 2})
        storage.store()

        # Modify in memory
        storage["c"] = 3

        # Reload discards changes
        storage.reload()
        assert "c" not in storage
        assert storage == {"a": 1, "b": 2}

    def test_encryption_preserves_types(self, temp_db_path, encryption_key):
        """Test that encryption preserves JSON types."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        storage.update({
            "int": 42,
            "float": 3.14,
            "bool": True,
            "null": None,
            "list": [1, 2, 3],
            "dict": {"nested": "value"}
        })
        storage.store()

        storage2 = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        assert storage2["int"] == 42
        assert storage2["float"] == 3.14
        assert storage2["bool"] is True
        assert storage2["null"] is None
        assert storage2["list"] == [1, 2, 3]
        assert storage2["dict"]["nested"] == "value"

    def test_jsonstorage_reads_encrypted_file_as_ciphertext(self, temp_db_path, encryption_key):
        """Test that JsonStorage reads encrypted file as ciphertext (doesn't decrypt)."""
        # Create encrypted data
        encrypted_storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        encrypted_storage["data"] = "secret"
        encrypted_storage.store()

        # Read with plain JsonStorage (no decryption)
        plain_storage = JsonStorage(temp_db_path, disable_lock=True)

        # Should see encryption metadata, not plaintext
        assert "ciphertext" in plain_storage or "tag" in plain_storage
        assert "data" not in plain_storage
        assert "secret" not in plain_storage

    def test_dict_operations_on_encrypted_storage(self, temp_db_path, encryption_key):
        """Test standard dict operations work on EncryptedJsonStorage."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)

        # Test setitem/getitem
        storage["key1"] = "value1"
        assert storage["key1"] == "value1"

        # Test pop
        value = storage.pop("key1")
        assert value == "value1"
        assert "key1" not in storage

        # Test update
        storage.update({"a": 1, "b": 2})
        assert len(storage) == 2

        storage.store()
        storage.reload()
        assert len(storage) == 2

    def test_remove_encrypted_file(self, temp_db_path, encryption_key):
        """Test removing an encrypted storage file."""
        storage = EncryptedJsonStorage(encryption_key, temp_db_path, disable_lock=True)
        storage["data"] = "value"
        storage.store()

        assert os.path.exists(temp_db_path)
        storage.remove()
        assert not os.path.exists(temp_db_path)
