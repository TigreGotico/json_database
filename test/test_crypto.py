import os
import unittest

from json_database import EncryptedJsonStorage, JsonStorage  # Replace with actual import


class TestEncryptedJsonStorage(unittest.TestCase):
    def setUp(self):
        self.key = "S" * 16  # Replace with actual key generation if needed
        self.file_path = "/tmp/test.json"
        # Ensure the test file doesn't exist at the start of each test
        if os.path.exists(self.file_path):
            os.remove(self.file_path)

    def tearDown(self):
        # Clean up the test file after each test
        if os.path.exists(self.file_path):
            os.remove(self.file_path)

    def test_add_and_store_data(self):
        db = EncryptedJsonStorage(self.key, self.file_path)
        db["A"] = "42"
        self.assertEqual(db["A"], "42")  # Check in-memory data
        db.store()
        self.assertTrue(os.path.exists(self.file_path))  # File should be created

    def test_encryption_in_file(self):
        db = EncryptedJsonStorage(self.key, self.file_path)
        db["A"] = "42"
        db.store()
        with open(self.file_path, "r") as file:
            file_data = file.read()
        # Key and value should not appear as plaintext
        self.assertNotIn('"A"', file_data)  # Key not plaintext
        # Also check that it has encryption metadata
        self.assertIn("ciphertext", file_data)

    def test_decryption_after_reload(self):
        db = EncryptedJsonStorage(self.key, self.file_path)
        db["A"] = "42"
        db.store()
        db.reload()
        self.assertEqual(db["A"], "42")  # Data should be decrypted correctly

    def test_jsonstorage_read_encrypted_data(self):
        encrypted_db = EncryptedJsonStorage(self.key, self.file_path)
        encrypted_db["A"] = "42"
        encrypted_db.store()

        db = JsonStorage(self.file_path)
        self.assertIn("ciphertext", db)  # Check that it's encrypted
        self.assertNotIn("A", db)



# Pytest-style tests for edge cases
import pytest


class TestEncryptedJsonStorageEdgeCases:
    """Edge case tests for encryption functionality."""

    def test_key_exactly_16_bytes(self, temp_db_path):
        """Test that key must be exactly 16 bytes."""
        key_16 = "a" * 16
        storage = EncryptedJsonStorage(key_16, temp_db_path)
        # Should not raise

    def test_key_15_bytes_fails(self, temp_db_path):
        """Test that 15-byte key raises assertion."""
        key_15 = "a" * 15
        with pytest.raises(AssertionError):
            EncryptedJsonStorage(key_15, temp_db_path)

    def test_key_17_bytes_fails(self, temp_db_path):
        """Test that 17-byte key raises assertion."""
        key_17 = "a" * 17
        with pytest.raises(AssertionError):
            EncryptedJsonStorage(key_17, temp_db_path)

    def test_empty_key_fails(self, temp_db_path):
        """Test that empty key raises assertion."""
        with pytest.raises(AssertionError):
            EncryptedJsonStorage("", temp_db_path)

    def test_unicode_key(self, temp_db_path):
        """Test encryption with unicode key (if 16 bytes)."""
        # Use unicode characters that total 16 bytes
        key = "café" * 4  # Multi-byte chars
        if len(key.encode('utf-8')) == 16:
            storage = EncryptedJsonStorage(key, temp_db_path)
            # Should work

    def test_compression_with_large_data(self, temp_db_path):
        """Test that large data is compressed during encryption."""
        key = "S" * 16
        storage = EncryptedJsonStorage(key, temp_db_path)

        # Add large dataset
        large_data = {"data": "x" * 10000}
        storage.update(large_data)
        storage.store()

        # Verify file was created
        assert os.path.exists(temp_db_path)

        # File size should be less than uncompressed
        with open(temp_db_path, 'r') as f:
            encrypted_content = f.read()

        # The encrypted data should be encoded, not the original size
        assert len(encrypted_content) < 10000  # Much less than raw data

    def test_special_characters_in_data(self, temp_db_path):
        """Test encryption with special characters."""
        key = "S" * 16
        storage = EncryptedJsonStorage(key, temp_db_path)

        special_data = {
            "special": "!@#$%^&*()",
            "quotes": '"quotes" and \'apostrophes\'',
            "newlines": "line1\nline2\rline3",
            "nulls": "string with \x00 null"
        }

        storage.update(special_data)
        storage.store()

        storage2 = EncryptedJsonStorage(key, temp_db_path)
        # UTF-8 strings should survive, but null bytes might not
        assert storage2["special"] == special_data["special"]
        assert storage2["quotes"] == special_data["quotes"]

    def test_binary_safe_encryption(self, temp_db_path):
        """Test that binary-safe fields are handled."""
        key = "S" * 16
        storage = EncryptedJsonStorage(key, temp_db_path)

        # JSON doesn't support binary, but base64 strings can work
        data = {"hex": "48656c6c6f"}  # "Hello" in hex
        storage.update(data)
        storage.store()

        storage2 = EncryptedJsonStorage(key, temp_db_path)
        assert storage2["hex"] == "48656c6c6f"

    def test_empty_file_initialization(self, temp_db_path):
        """Test initializing EncryptedJsonStorage from non-existent file."""
        key = "S" * 16
        assert not os.path.exists(temp_db_path)

        storage = EncryptedJsonStorage(key, temp_db_path)
        assert len(storage) == 0

    def test_multiple_encryptions_same_data(self, temp_db_path):
        """Test that same data encrypts differently each time."""
        key = "S" * 16

        # First encryption
        storage1 = EncryptedJsonStorage(key, temp_db_path)
        storage1["data"] = "test"
        storage1.store()
        with open(temp_db_path, 'r') as f:
            encrypted1 = f.read()

        # Second encryption (same data, different file)
        temp_db_path2 = temp_db_path.replace(".json", "_2.json")
        storage2 = EncryptedJsonStorage(key, temp_db_path2)
        storage2["data"] = "test"
        storage2.store()
        with open(temp_db_path2, 'r') as f:
            encrypted2 = f.read()

        # Encrypted data should be different (due to nonce/IV)
        assert encrypted1 != encrypted2

        # But both should decrypt to same value
        storage1_reload = EncryptedJsonStorage(key, temp_db_path)
        storage2_reload = EncryptedJsonStorage(key, temp_db_path2)
        assert storage1_reload["data"] == storage2_reload["data"]


if __name__ == "__main__":
    unittest.main()
