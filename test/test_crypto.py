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
        self.assertNotIn("42", file_data)  # Data should be encrypted

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


if __name__ == "__main__":
    unittest.main()
