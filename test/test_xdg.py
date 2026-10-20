"""Unit tests for XDG-aware storage classes."""

import os
import pytest
from pathlib import Path
from json_database import (
    JsonStorageXDG, EncryptedJsonStorageXDG, JsonDatabaseXDG, JsonConfigXDG
)


class TestJsonStorageXDG:
    """Test XDG-aware JsonStorage."""

    def test_create_with_default_xdg_path(self):
        """Test creating JsonStorageXDG with default XDG cache home."""
        storage = JsonStorageXDG("test_config", disable_lock=True)
        # Should create in XDG_CACHE_HOME/json_database/
        assert storage.name == "test_config"
        assert "json_database" in storage.path

    def test_custom_xdg_folder(self, temp_dir):
        """Test creating with custom XDG folder."""
        storage = JsonStorageXDG("test", xdg_folder=temp_dir, disable_lock=True)
        # Path should use custom folder
        assert temp_dir in storage.path

    def test_custom_subfolder(self, temp_dir):
        """Test custom subfolder parameter."""
        storage = JsonStorageXDG("test", xdg_folder=temp_dir,
                                subfolder="custom_db", disable_lock=True)
        assert "custom_db" in storage.path

    def test_custom_extension(self, temp_dir):
        """Test custom file extension."""
        storage = JsonStorageXDG("test", xdg_folder=temp_dir,
                                extension="conf", disable_lock=True)
        assert storage.path.endswith(".conf")

    def test_persistence_with_xdg_path(self, temp_dir):
        """Test that data persists using XDG paths."""
        storage1 = JsonStorageXDG("persist_test", xdg_folder=temp_dir,
                                 disable_lock=True)
        storage1["key"] = "value"
        storage1.store()

        # Create new instance with same name and folder
        storage2 = JsonStorageXDG("persist_test", xdg_folder=temp_dir,
                                 disable_lock=True)
        assert storage2["key"] == "value"


class TestEncryptedJsonStorageXDG:
    """Test XDG-aware encrypted storage."""

    def test_create_with_default_xdg_path(self, encryption_key):
        """Test creating with default XDG data home."""
        storage = EncryptedJsonStorageXDG(encryption_key, "secret",
                                        disable_lock=True)
        assert storage.name == "secret"
        assert "json_database" in storage.path

    def test_custom_xdg_folder(self, temp_dir, encryption_key):
        """Test with custom XDG folder."""
        storage = EncryptedJsonStorageXDG(encryption_key, "secret",
                                         xdg_folder=temp_dir, disable_lock=True)
        assert temp_dir in storage.path

    def test_encryption_with_xdg_path(self, temp_dir, encryption_key):
        """Test encryption works with XDG paths."""
        storage = EncryptedJsonStorageXDG(encryption_key, "test",
                                        xdg_folder=temp_dir, disable_lock=True)
        storage["secret"] = "confidential"
        storage.store()

        # Verify file exists and is encrypted
        assert os.path.exists(storage.path)

        # Load with correct key
        storage2 = EncryptedJsonStorageXDG(encryption_key, "test",
                                         xdg_folder=temp_dir, disable_lock=True)
        assert storage2["secret"] == "confidential"

    def test_custom_extension_for_encrypted(self, temp_dir, encryption_key):
        """Test custom extension for encrypted storage."""
        storage = EncryptedJsonStorageXDG(encryption_key, "test",
                                         xdg_folder=temp_dir,
                                         extension="ejson", disable_lock=True)
        assert storage.path.endswith(".ejson")


class TestJsonDatabaseXDG:
    """Test XDG-aware JsonDatabase."""

    def test_create_with_default_xdg(self):
        """Test creating JsonDatabaseXDG with defaults."""
        db = JsonDatabaseXDG("users", disable_lock=True)
        assert db.name == "users"
        assert "json_database" in db.path

    def test_custom_xdg_folder(self, temp_dir):
        """Test with custom XDG folder."""
        db = JsonDatabaseXDG("products", xdg_folder=temp_dir, disable_lock=True)
        assert temp_dir in db.path

    def test_database_operations_with_xdg(self, temp_dir):
        """Test CRUD operations work with XDG paths."""
        db = JsonDatabaseXDG("items", xdg_folder=temp_dir, disable_lock=True)

        db.add_item({"id": 1, "name": "Item1"})
        db.add_item({"id": 2, "name": "Item2"})
        db.commit()

        # Create new instance
        db2 = JsonDatabaseXDG("items", xdg_folder=temp_dir, disable_lock=True)
        assert len(db2) == 2
        assert db2[0]["name"] == "Item1"

    def test_custom_extension_for_db(self, temp_dir):
        """Test custom extension for database."""
        db = JsonDatabaseXDG("data", xdg_folder=temp_dir,
                            extension="db", disable_lock=True)
        assert db.path.endswith(".db")

    def test_directory_structure_created(self, temp_dir):
        """Test that XDG directory structure is created."""
        db = JsonDatabaseXDG("test", xdg_folder=temp_dir, disable_lock=True)
        db.add_item({"id": 1})
        db.commit()

        # Directory should exist
        db_dir = os.path.join(temp_dir, "json_database")
        assert os.path.isdir(db_dir)


class TestJsonConfigXDG:
    """Test XDG-aware config storage."""

    def test_create_with_default_xdg_config(self):
        """Test creating JsonConfigXDG with default XDG config home."""
        config = JsonConfigXDG("app_config", disable_lock=True)
        assert config.name == "app_config"
        assert "json_database" in config.path

    def test_custom_config_folder(self, temp_dir):
        """Test with custom config folder."""
        config = JsonConfigXDG("settings", xdg_folder=temp_dir, disable_lock=True)
        assert temp_dir in config.path

    def test_config_storage_and_loading(self, temp_dir):
        """Test storing and loading config."""
        config1 = JsonConfigXDG("myapp", xdg_folder=temp_dir, disable_lock=True)
        config1["theme"] = "dark"
        config1["language"] = "en"
        config1.store()

        config2 = JsonConfigXDG("myapp", xdg_folder=temp_dir, disable_lock=True)
        assert config2["theme"] == "dark"
        assert config2["language"] == "en"

    def test_config_merge(self, temp_dir):
        """Test merging config values."""
        config = JsonConfigXDG("test", xdg_folder=temp_dir, disable_lock=True)
        config["database"] = {"host": "localhost", "port": 5432}
        config.store()

        # Merge new config
        config.merge({"database": {"user": "admin"}})
        config.store()

        # Load and verify
        config2 = JsonConfigXDG("test", xdg_folder=temp_dir, disable_lock=True)
        assert config2["database"]["host"] == "localhost"
        assert config2["database"]["user"] == "admin"


class TestXDGPathResolution:
    """Test XDG path resolution and consistency."""

    def test_same_name_different_classes(self, temp_dir):
        """Test that different XDG classes use correct folders."""
        # JsonStorageXDG uses XDG_CACHE_HOME
        storage = JsonStorageXDG("same_name", xdg_folder=temp_dir,
                               disable_lock=True)

        # JsonDatabaseXDG also uses XDG_DATA_HOME
        db = JsonDatabaseXDG("same_name", xdg_folder=temp_dir,
                            disable_lock=True)

        # Paths should be different (cache vs data)
        assert storage.path != db.path

    def test_subfolder_in_path(self, temp_dir):
        """Test that subfolder is correctly included in path."""
        storage = JsonStorageXDG("test", xdg_folder=temp_dir,
                               subfolder="myapp", disable_lock=True)

        assert "myapp" in storage.path
        assert storage.path.endswith("test.json")

    def test_multiple_files_same_folder(self, temp_dir):
        """Test creating multiple files in same XDG folder."""
        storage1 = JsonStorageXDG("config1", xdg_folder=temp_dir,
                                 disable_lock=True)
        storage2 = JsonStorageXDG("config2", xdg_folder=temp_dir,
                                 disable_lock=True)

        storage1["key"] = "value1"
        storage2["key"] = "value2"

        storage1.store()
        storage2.store()

        # Verify they stored separately
        storage1_reload = JsonStorageXDG("config1", xdg_folder=temp_dir,
                                        disable_lock=True)
        storage2_reload = JsonStorageXDG("config2", xdg_folder=temp_dir,
                                        disable_lock=True)

        assert storage1_reload["key"] == "value1"
        assert storage2_reload["key"] == "value2"
