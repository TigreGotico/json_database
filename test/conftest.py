"""Pytest configuration and shared fixtures for json_database tests."""

import os
import pytest
import tempfile
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files, cleanup after test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def temp_db_path(temp_dir):
    """Generate a unique temp file path for a test database."""
    return os.path.join(temp_dir, "test_db.json")


@pytest.fixture
def sample_dict_data():
    """Return sample dictionary data for testing."""
    return {
        "name": "John Doe",
        "age": 30,
        "email": "john@example.com",
        "active": True,
        "tags": ["python", "testing"],
        "metadata": {
            "created": "2025-01-01",
            "modified": "2025-04-02"
        }
    }


@pytest.fixture
def sample_list_data():
    """Return sample list of dictionaries for database testing."""
    return [
        {"id": 1, "name": "Alice", "status": "active"},
        {"id": 2, "name": "Bob", "status": "inactive"},
        {"id": 3, "name": "Charlie", "status": "active"},
        {"id": 4, "name": "Diana", "status": "pending"},
    ]


@pytest.fixture
def nested_dict_data():
    """Return deeply nested dictionary for recursion testing."""
    return {
        "level1": {
            "level2": {
                "level3": {
                    "value": "deep",
                    "count": 42
                },
                "list": [1, 2, 3]
            },
            "key": "level1_value"
        },
        "flat": "top_level"
    }


@pytest.fixture
def encryption_key():
    """Return a valid 16-byte encryption key for testing."""
    return "S" * 16  # 16 bytes
