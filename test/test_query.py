"""Unit tests for Query builder class."""

import pytest
from json_database import JsonDatabase
from json_database.search import Query


class TestQuery:
    """Test suite for Query filter builder."""

    @pytest.fixture
    def sample_db(self, temp_db_path, sample_list_data):
        """Create a database with sample data for testing."""
        db = JsonDatabase("records", path=temp_db_path, disable_lock=True)
        for item in sample_list_data:
            db.add_item(item)
        return db

    @pytest.fixture
    def complex_db(self, temp_db_path):
        """Create a database with more complex data for advanced filtering."""
        db = JsonDatabase("products", path=temp_db_path, disable_lock=True)
        db.add_item({
            "id": 1,
            "name": "Laptop",
            "category": "Electronics",
            "price": 999.99,
            "tags": ["computers", "portable"],
            "in_stock": True
        })
        db.add_item({
            "id": 2,
            "name": "Mouse",
            "category": "Electronics",
            "price": 29.99,
            "tags": ["accessories", "input"],
            "in_stock": True
        })
        db.add_item({
            "id": 3,
            "name": "Book",
            "category": "Books",
            "price": 19.99,
            "tags": ["education", "reading"],
            "in_stock": False
        })
        db.add_item({
            "id": 4,
            "name": "Notebook",
            "category": "Office",
            "price": 5.99,
            "tags": ["stationery", "writing"],
            "in_stock": True
        })
        return db

    def test_query_initialization_from_database(self, sample_db):
        """Test creating Query from JsonDatabase."""
        query = Query(sample_db)
        assert len(query.result) == len(sample_db)

    def test_query_initialization_from_dict(self):
        """Test creating Query from single dictionary."""
        item = {"id": 1, "name": "Test"}
        query = Query(item)
        assert len(query.result) == 1
        assert query.result[0] == item

    def test_contains_key_exact(self, sample_db):
        """Test filtering by exact key presence."""
        query = Query(sample_db)
        query.contains_key("status")
        results = query.build()

        # All sample items have 'status' key
        assert len(results) == len(sample_db)

    def test_contains_key_missing(self, sample_db):
        """Test filtering by key that doesn't exist."""
        query = Query(sample_db)
        query.contains_key("nonexistent_key")
        results = query.build()

        # No items have this key
        assert len(results) == 0

    def test_contains_key_fuzzy(self, sample_db):
        """Test fuzzy key matching."""
        query = Query(sample_db)
        query.contains_key("nam", fuzzy=True, thresh=0.7)
        results = query.build()

        # Should match items with keys similar to "nam" (e.g., "name")
        assert len(results) > 0

    def test_contains_key_ignore_case(self, complex_db):
        """Test case-insensitive key matching."""
        query = Query(complex_db)
        query.contains_key("NAME", ignore_case=True)
        results = query.build()

        # Should find items with "name" key (case-insensitive)
        assert len(results) == len(complex_db)

    def test_contains_value_exact(self, complex_db):
        """Test filtering by exact key-value pair."""
        query = Query(complex_db)
        query.contains_value("category", "Electronics")
        results = query.build()

        # Should find Laptop and Mouse
        assert len(results) == 2

    def test_contains_value_fuzzy(self, complex_db):
        """Test fuzzy value matching."""
        query = Query(complex_db)
        query.contains_value("name", "Lapto", fuzzy=True, thresh=0.7)
        results = query.build()

        # Should fuzzy match "Laptop"
        assert len(results) > 0

    def test_contains_value_in_list(self, complex_db):
        """Test value matching when value is in a list."""
        query = Query(complex_db)
        query.contains_value("tags", "computers")
        results = query.build()

        # Laptop has "computers" in tags
        assert len(results) >= 1

    def test_value_contains(self, complex_db):
        """Test filtering by substring containment."""
        query = Query(complex_db)
        query.value_contains("name", "Book")
        results = query.build()

        # Should find items with "Book" in name
        assert len(results) >= 1

    def test_value_contains_ignore_case(self, complex_db):
        """Test case-insensitive substring matching."""
        query = Query(complex_db)
        query.value_contains("name", "laptop", ignore_case=True)
        results = query.build()

        # Should match "Laptop" case-insensitively
        assert len(results) >= 1

    def test_value_contains_token(self, complex_db):
        """Test word token matching."""
        query = Query(complex_db)
        query.value_contains_token("name", "Laptop")
        results = query.build()

        # Should find "Laptop" as a word
        assert len(results) >= 1

    def test_equal(self, complex_db):
        """Test exact equality filtering."""
        query = Query(complex_db)
        query.equal("category", "Electronics")
        results = query.build()

        # Should match exactly "Electronics"
        assert len(results) == 2

    def test_equal_ignore_case(self, complex_db):
        """Test case-insensitive equality."""
        query = Query(complex_db)
        query.equal("category", "electronics", ignore_case=True)
        results = query.build()

        # Should match "Electronics" case-insensitively
        assert len(results) == 2

    def test_below(self, complex_db):
        """Test less-than filtering."""
        query = Query(complex_db)
        query.below("price", 50)
        results = query.build()

        # Mouse, Book, Notebook are below $50
        assert len(results) >= 3

    def test_above(self, complex_db):
        """Test greater-than filtering."""
        query = Query(complex_db)
        query.above("price", 500)
        results = query.build()

        # Only Laptop is above $500
        assert len(results) >= 1

    def test_below_or_equal(self, complex_db):
        """Test less-than-or-equal filtering."""
        query = Query(complex_db)
        query.below_or_equal("price", 29.99)
        results = query.build()

        # Mouse, Book, Notebook
        assert len(results) >= 3

    def test_above_or_equal(self, complex_db):
        """Test greater-than-or-equal filtering."""
        query = Query(complex_db)
        query.above_or_equal("price", 999.99)
        results = query.build()

        # Only Laptop
        assert len(results) >= 1

    def test_in_range(self, complex_db):
        """Test range filtering."""
        query = Query(complex_db)
        query.in_range("price", 5, 100)
        results = query.build()

        # Mouse ($29.99), Book ($19.99), Notebook ($5.99)
        # Price must be strictly > 5 and < 100
        assert len(results) >= 2

    def test_chainable_filters(self, complex_db):
        """Test that filters are chainable."""
        query = Query(complex_db)
        results = (query
                   .contains_key("tags")
                   .equal("in_stock", True)
                   .below("price", 100)
                   .build())

        # Should have items with tags, in_stock=True, price<100
        assert len(results) > 0

    def test_chaining_narrows_results(self, complex_db):
        """Test that chaining filters properly narrows results."""
        # Start with all
        query1 = Query(complex_db)
        all_results = query1.build()

        # Chain filters
        query2 = Query(complex_db)
        query2.equal("in_stock", True)
        in_stock = query2.build()

        # Further chain
        query3 = Query(complex_db)
        query3.equal("in_stock", True).below("price", 100)
        filtered = query3.build()

        assert len(all_results) >= len(in_stock) >= len(filtered)

    def test_all_method(self, complex_db):
        """Test that all() returns all items (no-op)."""
        query = Query(complex_db)
        results = query.all().build()

        assert len(results) == len(complex_db)

    def test_build_returns_result_list(self, sample_db):
        """Test that build() returns the result list."""
        query = Query(sample_db)
        query.equal("status", "active")
        results = query.build()

        assert isinstance(results, list)

    def test_multiple_filters_on_same_key(self, complex_db):
        """Test applying multiple filters on the same key."""
        query = Query(complex_db)
        query.above("price", 10).below("price", 500)
        results = query.build()

        # Should have items with price between 10 and 500
        assert len(results) >= 1
        for item in results:
            assert 10 < item["price"] < 500

    def test_filtering_with_empty_result(self, sample_db):
        """Test filtering that results in no matches."""
        query = Query(sample_db)
        query.equal("status", "nonexistent_status")
        results = query.build()

        assert len(results) == 0

    def test_filtering_nested_keys(self, temp_db_path, nested_dict_data):
        """Test filtering on top-level keys of nested items."""
        db = JsonDatabase("nested", path=temp_db_path, disable_lock=True)
        db.add_item(nested_dict_data)

        query = Query(db)
        query.contains_key("level1")
        results = query.build()

        assert len(results) == 1

    def test_preserve_data_integrity(self, sample_db):
        """Test that filtering doesn't modify original data."""
        original_length = len(sample_db)
        original_first = sample_db[0].copy()

        query = Query(sample_db)
        query.equal("status", "active")
        _ = query.build()

        # Original database should be unchanged
        assert len(sample_db) == original_length
        assert sample_db[0] == original_first

    def test_boolean_equality(self, complex_db):
        """Test filtering with boolean values."""
        query = Query(complex_db)
        query.equal("in_stock", True)
        results = query.build()

        # Should find items that are in stock
        assert len(results) >= 1
        for item in results:
            assert item["in_stock"] is True

    def test_number_comparisons(self, complex_db):
        """Test numeric comparisons with various thresholds."""
        # Test exact price
        query1 = Query(complex_db)
        query1.equal("price", 29.99)
        results1 = query1.build()
        assert len(results1) == 1

        # Test above threshold
        query2 = Query(complex_db)
        query2.above("price", 100)
        results2 = query2.build()
        assert all(item["price"] > 100 for item in results2)

        # Test below threshold
        query3 = Query(complex_db)
        query3.below("price", 50)
        results3 = query3.build()
        assert all(item["price"] < 50 for item in results3)

    def test_filter_sequence(self, complex_db):
        """Test a realistic sequence of filters."""
        query = Query(complex_db)

        # Find electronics that are in stock and cheap
        results = (query
                   .equal("category", "Electronics")
                   .equal("in_stock", True)
                   .below("price", 100)
                   .build())

        # Should find Mouse (the only cheap electronic in stock)
        assert len(results) >= 1
        for item in results:
            assert item["category"] == "Electronics"
            assert item["in_stock"] is True
            assert item["price"] < 100
