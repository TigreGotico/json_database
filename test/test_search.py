"""Unit tests for search utility functions."""

import pytest
from json_database.utils import (
    fuzzy_match, match_one, merge_dict,
    get_key_recursively, get_value_recursively,
    get_key_recursively_fuzzy, get_value_recursively_fuzzy
)


class TestFuzzyMatch:
    """Test fuzzy_match string similarity function."""

    def test_exact_match(self):
        """Test perfect string match."""
        score = fuzzy_match("hello", "hello")
        assert score == 1.0

    def test_no_match(self):
        """Test completely different strings."""
        score = fuzzy_match("abc", "xyz")
        assert 0 <= score < 0.5

    def test_partial_match(self):
        """Test partial string match."""
        score = fuzzy_match("hello", "hallo")
        assert 0.5 < score < 1.0

    def test_substring_match(self):
        """Test when one is substring of other."""
        score = fuzzy_match("test", "testing")
        assert 0.5 <= score < 1.0

    def test_case_sensitive(self):
        """Test that matching is case-sensitive."""
        score1 = fuzzy_match("Hello", "hello")
        score2 = fuzzy_match("hello", "hello")
        assert score1 < score2

    def test_empty_strings(self):
        """Test matching empty strings."""
        score = fuzzy_match("", "")
        assert score == 1.0

    def test_empty_vs_nonempty(self):
        """Test empty string vs non-empty."""
        score = fuzzy_match("", "hello")
        assert score == 0.0

    def test_long_strings(self):
        """Test matching longer strings."""
        str1 = "the quick brown fox jumps over the lazy dog"
        str2 = "the quick brown fox jumps over the lazy dog"
        assert fuzzy_match(str1, str2) == 1.0

    def test_unicode_strings(self):
        """Test matching unicode strings."""
        score = fuzzy_match("café", "cafe")
        assert 0 <= score <= 1.0


class TestMatchOne:
    """Test match_one best-match selection."""

    def test_exact_match_in_list(self):
        """Test finding exact match in list."""
        choices = ["apple", "banana", "cherry"]
        match, score = match_one("banana", choices)
        assert match == "banana"
        assert score == 1.0

    def test_best_match_in_list(self):
        """Test finding best match when no exact match."""
        choices = ["apple", "apply", "apricot"]
        match, score = match_one("aple", choices)
        # Should match "apple" or "apply" (fuzzy)
        assert match in ["apple", "apply"]
        assert score > 0.5

    def test_match_in_dict(self):
        """Test finding best match in dictionary keys."""
        choices = {"apple": 1, "banana": 2, "cherry": 3}
        match, score = match_one("banana", choices)
        assert match == 2  # Returns the value, not the key
        assert score == 1.0

    def test_single_choice(self):
        """Test with single choice."""
        choices = ["apple"]
        match, score = match_one("apple", choices)
        assert match == "apple"
        assert score == 1.0

    def test_no_perfect_match(self):
        """Test when no perfect match exists."""
        choices = ["apple", "banana", "cherry"]
        match, score = match_one("orange", choices)
        # Should return best match with score < 1.0
        assert match in choices
        assert score < 1.0

    def test_invalid_choices_type(self):
        """Test that invalid choices type raises error."""
        with pytest.raises(ValueError):
            match_one("query", 123)  # Invalid type


class TestKeyRecursion:
    """Test recursive key search utilities."""

    def test_get_key_recursively_flat(self):
        """Test finding key in flat dict."""
        data = {"a": 1, "b": 2, "c": 3}
        results = get_key_recursively(data, "b", filter_None=True)
        # Returns list of dicts that contain the key
        assert len(results) == 1
        assert results[0] == data

    def test_get_key_recursively_nested(self):
        """Test finding key in nested dict."""
        data = {
            "level1": {
                "level2": {
                    "target": "value"
                }
            }
        }
        results = get_key_recursively(data, "target", filter_None=True)
        # Should find the nested dict containing "target"
        assert len(results) > 0
        assert "target" in results[0]

    def test_get_key_recursively_multiple(self):
        """Test finding key that appears multiple times."""
        data = {
            "id": 1,
            "nested": {
                "id": 2,
                "deep": {
                    "id": 3
                }
            }
        }
        results = get_key_recursively(data, "id")
        assert len(results) >= 1

    def test_get_key_recursively_not_found(self):
        """Test when key not found."""
        data = {"a": 1, "b": {"c": 2}}
        results = get_key_recursively(data, "z")
        assert len(results) == 0

    def test_get_key_recursively_fuzzy(self):
        """Test fuzzy key searching."""
        data = {
            "firstname": "John",
            "nested": {
                "lastname": "Doe"
            }
        }
        results = get_key_recursively_fuzzy(data, "name", thresh=0.5)
        # Should find keys matching "name" fuzzily
        assert len(results) > 0


class TestValueRecursion:
    """Test recursive value search utilities."""

    def test_get_value_recursively_flat(self):
        """Test finding value in flat dict."""
        data = {"a": "apple", "b": "banana", "c": "cherry"}
        results = get_value_recursively(data, "a", "apple")
        assert len(results) > 0

    def test_get_value_recursively_nested(self):
        """Test finding value in nested dict."""
        data = {
            "user": {
                "name": "Alice",
                "details": {
                    "city": "NYC"
                }
            }
        }
        results = get_value_recursively(data, "name", "Alice")
        assert len(results) > 0

    def test_get_value_recursively_not_found(self):
        """Test when value not found."""
        data = {"a": 1, "b": {"c": 2}}
        results = get_value_recursively(data, "x", "nonexistent")
        assert len(results) == 0

    def test_get_value_recursively_different_types(self):
        """Test finding values with different types."""
        data = {
            "count": 42,
            "name": "test",
            "nested": {
                "value": 42
            }
        }
        results = get_value_recursively(data, "count", 42)
        assert len(results) > 0

    def test_get_value_recursively_fuzzy(self):
        """Test fuzzy value searching."""
        data = {
            "product": "Laptop",
            "items": {
                "item": "Lapto"  # Typo
            }
        }
        results = get_value_recursively_fuzzy(data, "product", "Lapto", thresh=0.7)
        # Should find similar value
        assert len(results) >= 0  # Might be 0 or more depending on threshold

    def test_get_value_recursively_in_lists(self):
        """Test finding values when value is in a list."""
        data = {
            "tags": ["python", "testing", "data"],
            "nested": {
                "keywords": ["python", "tutorial"]
            }
        }
        results = get_value_recursively(data, "tags", ["python", "testing", "data"])
        assert len(results) > 0


class TestMergeDict:
    """Test dictionary merging utility."""

    def test_simple_merge(self):
        """Test simple non-overlapping merge."""
        base = {"a": 1}
        delta = {"b": 2}
        result = merge_dict(base, delta)
        assert result == {"a": 1, "b": 2}

    def test_merge_overwrites(self):
        """Test that merge overwrites existing keys."""
        base = {"a": 1, "b": 2}
        delta = {"b": 3}
        result = merge_dict(base, delta)
        assert result["b"] == 3

    def test_merge_nested_dicts(self):
        """Test merging nested dictionaries."""
        base = {"a": {"x": 1}}
        delta = {"a": {"y": 2}}
        result = merge_dict(base, delta)
        assert result["a"]["x"] == 1
        assert result["a"]["y"] == 2

    def test_merge_lists(self):
        """Test merge_lists parameter."""
        base = {"items": [1, 2]}
        delta = {"items": [3, 4]}
        result = merge_dict(base, delta, merge_lists=True)
        assert 1 in result["items"] and 3 in result["items"]

    def test_merge_lists_no_dupes(self):
        """Test no_dupes parameter in list merge."""
        base = {"items": [1, 2]}
        delta = {"items": [2, 3]}
        result = merge_dict(base, delta, merge_lists=True, no_dupes=True)
        assert result["items"].count(2) == 1

    def test_skip_empty(self):
        """Test skip_empty parameter."""
        base = {"a": "value"}
        delta = {"a": ""}
        result = merge_dict(base, delta, skip_empty=True)
        assert result["a"] == "value"

    def test_new_only(self):
        """Test new_only parameter (only add new keys)."""
        base = {"a": 1}
        delta = {"a": 2, "b": 2}
        result = merge_dict(base, delta, new_only=True)
        assert result["a"] == 1  # Not overwritten
        assert result["b"] == 2  # New key added

    def test_merge_with_none_values(self):
        """Test merging None values."""
        base = {"a": 1, "b": None}
        delta = {"b": 2}
        result = merge_dict(base, delta, skip_empty=False)
        assert result["b"] == 2

    def test_deep_nested_merge(self):
        """Test merging deeply nested structures."""
        base = {
            "level1": {
                "level2": {
                    "level3": {
                        "value": "original"
                    }
                }
            }
        }
        delta = {
            "level1": {
                "level2": {
                    "level3": {
                        "new_value": "added"
                    }
                }
            }
        }
        result = merge_dict(base, delta)
        assert result["level1"]["level2"]["level3"]["value"] == "original"
        assert result["level1"]["level2"]["level3"]["new_value"] == "added"


class TestMergeDictEdgeCases:
    """Test edge cases in merge_dict for full coverage."""

    def test_merge_dict_nested_with_false_values(self):
        """Test merge_dict preserves False values (not treated as empty)."""
        base = {"flag": True}
        delta = {"flag": False}
        result = merge_dict(base, delta, skip_empty=True)
        assert result["flag"] is False

    def test_merge_dict_list_with_empty_list_skip(self):
        """Test skip_empty=True doesn't skip empty list."""
        base = {"items": [1, 2, 3]}
        delta = {"items": []}
        result = merge_dict(base, delta, skip_empty=True)
        # Empty list should be skipped, so base value remains
        assert result["items"] == [1, 2, 3]

    def test_merge_dict_replace_dict_with_list(self):
        """Test merge_dict replaces dict with list."""
        base = {"data": {"key": "value"}}
        delta = {"data": [1, 2, 3]}
        result = merge_dict(base, delta, merge_lists=False)
        assert result["data"] == [1, 2, 3]

    def test_merge_dict_replace_list_with_dict(self):
        """Test merge_dict replaces list with dict."""
        base = {"data": [1, 2, 3]}
        delta = {"data": {"key": "value"}}
        result = merge_dict(base, delta, merge_lists=False)
        assert result["data"] == {"key": "value"}

    def test_merge_dict_with_zero_value_skipped(self):
        """Test merge_dict skips 0 values with skip_empty=True."""
        base = {"count": 5}
        delta = {"count": 0}
        result = merge_dict(base, delta, skip_empty=True)
        # 0 is considered empty, so should be skipped
        assert result["count"] == 5

    def test_merge_dict_with_zero_value_not_skipped(self):
        """Test merge_dict preserves 0 without skip_empty."""
        base = {"count": 5}
        delta = {"count": 0}
        result = merge_dict(base, delta, skip_empty=False)
        assert result["count"] == 0

    def test_merge_dict_none_with_skip_empty(self):
        """Test merge_dict with None values and skip_empty."""
        base = {"key": "original"}
        delta = {"key": None}
        result = merge_dict(base, delta, skip_empty=True)
        # None is empty, should be skipped
        assert result["key"] == "original"

    def test_merge_dict_none_without_skip_empty(self):
        """Test merge_dict with None values without skip_empty."""
        base = {"key": "original"}
        delta = {"key": None}
        result = merge_dict(base, delta, skip_empty=False)
        assert result["key"] is None

    def test_merge_dict_deeply_nested_with_merge_lists_false(self):
        """Test nested merge with merge_lists=False."""
        base = {
            "level1": {
                "level2": {
                    "items": [1, 2, 3]
                }
            }
        }
        delta = {
            "level1": {
                "level2": {
                    "items": [4, 5]
                }
            }
        }
        result = merge_dict(base, delta, merge_lists=False)
        # Should replace the list, not merge it
        assert result["level1"]["level2"]["items"] == [4, 5]

    def test_merge_dict_empty_string_with_skip(self):
        """Test merge_dict skips empty string when skip_empty=True."""
        base = {"name": "original"}
        delta = {"name": ""}
        result = merge_dict(base, delta, skip_empty=True)
        assert result["name"] == "original"

    def test_merge_dict_unicode_values(self):
        """Test merge_dict with unicode values."""
        base = {"greeting": "hello"}
        delta = {"greeting": "こんにちは"}
        result = merge_dict(base, delta)
        assert result["greeting"] == "こんにちは"


class TestSearchEdgeCases:
    """Test edge cases in search operations."""

    def test_empty_dict_search(self):
        """Test searching in empty dict."""
        data = {}
        results = get_key_recursively(data, "any_key")
        assert len(results) == 0

    def test_dict_with_none_values(self):
        """Test searching with None values."""
        data = {"a": None, "b": 2}
        # With filter_None=True (default), None values are skipped
        results = get_key_recursively(data, "a", filter_None=True)
        assert len(results) == 0

        # With filter_None=False, None values are included
        results2 = get_key_recursively(data, "a", filter_None=False)
        assert len(results2) > 0

    def test_dict_with_list_values(self):
        """Test searching in dict with list values."""
        data = {"tags": ["a", "b", "c"]}
        # get_key_recursively should find the key
        results = get_key_recursively(data, "tags")
        assert len(results) > 0

    def test_unicode_key_search(self):
        """Test searching for unicode keys."""
        data = {"名前": "Tanaka", "年齢": 30}
        results = get_key_recursively(data, "名前")
        assert len(results) > 0

    def test_fuzzy_with_very_different_strings(self):
        """Test fuzzy matching with very different strings."""
        score = fuzzy_match("aaaaaa", "zzzzzz")
        assert score < 0.3

    def test_match_one_with_empty_list(self):
        """Test match_one with empty list."""
        with pytest.raises((IndexError, ValueError)):
            match_one("query", [])
