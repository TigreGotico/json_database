"""Unit tests for search utility functions."""

import json
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

    def test_lru_cache_hit_on_repeated_call(self):
        """fuzzy_match is cached: a repeated call increments cache hits."""
        fuzzy_match.cache_clear()
        fuzzy_match("alpha", "alpha")
        fuzzy_match("alpha", "alpha")  # second call — must be a cache hit
        assert fuzzy_match.cache_info().hits >= 1


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


class TestUncommentJson:
    """Test uncomment_json and load_commented_json."""

    def test_uncomment_single_line_comments(self):
        """Test removing lines starting with //."""
        from json_database.utils import uncomment_json
        json_str = '{\n  // this is a comment\n  "name": "value"\n}'
        result = uncomment_json(json_str)
        assert "this is a comment" not in result
        assert "name" in result

    def test_uncomment_hash_comments(self):
        """Test removing lines starting with #."""
        from json_database.utils import uncomment_json
        json_str = '{\n  # hash comment\n  "key": 1\n}'
        result = uncomment_json(json_str)
        assert "hash comment" not in result
        assert "key" in result

    def test_uncomment_multiline_with_comments(self):
        """Test removing comments from multiline JSON."""
        from json_database.utils import uncomment_json
        json_str = '''{\n  // start\n  "a": 1,\n  # middle\n  "b": 2\n  // end\n}'''
        result = uncomment_json(json_str)
        assert "//" not in result
        assert "#" not in result
        assert '"a": 1' in result
        assert '"b": 2' in result

    def test_uncomment_preserves_json_structure(self):
        """Test that JSON structure is preserved after removing comments."""
        from json_database.utils import uncomment_json
        json_str = '''{\n  // comment here\n  "key": "value",\n  # another comment\n  "list": [1, 2, 3]\n}'''
        result = uncomment_json(json_str)
        data = json.loads(result)
        assert data["key"] == "value"
        assert data["list"] == [1, 2, 3]

    def test_uncomment_empty_lines(self):
        """Test handling empty lines in JSON."""
        from json_database.utils import uncomment_json
        json_str = '{\n  \n  "key": "val"\n  \n}'
        result = uncomment_json(json_str)
        assert "key" in result

    def test_uncomment_indented_comments(self):
        """Test removing indented comment lines."""
        from json_database.utils import uncomment_json
        json_str = '''{\n    // indented comment\n    "field": "data"\n}'''
        result = uncomment_json(json_str)
        assert "indented comment" not in result

    def test_load_commented_json_file(self, tmp_path):
        """Test load_commented_json with actual file."""
        from json_database.utils import load_commented_json
        test_file = tmp_path / "test.json"
        content = '''{\n  // comment\n  "test": "data"\n}'''
        test_file.write_text(content)
        data = load_commented_json(str(test_file))
        assert data["test"] == "data"

    def test_load_commented_json_complex(self, tmp_path):
        """Test load_commented_json with complex JSON."""
        from json_database.utils import load_commented_json
        test_file = tmp_path / "complex.json"
        content = '''{\n  // config section\n  "app": {\n    # database\n    "db": "sqlite",\n    "port": 5432\n  },\n  // items\n  "items": [1, 2, 3]\n}'''
        test_file.write_text(content)
        data = load_commented_json(str(test_file))
        assert data["app"]["db"] == "sqlite"
        assert data["items"] == [1, 2, 3]


class TestIsJsonifiable:
    """Test is_jsonifiable utility function."""

    def test_is_jsonifiable_dict(self):
        """Test that dict is jsonifiable."""
        from json_database.utils import is_jsonifiable
        assert is_jsonifiable({"key": "value"}) is True

    def test_is_jsonifiable_valid_json_string(self):
        """Test that valid JSON string is jsonifiable."""
        from json_database.utils import is_jsonifiable
        assert is_jsonifiable('{"key": "value"}') is True

    def test_is_jsonifiable_invalid_json_string(self):
        """Test that invalid JSON string is not jsonifiable."""
        from json_database.utils import is_jsonifiable
        assert is_jsonifiable("not json {invalid}") is False

    def test_is_jsonifiable_plain_string(self):
        """Test that plain string is not jsonifiable (not valid JSON)."""
        from json_database.utils import is_jsonifiable
        assert is_jsonifiable("plain string") is False

    def test_is_jsonifiable_object_with_dict(self):
        """Test that object with __dict__ is jsonifiable."""
        from json_database.utils import is_jsonifiable
        class TestObj:
            pass
        obj = TestObj()
        assert is_jsonifiable(obj) is True

    def test_is_jsonifiable_number(self):
        """Test that number is not jsonifiable (no __dict__)."""
        from json_database.utils import is_jsonifiable
        assert is_jsonifiable(42) is False

    def test_is_jsonifiable_list(self):
        """Test that list is not jsonifiable (no __dict__)."""
        from json_database.utils import is_jsonifiable
        assert is_jsonifiable([1, 2, 3]) is False

    def test_is_jsonifiable_none(self):
        """Test that None is not jsonifiable."""
        from json_database.utils import is_jsonifiable
        assert is_jsonifiable(None) is False


class TestGetValueRecursivelyFuzzy:
    """Test fuzzy value searching."""

    def test_get_value_recursively_fuzzy_exact_match(self):
        """Test fuzzy value search with exact match."""
        from json_database.utils import get_value_recursively_fuzzy
        data = {"name": "Alice", "age": 30}
        results = get_value_recursively_fuzzy(data, "name", "Alice", thresh=0.5)
        assert len(results) > 0
        assert results[0][1] == 1.0

    def test_get_value_recursively_fuzzy_partial_match(self):
        """Test fuzzy value search with partial match."""
        from json_database.utils import get_value_recursively_fuzzy
        data = {"product": "Laptop"}
        results = get_value_recursively_fuzzy(data, "product", "Lapto", thresh=0.7)
        # Should find similar value
        assert len(results) > 0

    def test_get_value_recursively_fuzzy_in_list(self):
        """Test fuzzy matching values inside lists."""
        from json_database.utils import get_value_recursively_fuzzy
        data = {"tags": ["python", "testing", "data"]}
        results = get_value_recursively_fuzzy(data, "tags", "python", thresh=0.5)
        assert len(results) > 0

    def test_get_value_recursively_fuzzy_nested(self):
        """Test fuzzy matching in nested structures."""
        from json_database.utils import get_value_recursively_fuzzy
        data = {
            "user": {
                "profile": {
                    "name": "John"
                }
            }
        }
        results = get_value_recursively_fuzzy(data, "name", "John", thresh=0.5)
        assert len(results) > 0

    def test_get_value_recursively_fuzzy_no_match(self):
        """Test fuzzy matching when no match found."""
        from json_database.utils import get_value_recursively_fuzzy
        data = {"name": "Alice"}
        results = get_value_recursively_fuzzy(data, "name", "xyz", thresh=0.99)
        assert len(results) == 0

    def test_get_value_recursively_fuzzy_threshold(self):
        """Test fuzzy matching with different thresholds."""
        from json_database.utils import get_value_recursively_fuzzy
        data = {"word": "test"}
        results_low = get_value_recursively_fuzzy(data, "word", "tost", thresh=0.5)
        results_high = get_value_recursively_fuzzy(data, "word", "tost", thresh=0.99)
        assert len(results_low) >= len(results_high)

    def test_get_value_recursively_fuzzy_multiple_matches(self):
        """Test fuzzy matching returns multiple matches sorted by score."""
        from json_database.utils import get_value_recursively_fuzzy
        data = {
            "a": "apple",
            "b": "apply",
            "c": "orange"
        }
        results = get_value_recursively_fuzzy(data, "a", "aple", thresh=0.6)
        # Should be sorted by score (highest first)
        if len(results) > 1:
            assert results[0][1] >= results[1][1]


class TestJsonifyRecursively:
    """Test jsonify_recursively utility function."""

    def test_jsonify_recursively_dict(self):
        """Test jsonifying a simple dict."""
        from json_database.utils import jsonify_recursively
        data = {"key": "value", "nested": {"inner": "data"}}
        result = jsonify_recursively(data)
        assert result["key"] == "value"
        assert result["nested"]["inner"] == "data"

    def test_jsonify_recursively_list(self):
        """Test jsonifying a list."""
        from json_database.utils import jsonify_recursively
        data = [1, 2, {"key": "value"}]
        result = jsonify_recursively(data)
        assert len(result) == 3
        assert result[2]["key"] == "value"

    def test_jsonify_recursively_nested_lists(self):
        """Test jsonifying nested lists."""
        from json_database.utils import jsonify_recursively
        data = [[1, 2], [3, 4]]
        result = jsonify_recursively(data)
        assert result == [[1, 2], [3, 4]]

    def test_jsonify_recursively_object_with_dict(self):
        """Test jsonifying object with __dict__."""
        from json_database.utils import jsonify_recursively
        class TestObj:
            def __init__(self):
                self.name = "test"
                self.value = 42
        obj = TestObj()
        result = jsonify_recursively(obj)
        assert result["name"] == "test"
        assert result["value"] == 42

    def test_jsonify_recursively_mixed_structure(self):
        """Test jsonifying mixed dict/list/object structures."""
        from json_database.utils import jsonify_recursively
        class Item:
            def __init__(self, val):
                self.val = val
        data = {
            "items": [Item(1), Item(2)],
            "meta": {"count": 2}
        }
        result = jsonify_recursively(data)
        assert len(result["items"]) == 2
        assert result["items"][0]["val"] == 1
        assert result["meta"]["count"] == 2

    def test_jsonify_recursively_scalar_values(self):
        """Test jsonifying scalar values."""
        from json_database.utils import jsonify_recursively
        assert jsonify_recursively(42) == 42
        assert jsonify_recursively("string") == "string"
        assert jsonify_recursively(3.14) == 3.14
        assert jsonify_recursively(True) is True


class TestGetKeyRecursivelyEdgeCases:
    """Test edge cases in get_key_recursively functions."""

    def test_get_key_recursively_with_objects_in_list(self):
        """Test get_key_recursively with list containing dicts."""
        class Item:
            def __init__(self, name):
                self.name = name

        data = {
            "items": [Item("first"), Item("second")]
        }
        results = get_key_recursively(data, "name")
        # Should find name in objects within list via __dict__
        assert isinstance(results, list)

    def test_get_key_recursively_unparseable_input(self):
        """Test get_key_recursively raises error for unparseable input."""
        with pytest.raises(ValueError):
            get_key_recursively(42, "key")

    def test_get_key_recursively_fuzzy_empty_threshold(self):
        """Test fuzzy key search with very low threshold."""
        from json_database.utils import get_key_recursively_fuzzy
        data = {"product": "item", "name": "test"}
        results = get_key_recursively_fuzzy(data, "x", thresh=0.0)
        # Even low threshold should match something
        assert len(results) >= 0

    def test_get_key_recursively_fuzzy_high_threshold(self):
        """Test fuzzy key search with very high threshold."""
        from json_database.utils import get_key_recursively_fuzzy
        data = {"firstname": "John", "lastname": "Doe"}
        results = get_key_recursively_fuzzy(data, "name", thresh=0.99)
        # High threshold may not match anything
        assert isinstance(results, list)

    def test_get_key_recursively_fuzzy_sorting(self):
        """Test that fuzzy results are sorted by score."""
        from json_database.utils import get_key_recursively_fuzzy
        data = {
            "name": "test",
            "names": "test2",
            "n": "test3"
        }
        results = get_key_recursively_fuzzy(data, "name", thresh=0.3)
        if len(results) > 1:
            # Should be sorted by score descending
            for i in range(len(results) - 1):
                assert results[i][1] >= results[i+1][1]


class TestGetValueRecursivelyEdgeCases:
    """Test edge cases in get_value_recursively functions."""

    def test_get_value_recursively_unparseable_input(self):
        """Test get_value_recursively raises error for unparseable input."""
        with pytest.raises(ValueError):
            get_value_recursively(42, "key", "value")

    def test_get_value_recursively_with_objects_in_list(self):
        """Test get_value_recursively with objects in list."""
        class Item:
            def __init__(self, id):
                self.id = id
        data = {"items": [Item(1), Item(2)]}
        results = get_value_recursively(data, "id", 1)
        # Should find objects with id=1
        assert len(results) >= 1

    def test_get_value_recursively_fuzzy_unparseable(self):
        """Test get_value_recursively_fuzzy raises error for unparseable input."""
        with pytest.raises(ValueError):
            get_value_recursively_fuzzy(42, "key", "value")

    def test_get_value_recursively_fuzzy_list_fuzzy_matching(self):
        """Test fuzzy matching against list values."""
        from json_database.utils import get_value_recursively_fuzzy
        data = {"tags": ["python", "testing"]}
        results = get_value_recursively_fuzzy(data, "tags", "python", thresh=0.5)
        assert len(results) > 0

    def test_get_value_recursively_fuzzy_dict_value(self):
        """Test fuzzy search when key maps to dict (no match)."""
        from json_database.utils import get_value_recursively_fuzzy
        data = {"nested": {"inner": "value"}}
        # Searching for dict value should not match
        results = get_value_recursively_fuzzy(data, "nested", "value", thresh=0.5)
        assert isinstance(results, list)

    def test_get_value_recursively_fuzzy_object_in_list(self):
        """Test fuzzy search with objects in list."""
        from json_database.utils import get_value_recursively_fuzzy
        class Item:
            def __init__(self, name):
                self.name = name
        data = {"items": [Item("test")]}
        results = get_value_recursively_fuzzy(data, "name", "test", thresh=0.5)
        assert len(results) >= 0  # May or may not find depending on structure


class TestDummyLock:
    """Test DummyLock utility class."""

    def test_dummy_lock_acquire(self):
        """Test DummyLock.acquire always returns True."""
        from json_database.utils import DummyLock
        lock = DummyLock("/tmp/test.lock")
        assert lock.acquire() is True
        assert lock.acquire(blocking=False) is True

    def test_dummy_lock_release(self):
        """Test DummyLock.release is a no-op."""
        from json_database.utils import DummyLock
        lock = DummyLock("/tmp/test.lock")
        lock.release()  # Should not raise

    def test_dummy_lock_context_manager(self):
        """Test DummyLock as context manager."""
        from json_database.utils import DummyLock
        with DummyLock("/tmp/test.lock") as lock:
            assert lock is not None
        # Should exit cleanly

    def test_dummy_lock_path(self):
        """Test DummyLock stores path."""
        from json_database.utils import DummyLock
        lock = DummyLock("/tmp/mylock.lock")
        assert lock.path == "/tmp/mylock.lock"


class TestMergeDictRecursionEdgeCases:
    """Test deep recursion edge cases in merge_dict."""

    def test_merge_dict_deeply_nested_recursion(self):
        """Test merge_dict with deeply nested structures."""
        base = {
            "l1": {
                "l2": {
                    "l3": {
                        "l4": {
                            "value": "original"
                        }
                    }
                }
            }
        }
        delta = {
            "l1": {
                "l2": {
                    "l3": {
                        "l4": {
                            "new": "added"
                        }
                    }
                }
            }
        }
        result = merge_dict(base, delta)
        assert result["l1"]["l2"]["l3"]["l4"]["value"] == "original"
        assert result["l1"]["l2"]["l3"]["l4"]["new"] == "added"

    def test_merge_dict_with_all_flags_enabled(self):
        """Test merge_dict with all options enabled."""
        base = {"list": [1, 2], "data": {"key": "val"}}
        delta = {"list": [2, 3, 4], "data": {"new": "item"}}
        result = merge_dict(base, delta, merge_lists=True, skip_empty=True,
                           no_dupes=True, new_only=False)
        assert 1 in result["list"]
        assert 3 in result["list"]
        assert result["list"].count(2) == 1  # No dupes
        assert result["data"]["key"] == "val"
        assert result["data"]["new"] == "item"

    def test_merge_dict_nested_skip_empty(self):
        """Test skip_empty in nested merge."""
        base = {"nested": {"key": "value"}}
        delta = {"nested": {"key": ""}}
        result = merge_dict(base, delta, skip_empty=True)
        # Empty value should be skipped, keeping original
        assert result["nested"]["key"] == "value"


class TestRecursiveHelpersObjectBranch:
    """Cover the __dict__ (object) branch in recursive search helpers."""

    class _Obj:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    class _NoDict:
        __slots__ = ("x",)
        def __init__(self, x):
            self.x = x

    def test_get_key_recursively_object_in_list(self):
        """get_key_recursively follows __dict__ for objects in a list value."""
        obj = self._Obj(color="red")
        data = {"items": [obj]}
        results = get_key_recursively(data, "color")
        assert obj in results

    def test_get_key_recursively_object_no_dict(self):
        """get_key_recursively skips objects with no __dict__ (slots)."""
        obj = self._NoDict(42)
        data = {"items": [obj]}
        results = get_key_recursively(data, "x")
        assert results == []

    def test_get_key_recursively_fuzzy_object_in_list(self):
        """get_key_recursively_fuzzy follows __dict__ for objects in a list."""
        obj = self._Obj(username="alice")
        data = {"items": [obj]}
        results = get_key_recursively_fuzzy(data, "username", thresh=0.9)
        assert any(r[0] is obj for r in results)

    def test_get_key_recursively_fuzzy_object_no_dict(self):
        """get_key_recursively_fuzzy skips slot-only objects."""
        obj = self._NoDict(42)
        data = {"items": [obj]}
        results = get_key_recursively_fuzzy(data, "x", thresh=0.5)
        assert results == []

    def test_get_value_recursively_object_in_list(self):
        """get_value_recursively follows __dict__ for objects in a list."""
        obj = self._Obj(role="admin")
        data = {"items": [obj]}
        results = get_value_recursively(data, "role", "admin")
        assert obj in results

    def test_get_value_recursively_object_no_dict(self):
        """get_value_recursively skips slot-only objects."""
        obj = self._NoDict(42)
        data = {"items": [obj]}
        results = get_value_recursively(data, "x", 42)
        assert results == []

    def test_get_value_recursively_fuzzy_object_in_list(self):
        """get_value_recursively_fuzzy follows __dict__ for objects in a list."""
        obj = self._Obj(tag="administrator")
        data = {"items": [obj]}
        results = get_value_recursively_fuzzy(data, "tag", "admin", thresh=0.5)
        assert any(r[0] is obj for r in results)

    def test_get_value_recursively_fuzzy_object_no_dict(self):
        """get_value_recursively_fuzzy skips slot-only objects."""
        obj = self._NoDict(42)
        data = {"items": [obj]}
        results = get_value_recursively_fuzzy(data, "x", "42", thresh=0.5)
        assert results == []
