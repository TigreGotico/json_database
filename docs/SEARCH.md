# Search and Query

`json_database` provides two complementary search interfaces:

1. **`JsonDatabase` search methods** — recursive key/value search across the full
   database structure.
2. **`Query` builder** — chainable filters applied to a flat list of records.

---

## JsonDatabase Search Methods

### search_by_key

`json_database/__init__.py:372`

```python
db.search_by_key(key: str, fuzzy: bool = False, thresh: float = 0.7,
                 include_empty: bool = False) -> list
```

Recursively traverses all records and returns those that contain `key`.

- **Exact mode** (default): returns a `list` of dicts where the key is present
  (and non-empty unless `include_empty=True`).
- **Fuzzy mode** (`fuzzy=True`): returns a `list` of `(dict, score)` tuples
  sorted by descending similarity score. `thresh` sets the minimum score (0–1).

```python
# Find all records that have an "email" field
users = db.search_by_key("email")

# Fuzzy: find records with a key similar to "birth"
matches = db.search_by_key("birth", fuzzy=True, thresh=0.6)
for item, score in matches:
    print(score, item)  # e.g. 0.8, {"birthday": "12 May", ...}
```

### search_by_value

`json_database/__init__.py:377`

```python
db.search_by_value(key: str, value, fuzzy: bool = False, thresh: float = 0.7) -> list
```

Recursively traverses all records and returns those where `key == value`.

- **Exact mode**: returns a `list` of matching dicts.
- **Fuzzy mode**: returns a `list` of `(dict, score)` tuples sorted by
  descending score. Operates on string values and list-valued fields.

```python
# Exact match
admins = db.search_by_value("role", "admin")

# Fuzzy match — useful for approximate name searches
results = db.search_by_value("name", "jon", fuzzy=True)
for item, score in results:
    print(item["name"], score)  # e.g. "john"  0.857, "jones"  0.727
```

---

## Query Builder

`json_database/search.py:5`

The `Query` class provides a fluent interface for filtering a database's records.
Each method narrows `Query.result` and returns `self` for chaining. Call
`build()` at the end to get the final list.

```python
from json_database.search import Query

results = Query(db).equal("status", "active").above("score", 50).build()
```

`Query` can also be initialised from a single dict (treated as a one-element list):

```python
q = Query({"name": "Alice", "score": 90})
```

### Filter Methods

All filter methods accept `ignore_case: bool = False` unless noted otherwise.
When `ignore_case=True`, key and value comparisons are lowercased.

#### `contains_key(key, fuzzy=False, thresh=0.7, ignore_case=False)`

`json_database/search.py:42`

Keeps only records that have `key` set to a truthy value.

- `fuzzy=True`: uses `fuzzy_match` to find keys with similarity above `thresh`.

```python
Query(db).contains_key("email").build()
Query(db).contains_key("eml", fuzzy=True, thresh=0.6).build()
```

#### `contains_value(key, value, fuzzy=False, thresh=0.75, ignore_case=False)`

`json_database/search.py:65`

Keeps records where the field `key` contains `value`.

- For string fields: `value in field_value`.
- For list fields: `value` is an element of the list.
- For dict fields: `value` is a key of the dict.
- `fuzzy=True`: uses `fuzzy_match` / `match_one` to find approximate matches.

```python
# Items where tags list contains "python"
Query(db).contains_value("tags", "python").build()

# Fuzzy: items where description contains something close to "machne"
Query(db).contains_value("description", "machne", fuzzy=True).build()
```

#### `value_contains(key, value, ignore_case=False)`

`json_database/search.py:108`

Keeps records where the field `key`'s string/list representation contains
`value` as a substring or element (the inverse membership direction from
`contains_value`).

- For strings: `value in field_value` (substring check).
- For lists: `value in [str(x) for x in field_value]`.
- For dicts: `value in [str(k) for k in field_value.keys()]`.

```python
# Items where "name" field contains "bob" as substring
Query(db).value_contains("name", "bob", ignore_case=True).build()
```

#### `value_contains_token(key, value, fuzzy=False, thresh=0.75, ignore_case=False)`

`json_database/search.py:139`

Keeps records where the field `key` (a space-tokenised string or a list) contains
`value` as an exact token.

- `fuzzy=True`: uses `match_one` against the token list.

```python
# Items where "title" contains "noir" as a word (not just substring)
Query(db).value_contains_token("title", "noir", ignore_case=True).build()
```

#### `equal(key, value, ignore_case=False)`

`json_database/search.py:159`

Keeps records where `field[key] == value` (exact equality).

```python
Query(db).equal("status", "active").build()
Query(db).equal("country", "UK", ignore_case=True).build()
```

#### `below(key, value, ignore_case=False)`

`json_database/search.py:168`

Keeps records where `field[key] < value`.

#### `above(key, value, ignore_case=False)`

`json_database/search.py:173`

Keeps records where `field[key] > value`.

#### `below_or_equal(key, value, ignore_case=False)`

`json_database/search.py:178`

Keeps records where `field[key] <= value`.

#### `above_or_equal(key, value, ignore_case=False)`

`json_database/search.py:183`

Keeps records where `field[key] >= value`.

#### `in_range(key, min_value, max_value, ignore_case=False)`

`json_database/search.py:188`

Keeps records where `min_value < field[key] < max_value` (exclusive bounds on
both sides).

```python
# Movies with duration between 90 and 150 minutes (exclusive)
Query(db).in_range("duration", 90, 150).build()
```

#### `all()`

`json_database/search.py:193`

No-op. Returns `self` unchanged. Useful as a placeholder in conditional chains.

#### `build()`

`json_database/search.py:201`

Returns `self.result` — the current filtered list of records.

---

## Fuzzy Matching Internals

Fuzzy matching is powered by `difflib.SequenceMatcher` via the `fuzzy_match`
utility (`json_database/utils.py:38`). Scores are in `[0.0, 1.0]` where `1.0`
is a perfect match.

`match_one` (`json_database/utils.py:47`) selects the single best match from a
list or dict of candidates and returns `(best_match, score)`.

Default thresholds:

| Context | Default thresh |
|---|---|
| `search_by_key` fuzzy | 0.7 |
| `search_by_value` fuzzy | 0.7 |
| `Query.contains_key` fuzzy | 0.7 |
| `Query.contains_value` fuzzy | 0.75 |
| `Query.value_contains_token` fuzzy | 0.75 |

---

## Combining Methods

All `Query` methods can be chained freely. Each call is applied sequentially to
the current result set, so order matters for performance (put cheaper/narrower
filters first).

```python
results = (Query(db)
           .contains_key("price")          # only records with a price
           .above("price", 0)              # price > 0
           .below_or_equal("price", 100)   # price <= 100
           .equal("in_stock", True)
           .contains_value("tags", "sale", ignore_case=True)
           .build())
```
