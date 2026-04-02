# Plan: Performance Improvements

Based on profiling findings. Ranked by impact (critical → minor).

## Implementation Steps

1. **`__len__` O(1) via `_active_count`** (`__init__.py`)
   - Add `_active_count: int` attribute to `JsonDatabase.__init__`, computed from the loaded list
   - Increment in `append`
   - Decrement in `remove_item`
   - Recompute in `__init__` after `load_local` and in `reset()` after `db.reload()`
   - Change `__len__` to return `self._active_count`

2. **`Query.__init__` lazy — no `list(db)` copy** (`search.py`)
   - Store `db.db[db.name]` directly instead of `list(db)`
   - All filter methods already iterate `self.result`; change them to skip tombstones inline
   - `build()` materialises to a plain list (filters already produce lists, so build() stays as-is)
   - For the single-dict (non-db) init path, wrap in a list as before

3. **`contains_value` single-pass — remove pre-filter** (`search.py`)
   - Remove the `self.contains_key(key, ignore_case=ignore_case)` call at line 91
   - Inline `_resolve_key` / `_get_value` with a `try/except KeyError` inside the loop

4. **`fuzzy_match` lru_cache** (`utils.py`)
   - Add `@functools.lru_cache(maxsize=4096)` to `fuzzy_match`

5. **`uncomment_json` compiled regex** (`utils.py`)
   - Add `_COMMENT_RE = re.compile(r'^\s*(//|#)')` at module level
   - Replace `lstrip()` + `startswith` checks with `_COMMENT_RE.match(line)`

6. **`jsonify_recursively` scalar short-circuit** (`utils.py`)
   - Add early return for non-dict, non-list, no-`__dict__` values

## Commit order
Steps 1 → 2 → 3 → 4 → 5 → 6 (each step = one commit)
