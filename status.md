# Status: Performance Improvements

## Checklist

- [x] 1. `__len__` O(1) via `_active_count` (`__init__.py`)
- [x] 2. `Query.__init__` lazy — no `list(db)` copy (`search.py`)
- [x] 3. `contains_value` single-pass — remove pre-filter (`search.py`)
- [x] 4. `fuzzy_match` lru_cache (`utils.py`)
- [x] 5. `uncomment_json` compiled regex (`utils.py`)
- [x] 6. `jsonify_recursively` scalar short-circuit (`utils.py`)
- [x] 7. Add missing tests for `_active_count`, O(1) `__len__` timing, `fuzzy_match` cache hits
- [x] 8. Clean up `spec.md` — remove stale test-coverage block, align criterion 5 with implementation
