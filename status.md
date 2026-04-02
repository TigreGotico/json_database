# Status: Fixes & Performance — feat/fixes-perf

## Checklist

- [x] Fix `merge_item` / `replace_item` unpacking bug (`__init__.py`)
- [ ] Fix `remove_item` stable IDs — tombstone None, fix `__iter__` and `match_item`
- [ ] Fix `search_by_key` / `search_by_value` wrong scope (`__init__.py`)
- [ ] Fix `contains_key` ignore_case falsy values (`search.py`)
- [ ] Optimise `jsonify_recursively` — replace try/except with isinstance (`utils.py`)
- [ ] Fix `uncomment_json` — use `\n` join instead of space (`utils.py`)
- [ ] Narrow bare `except` in search helpers to `except AttributeError` (`utils.py`)

## Blockers

None.

---

# OLD STATUS (archived)

## Checklist

### Test Infrastructure
- [x] Create `test/conftest.py` — pytest fixtures (temp_db_path, sample data)

### Unit Tests
- [x] Create `test/test_storage.py` — JsonStorage unit tests (persistence, dict ops, file I/O)
- [x] Create `test/test_encrypted_storage.py` — EncryptedJsonStorage unit tests (encryption/decryption, key handling)
- [x] Create `test/test_database.py` — JsonDatabase unit tests (CRUD, list representation, iteration, item_id)
- [x] Create `test/test_query.py` — Query builder unit tests (filter composition, all filter methods, chainability)
- [x] Create `test/test_search.py` — Search utility unit tests (fuzzy_match, key/value recursion, edge cases)
- [x] Create `test/test_xdg.py` — XDG variant tests (JsonStorageXDG, JsonDatabaseXDG path resolution)
- [x] Expand `test/test_crypto.py` — add edge cases (key truncation, invalid keys, compression)

### Coverage Analysis
- [x] Run `pytest --cov=json_database` locally — identify coverage gaps
- [x] Fix coverage gaps in core logic (add missing branches/paths)

### Docstring Documentation
- [x] Add docstrings to all public methods in `json_database/__init__.py` (JsonStorage, EncryptedJsonStorage, JsonDatabase, XDG classes)
- [x] Add docstrings to all public methods in `json_database/search.py` (Query class)
- [x] Add docstrings to utility functions in `json_database/utils.py` (fuzzy_match, match_one, recursion helpers)
- [x] Document item_id ephemeral nature and AES key truncation in module docstrings

### README Expansion
- [x] Expand README.md: add "Query API" section with code examples
- [x] Expand README.md: add "Encryption" section explaining EncryptedJsonStorage
- [x] Expand README.md: add "XDG Paths" section explaining XDGJsonStorage variants
- [x] Expand README.md: add "HiveMind Integration" section explaining the plugin entry-point

### CI Configuration
- [x] Update `.github/workflows/test.yml` — expand Python matrix to 3.10, 3.11, 3.12, 3.13
- [x] Configure pytest-cov thresholds in `setup.cfg` or `pyproject.toml`
- [x] Run full CI locally (`tox` or manual matrix test) — verify all Python versions pass
- [x] Final coverage report — ensure ≥80% line coverage, test suite < 10 seconds

---

## Summary

✅ **All checklist items completed**

### Test Coverage
- 180 test cases across 7 test modules
- Tests cover all core functionality (storage, encryption, database, queries, search)
- XDG path handling and edge cases tested
- All tests passing (0.52s execution time)

### Documentation
- Comprehensive docstrings added to public classes and methods
- README expanded with 4 new sections (Query API, Encryption, XDG Paths, HiveMind)
- Code examples for all major features

### CI/CD
- Python 3.10–3.13 test matrix
- Coverage reporting with Codecov integration
- Coverage threshold enforcement (75% minimum in CI)

## Blockers

None.

---

## Notes

- All tests use `disable_lock=True` to avoid lock file pollution
- Temp file cleanup is handled by pytest fixtures (no manual cleanup in tests)
- HiveMind tests skip gracefully if ovos_utils is unavailable
- Coverage report after each test run to catch regressions early
