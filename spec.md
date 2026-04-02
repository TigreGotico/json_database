# Spec: Performance Improvements

## Objective
Eliminate the dominant CPU bottlenecks identified by cProfile profiling: an O(n) `__len__` that executes on every insert, an O(n) `list(db)` copy on every `Query` construction, a redundant double-pass in `contains_value`, and per-line string operations in `uncomment_json`. Each improvement must be measurable and must not change observable behaviour.

## Functional Requirements

### Critical

1. `JsonDatabase.__len__` MUST return in O(1) time by maintaining a `_active_count` integer attribute, incremented on `append` and decremented on `remove_item`.
2. `_active_count` MUST be recomputed from scratch after `load_local` (disk load) and `reset()`, so it stays correct across reloads.
3. `_active_count` MUST NOT include tombstone slots.
4. `add_item` documentation MUST note that callers performing bulk inserts of known-unique items SHOULD pass `allow_duplicates=True` to avoid the O(n) duplicate scan; no code change is required for this item.
5. `Query.__init__` MUST NOT materialise the entire database with `list(db)`; it MUST store a direct reference to the raw item list and apply tombstone filtering lazily during filter passes.
6. All `Query` filter methods MUST still yield only non-tombstone items (tombstones MUST be skipped during iteration).
7. `Query.build()` MUST return a plain `list` (not a generator or iterator), preserving backward compatibility.

### Major

8. `Query.contains_value` MUST NOT call `self.contains_key` as a pre-filter pass; key presence MUST be checked inline during the single value-matching pass.
9. `fuzzy_match` results MUST be cached using `functools.lru_cache` so repeated calls with the same `(x, against)` pair are served from cache rather than recomputed.

### Minor

10. `uncomment_json` MUST strip `//` and `#` comment lines using a single compiled regular expression rather than per-line `lstrip()` + `startswith()` calls.
11. The compiled regex MUST be a module-level constant (`_COMMENT_RE = re.compile(r'^\s*(//|#)')`) compiled once per process.
12. `jsonify_recursively` MUST short-circuit for values that are already plain scalars (non-dict, non-list, no `__dict__`) without descending further.

### Invariants

13. All existing tests MUST continue to pass after each change.
14. No public API signatures MUST change.

## Non-Goals

- Persistent index structures or secondary indices for `search_by_key` / `search_by_value`.
- Parallelising or batching disk I/O.
- Depth-limit or cycle-detection guard in recursive search helpers (separate safety concern).
- Changing `__contains__` to skip `jsonify_recursively` (correctness risk outweighs perf gain).

## Interfaces & Contracts

- `JsonDatabase.__len__` — returns `int`; value MUST equal `sum(1 for _ in db)` at all times.
- `JsonDatabase._active_count` — private `int` attribute; not part of public API but MUST be consistent.
- `Query.result` — public `list` attribute; `build()` returns it; callers may index and mutate it.
- `uncomment_json(commented_json_str: str) -> str` — unchanged signature and semantics.
- `fuzzy_match(x: str, against: str) -> float` — unchanged signature; cache is transparent to callers.

## Acceptance Criteria

- [ ] `len(db)` returns the correct count after `add_item`, `remove_item`, `reset()`, and a fresh `__init__` that loads an existing file.
- [ ] `len(db)` is served from `_active_count` without iterating the raw list (verified by asserting `db._active_count == len(db)` and that `_active_count` is an `int`).
- [ ] Calling `len(db)` 1 000 times on a 1 000-item database completes in under 1 ms (timing assertion or equivalent).
- [ ] `Query(db)` construction does not allocate a new list copy of the database (verified by asserting `Query(db).result is db.db[db.name]` or equivalent direct reference check).
- [ ] `Query(...).build()` returns a `list` instance.
- [ ] All existing `Query` filter tests pass, confirming tombstone items are excluded from results.
- [ ] `contains_value` does not call `contains_key` internally (verified by unit test or code inspection).
- [ ] `fuzzy_match` called twice with identical arguments returns the same result and hits the `lru_cache` (verified via `fuzzy_match.cache_info().hits > 0` after second call).
- [ ] `uncomment_json` strips `//` and `#` comment lines correctly for all existing test inputs.
- [ ] `uncomment_json` uses a module-level compiled `re.Pattern` (verified by grep for `re.compile` in `utils.py`).
- [ ] `jsonify_recursively` returns the input value unchanged for plain scalars (int, float, str, bool, None) without entering any branch.
- [ ] `python -m pytest` passes with no regressions.

## Functional Requirements

1. **Write unit tests for JsonStorage** — verify dict-like interface, file I/O, persistence across sessions, and key/value validation.
2. **Write unit tests for JsonDatabase** — verify CRUD operations (add_item, remove_item, update_item), list representation, and item iteration.
3. **Write unit tests for Query builder** — verify filter composition, chainability, and correctness of result filtering (exact match, fuzzy match, recursive key/value search).
4. **Write unit tests for search utilities** — verify fuzzy matching, key/value recursion, and empty/edge cases.
5. **Expand CI to test Python 3.10, 3.11, 3.12, 3.13** — ensure compatibility across current supported versions.
6. **Document the Query API in README** — explain filter(), filter_fuzzy(), and_(), or_() with examples.
7. **Document EncryptedJsonStorage in README** — explain AES-GCM encryption, key derivation, and when to use it.
8. **Document XDG path management in README** — explain XDGJsonStorage and when it applies.
9. **Document the HiveMind plugin in README** — explain the entry-point and integration context.
10. **Add docstrings to all public classes and methods** — explain purpose, parameters, return types, and known limitations.
11. **Document silent AES key truncation behavior** — clarify that keys > 16 bytes are silently sliced.
12. **Document item_id ephemeral nature** — clearly warn that item IDs are not stable across sessions and should not be persisted externally.

## Non-Goals

- Refactoring or replacing item_id with stable UUIDs (architectural change — future breaking release).
- Refactoring core search logic.
- Migrating from setup.py to pyproject.toml (separate packaging modernization task).
- Lazy-importing ovos_utils (separate import-safety task).
- Removing or changing the TODO placeholders in match_item/merge_item/replace_item (design decision pending).

## Interfaces & Contracts

- **Test framework:** pytest (existing in dev dependencies).
- **Coverage tool:** pytest-cov (measure and report line coverage).
- **CI environment:** GitHub Actions (modify .github/workflows/test.yml to expand Python version matrix).
- **Documentation format:** Markdown (README.md).

## Acceptance Criteria

- [ ] All core modules have ≥80% line coverage measured by pytest-cov.
- [ ] JsonStorage tests cover persistence, dict operations, and file I/O (≥15 test cases).
- [ ] JsonDatabase tests cover CRUD, list representation, iteration (≥20 test cases).
- [ ] Query builder tests cover filter composition, chainability, exact/fuzzy matching (≥25 test cases).
- [ ] Search utility tests cover fuzzy matching and recursion (≥10 test cases).
- [ ] EncryptedJsonStorage tests unchanged; coverage remains ≥90%.
- [ ] CI matrix includes Python 3.10, 3.11, 3.12, 3.13; all versions pass.
- [ ] README contains a new "Query API" section with code examples.
- [ ] README contains a new "Encryption" section explaining EncryptedJsonStorage.
- [ ] README contains a new "XDG Paths" section explaining XDGJsonStorage.
- [ ] README contains a new "HiveMind Integration" section.
- [ ] All public classes and public methods have docstrings (no bare `def`s).
- [ ] Documentation explicitly warns about item_id instability and AES key truncation.
- [ ] Test suite runs in under 10 seconds (local dev feedback loop).
