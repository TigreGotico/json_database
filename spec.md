# Spec: Performance Improvements

## Objective
Eliminate the dominant CPU bottlenecks identified by cProfile profiling: an O(n) `__len__` that executes on every insert, an O(n) `list(db)` copy on every `Query` construction, a redundant double-pass in `contains_value`, and per-line string operations in `uncomment_json`. Each improvement must be measurable and must not change observable behaviour.

## Functional Requirements

### Critical

1. `JsonDatabase.__len__` MUST return in O(1) time by maintaining a `_active_count` integer attribute, incremented on `append` and decremented on `remove_item`.
2. `_active_count` MUST be recomputed from scratch after `load_local` (disk load) and `reset()`, so it stays correct across reloads.
3. `_active_count` MUST NOT include tombstone slots.
4. `add_item` documentation MUST note that callers performing bulk inserts of known-unique items SHOULD pass `allow_duplicates=True` to avoid the O(n) duplicate scan; no code change is required for this item.
5. `Query.__init__` MUST NOT use `list(db)` (which invokes the full `__iter__` protocol); it MUST iterate `db.db[db.name]` directly, skipping tombstone slots, so active items are collected without the `__iter__` overhead.
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
- [ ] `Query(db)` construction does not use `list(db)` (verified by asserting that tombstones are excluded from `query.result` and that the implementation iterates `db.db[db.name]` directly).
- [ ] `Query(...).build()` returns a `list` instance.
- [ ] All existing `Query` filter tests pass, confirming tombstone items are excluded from results.
- [ ] `contains_value` does not call `contains_key` internally (verified by unit test or code inspection).
- [ ] `fuzzy_match` called twice with identical arguments returns the same result and hits the `lru_cache` (verified via `fuzzy_match.cache_info().hits > 0` after second call).
- [ ] `uncomment_json` strips `//` and `#` comment lines correctly for all existing test inputs.
- [ ] `uncomment_json` uses a module-level compiled `re.Pattern` (verified by grep for `re.compile` in `utils.py`).
- [ ] `jsonify_recursively` returns the input value unchanged for plain scalars (int, float, str, bool, None) without entering any branch.
- [ ] `python -m pytest` passes with no regressions.

