# Status: Improve Test Coverage to 80%

## Checklist

### New Test Files
- [x] Create `test/test_exceptions.py` — exception class tests (InvalidItemID, DatabaseNotCommitted, SessionError, MatchError)
- [x] Create `test/test_xdg_utils.py` — xdg path helper tests (xdg_cache_home, xdg_data_home, xdg_config_home)

### Expanded Tests
- [ ] Expand `test/test_storage.py` — error handling (reload failure, store errors, logging)
- [ ] Expand `test/test_database.py` — match/merge/replace strategies and edge cases
- [x] Expand `test/test_search.py` — merge_dict recursion, uncomment_json comments, fuzzy thresholds

### Query Fuzzy Matching Coverage
- [ ] Add Query fuzzy matching edge cases (threshold boundaries, type coercion)
- [ ] Test equal() with ignore_case and special characters
- [ ] Test comparison operators (below, above) with type mismatches

### Verification
- [ ] Run `pytest --cov=json_database --cov-fail-under=80` and verify target achieved
- [ ] Confirm all existing tests still pass
- [ ] Document coverage improvement results

---

## Blockers

None.

---

## Notes

- Target: 80% overall coverage (from 53%)
- Focus areas: exception handling, recursion branches, fuzzy matching, type coercion
- Each gap should have at least one corresponding test
- No refactoring — test-only changes
