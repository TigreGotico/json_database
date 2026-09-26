# Development

## Setting Up

```bash
git clone https://github.com/TigreGotico/json_database
cd json_database
pip install -e ".[test]"
# or with uv:
uv pip install -e ".[test]"
```

Install test requirements explicitly if the extras are not defined in setup.py:

```bash
pip install -r test/requirements.txt
pip install -e .
```

## Running Tests

```bash
pytest test/
```

Run with coverage:

```bash
pytest --cov=json_database --cov-report=term-missing test/
```

The CI gate requires 80% overall coverage:

```bash
pytest --cov=json_database --cov-fail-under=80 test/
```

## Test Suite

350 tests across 9 test modules. Typical execution time: ~1.3 seconds.

| Test file | What it covers |
|---|---|
| `test/test_storage.py` | `JsonStorage` load, save, lock, merge, context manager |
| `test/test_database.py` | `JsonDatabase` CRUD, search, item ID behaviour |
| `test/test_encrypted_storage.py` | `EncryptedJsonStorage` round-trip, key enforcement |
| `test/test_crypto.py` | `encrypt`/`decrypt`, `compress_payload`/`decompress_payload` |
| `test/test_query.py` | All `Query` filter methods and edge cases |
| `test/test_search.py` | `search_by_key` and `search_by_value` on `JsonDatabase` |
| `test/test_xdg.py` | XDG variant classes path resolution |
| `test/test_xdg_utils.py` | `xdg_utils.py` helper functions and env variable overrides |
| `test/test_exceptions.py` | Exception class hierarchy |

Shared fixtures (temp directories, sample databases) are in `test/conftest.py`.

## Coverage Summary

| Module | Coverage |
|---|---|
| `json_database/search.py` | 91% |
| `json_database/utils.py` | 81% |
| `json_database/__init__.py` | 65% |
| Overall | ~68% (local) / 80% gate in CI |

The CI workflow (`unit_tests.yml`) enforces `--cov-fail-under=80` on Python
3.10, 3.11, 3.12, and 3.13.

## CI Workflows

| Workflow | Trigger | Purpose |
|---|---|---|
| `unit_tests.yml` | PR to `dev`, push to `master` | Run tests with coverage on 4 Python versions |
| `build_tests.yml` | Any push | Verify `setup.py bdist_wheel` builds |
| `build-tests.yml` | PR to `dev`/`master`/`main` | Reusable build test via OpenVoiceOS automations |
| `lint.yml` | — | Code style checks |
| `pip_audit.yml` | — | Dependency vulnerability scan |
| `publish_stable.yml` | — | PyPI release |

Coverage is uploaded to Codecov from the Python 3.12 matrix job.

## Branching

- `dev` — main development branch; PRs target this branch.
- `master` — stable releases.

## Commit Style

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat: add fuzzy threshold parameter to Query.equal
fix: handle empty list in merge_dict when no_dupes=True
docs: sync API reference after EncryptedJsonStorage changes
test: add edge case for item_id shift after remove_item
```

## Adding a New Storage Class

1. Subclass the appropriate base (`JsonStorage` or `JsonDatabase`).
2. Override `__init__` to resolve the path and call `super().__init__(path, ...)`.
3. Add the class to `json_database/__init__.py` exports.
4. Add a test file under `test/`.
5. Update [API Reference](API.md) and [docs/index.md](index.md).

## Known Uncovered Code Paths

- `merge_item` and `replace_item` error paths in `JsonDatabase` — `match_strategy`
  parameter is accepted but not yet implemented.
- `DummyLock` detailed locking edge cases.

The HiveMind plugin adapter that used to live here as `json_database/hpm.py`
was extracted into
[`hivemind-json-db-plugin`](https://github.com/JarbasHiveMind/hivemind-json-db-plugin);
its tests now live in that repo.
