# Decisions: Test Coverage and Documentation

| Decision | Alternatives Considered | Rationale |
| :--- | :--- | :--- |
| **Use real temp files in tests, not mocks** | Mock JsonStorage.store/load | JsonStorage is fundamentally a file I/O library; mocking defeats the purpose of testing. Real temp files verify actual persistence, encoding, and lock behavior. |
| **pytest-cov with --cov-fail-under=80** | 70% threshold, or no automated enforcement | 80% provides meaningful coverage for a production library without being pedantic. Automated enforcement prevents coverage regressions. |
| **Test Python 3.10–3.13 (drop 3.9)** | Keep 3.9, test 3.8–3.13 | Python 3.9 reaches EOE Oct 2025 (soon). 3.10+ covers active support window. New typing features (PEP 604, PEP 673) are widely used in 3.10+. |
| **Separate test files by module (storage, database, query, search)** | Single monolithic test file | Mirrors project structure; easier to navigate; scales for future additions. Each module has distinct concerns. |
| **Add docstrings inline (no separate docs/ folder)** | Create docs/API.md | Docstrings stay with code; inline docstrings + README cover most use cases. Separate docs folder introduces sync burden. |
| **Expand README with 4 sections, not rewrite** | Rewrite README from scratch | Preserve existing content and structure; append new sections. Minimal disruption, easier code review. |
| **Document item_id ephemeral nature with explicit WARNING** | Silently accept the limitation | Users storing item_id externally face silent data corruption. Explicit warnings in code and docs are mandatory. |
| **Do NOT fix item_id or add UUIDs (architectural change)** | Implement stable IDs now | Breaking change → requires major version bump. Out of scope for this task (listed as non-goal). Defer to next major release. |
| **Use conftest.py for shared fixtures** | Duplicate fixtures in each test file | Single source of truth; reduces boilerplate; easier to maintain. Standard pytest pattern. |
