# Workspace Audit — tigregotico/json_database

**Audited:** 2026-04-02
**Repos surveyed:** 1

---

## Summary

| Repo | Last Commit | Stars | Primary | Secondary |
|---|---|---|---|---|
| json_database | 2025-12 | N/A | MODERNIZE | needs-tests, needs-packaging, dependency-risk, interesting-to-outsiders |

---

## MODERNIZE

### json_database
> Pure-Python persistent dict with fuzzy search, AES encryption, and HiveMind plugin integration.

**Current state:** The core idea is genuinely useful and the implementation is clean. `JsonStorage` as a subclass of `dict` is an ergonomic design choice. `JsonDatabase` wraps it into a searchable list-of-records store. Recursive key/value search with optional fuzzy matching via `SequenceMatcher` is a nice touch. The `Query` builder in `search.py` adds a composable filter API that goes well beyond the basic search methods. `EncryptedJsonStorage` (AES-GCM with zlib compression) is a meaningful differentiator — most "json persistence" libraries do not ship this. The HiveMind plugin entry-point (`hivemind-json-db-plugin`) shows the library is genuinely integrated into a larger ecosystem.

**What's stale / what needs work:**

1. **Packaging is `setup.py` only.** No `pyproject.toml`. In 2026 this is a maintenance liability and signals an unmaintained project to anyone scanning PyPI.
2. **Test coverage is dangerously thin.** Exactly one test file (`test/test_crypto.py`) covers only `EncryptedJsonStorage`. The core `JsonDatabase`, `JsonStorage`, `Query`, and all search utilities have zero automated tests. CI only runs against Python 3.9 — two major versions behind current.
3. **`item_id` is explicitly ephemeral.** The code documents this: "WARNING: this is not immutable across sessions." Any caller storing item IDs externally has a silent data-corruption hazard. This limitation is buried in docstrings.
4. **AES key silently truncates.** Keys longer than 16 bytes are silently sliced to 16 (`key = key[0:16]`). Not documented anywhere visible.
5. **`pycryptodomex` is import-silenced.** `AES = None` if neither `pycryptodomex` nor `pycryptodome` is installed; the failure only surfaces at runtime.
6. **`combo_lock` is the sole hard dependency** — low visibility, no obvious maintenance signal.
7. **`hpm.py` imports `ovos_utils` at module level** but `ovos_utils` is not in `requirements.txt`. Any import of `json_database.hpm` without the full OVOS stack raises `ImportError` with no actionable message.
8. **`Query` API, `EncryptedJsonStorage`, and XDG classes are completely absent from the README.**
9. **`match_item`/`merge_item`/`replace_item` have `# TODO` placeholders** for unimplemented strategy parameters that are currently silently ignored.

**Effort estimate:** Medium. Packaging migration is mechanical (~2 hours). Meaningful test coverage is ~1-2 days. The `item_id` stability problem is architectural and requires a breaking change.

**Worth it because:** This library is already deployed as a HiveMind ecosystem plugin. It ships on PyPI. The combination of persistent dict + fuzzy search + optional AES encryption + XDG-aware paths is a coherent and useful toolset for lightweight storage in voice assistant and IoT contexts. Modernizing packaging and filling out tests would make it trustworthy enough to recommend confidently beyond the OVOS ecosystem.

---

## Cross-cutting observations

The library does more than it advertises. The README never mentions AES encryption, the `Query` builder API, XDG path management, or the HiveMind plugin. A developer scanning PyPI for a solution to any of those specific needs will miss this library entirely.

The test gap is the most serious problem. One test file covering only encryption means every refactor, every Python version bump, and every dependency update runs blind. The CI configuration testing only Python 3.9 means the library may already be broken on 3.12+ with no signal.

The `item_id` design is a latent correctness bug. Index-based IDs that shift when items are removed produce silent data corruption hazards for any downstream consumer in the HiveMind ecosystem that persists an item_id to disk and reloads it after a deletion.

The uncomfortable truth: this library exists largely to serve the OVOS/HiveMind voice assistant ecosystem and that is essentially its only real deployment context. Outside that ecosystem, `json_database` competes directly with `tinydb` — which has stable IDs, a more mature query language, and active development. The library needs either a stronger differentiation story or it should be understood as an OVOS/HiveMind internal utility dressed up as a general-purpose package.

Renovate was only just added (December 2025). Dependency update automation is better than nothing, but does not substitute for tests that can validate whether a bump breaks anything.

---

## Recommended next actions

1. **Archive:** Nothing to archive.
2. **Modernize first:** Migrate to `pyproject.toml`; expand CI to Python 3.10–3.13; write tests for `JsonDatabase`, `JsonStorage`, `Query`, and search utilities; fix silent AES key truncation; lazy-import `ovos_utils` in `hpm.py`; move `pycryptodomex` to an optional extras group.
3. **Invest in:** Stable item IDs (UUID assigned at `add_item` time); README sections for `Query`, `EncryptedJsonStorage`, and XDG classes; `CONTRIBUTING.md`.
4. **Writeup candidates:** None. The library is a competent combination of known patterns, not a novel contribution.
