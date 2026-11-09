# PROGRESS.md — Bumpguard Progress Tracker

## Status Summary
- **Current Phase**: Batch 3 Complete — Lockfile Parsing, Diff Engine & Registry Client
- **Overall Status**: In Progress (MVP Phase)

---

## Batch History

### Batch 1: Project Setup & Control Documents
- [x] Initialized project root at `bumpguard/`
- [x] Created `AGENTS.md` (boundaries, safety rules, implementer role)
- [x] Created `PROJECT_SPEC.md` (frozen MVP scope, backend/frontend architecture)
- [x] Created `PROGRESS.md` (progress tracker and active task ledger)
- [x] Initialized git repository and directory structure (`backend/`, `frontend/`)

### Batch 2: Core Types & Safe Extractor
- [x] Implemented core domain models in `bumpguard.core.types` (`Ecosystem`, `PackageRef`, `FactKind`, `Context`, `Fact`, `Finding`, `Severity`)
- [x] Implemented safe in-memory archive extraction in `bumpguard.extract.safe_extractor`
- [x] Built `safe_path` sanitization enforcing zero path traversal (`..`), rejection of absolute paths, and Windows reserved devices
- [x] Enforced decompression bomb mitigations (size, file count, expansion ratio limits)
- [x] Authored and verified unit test suites (`tests/test_core.py`, `tests/test_extract.py`) with 8 passing tests

### Batch 3: Lockfile Parsing, Diff Engine & Registry Client
- [x] Implemented `parse_package_lock` supporting lockfileVersion 1, 2, and 3 (`bumpguard.lockfile.parser`)
- [x] Implemented lockfile version diffing logic (`bumpguard.lockfile.diff`)
- [x] Implemented `NpmRegistryClient` for fetching packument metadata and checking:
  - `BG-META-001` (publisher / maintainer change)
  - `BG-META-003` (fresh release < 72h)
  - `BG-POL-003` (missing integrity)
- [x] Authored and verified unit test suites (`tests/test_lockfile.py`, `tests/test_registry.py`) with 11 total passing tests

---

## Current Task
- **Active Task**: Batch 3 complete.
- **Next Task (Batch 4)**: Code Fact Extraction (AST/Pattern Analyzer) & Fact-Set Difference Scorer.

---

## Blockers & Open Issues
- None.
