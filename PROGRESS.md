# PROGRESS.md — Bumpguard Progress Tracker

## Status Summary
- **Current Phase**: Batch 2 Complete — Core Types & Safe In-Memory Extractor
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

---

## Current Task
- **Active Task**: Batch 2 complete.
- **Next Task (Batch 3)**: Lockfile Parser & Diff Engine (`package-lock.json` parsing and version diffing) + Registry Client.

---

## Blockers & Open Issues
- None.
