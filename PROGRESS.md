# PROGRESS.md — Bumpguard Progress Tracker

## Status Summary
- **Current Phase**: Batch 5 Complete — CLI, Markdown / JSON Reporters, and Local API Server
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

### Batch 4: Code Fact Extraction, Diff Engine & Risk Scorer
- [x] Implemented `FactExtractor` pattern matching for JavaScript/Node.js facts:
  - `BG-CODE-001` (network access)
  - `BG-CODE-002` (process execution)
  - `BG-CODE-003` (dynamic eval)
  - `BG-CODE-005` (sensitive files and env token reads)
  - `BG-CODE-006` (self-propagating worm publication)
- [x] Implemented `compare_package_archives` diff engine:
  - Skips identical files by SHA256
  - Detects `BG-EXEC-001` (lifecycle scripts) and `BG-EXEC-002` (`binding.gyp`)
  - Computes `new_facts - old_facts` keyed by `(kind, api, context)`
- [x] Implemented v0 heuristic scorer in `bumpguard.score.scorer` with rule weights and critical overrides
- [x] Authored and verified unit test suites (`tests/test_analyzer.py`, `tests/test_scorer.py`) with 17 total passing tests

### Batch 5: CLI, Reporters, and Local API Server
- [x] Implemented Markdown PR table generator matching Section 7.5 format (`bumpguard.report.reporter`)
- [x] Implemented JSON report serialization (`bumpguard.report.reporter`)
- [x] Implemented embedded HTTP server in `bumpguard.server` with `/api/scan`, `/api/health`, and static asset serving
- [x] Implemented CLI entry point in `bumpguard.cli` with `diff` and `serve` commands
- [x] Authored and verified unit test suites (`tests/test_report.py`, `tests/test_cli.py`) with 22 total passing tests

---

## Current Task
- **Active Task**: Batch 5 complete.
- **Next Task (Batch 6)**: Frontend Web Dashboard in `frontend/` & Integration with `bumpguard serve`.

---

## Blockers & Open Issues
- None.
