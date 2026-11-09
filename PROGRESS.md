# PROGRESS.md — Bumpguard Progress Tracker

## Status Summary
- **Current Phase**: v1 Scope Complete & Verified (Batches 8–10 Finished)
- **Overall Status**: Complete & Passing (31/31 automated tests pass)

---

## v1 Milestone Checklist

### Batch 8: Configuration & Expiring Ignore Rules (`bumpguard.toml`)
- [x] Implemented `bumpguard.toml` parser and policy controls in `bumpguard.config`
- [x] Implemented expiring ignore rules (`[[ignore]] package, rule, expires, reason`)
- [x] Verified expired ignore rules force security review and are not silently skipped
- [x] Authored unit tests in `tests/test_config.py`

### Batch 9: SARIF v2.1.0 Output Generation (`results.sarif`)
- [x] Implemented standard SARIF v2.1.0 generator in `bumpguard.report.sarif`
- [x] Mapped rule definitions, locations, and severities (`error`, `warning`, `note`) for GitHub Code Scanning
- [x] Added `--format sarif` and `--sarif-file` CLI flags
- [x] Authored unit tests in `tests/test_sarif.py`

### Batch 10: PyPI Ecosystem Support
- [x] Implemented safe in-memory `.whl` (ZIP) extractor with path traversal protections in `bumpguard.extract.wheel_extractor`
- [x] Implemented Python fact patterns and `.pth` persistence hook detection (`BG-EXEC-003`) in `bumpguard.analyze.python_analyzer`
- [x] Implemented `requirements.txt` dependency parser in `bumpguard.lockfile.pypi_parser`
- [x] Authored unit tests in `tests/test_pypi.py`

---

## Batch History (MVP Phase)

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

### Batch 6: Frontend Web Visualizer & Integration
- [x] Built modern security dashboard in `frontend/` (`index.html`, `styles.css`, `app.js`)
- [x] Interactive lockfile diff inspector with pre-loaded demo scenario
- [x] Executive KPI cards (Scanned, Needs Review, Clean, Removed)
- [x] Filtering, badge coloring, and code evidence drawer for findings
- [x] Seamless integration: `bumpguard serve` serves the frontend while running `/api/scan` backend
- [x] Added automated server integration test suite (`tests/test_server.py`) with 25 total passing tests

### Batch 7: Action, Documentation & End-to-End Verification
- [x] Created Composite GitHub Action in `action/action.yml`
- [x] Authored `SECURITY.md` detailing static analysis non-execution invariants and vulnerability disclosure
- [x] Authored comprehensive `README.md` with pipeline overview, quickstart CLI commands, and explicit limitations
- [x] Added sample lockfiles in `samples/` (`old-lock.json`, `new-lock.json`) for immediate evaluation
- [x] Added root-level test runner `run_tests.py` (`python run_tests.py`)
- [x] Improved CLI error reporting when file paths are missing on disk
- [x] Complete test suite passing: 25/25 automated unit & integration tests

---

## Current Task
- **Active Task**: All MVP Batches complete. Project ready for production use, pull request scanning, or local web inspection.
- **Future Enhancements (v1)**: PyPI support, SARIF format, and expiring ignore rules.

---

## Blockers & Open Issues
- None.
