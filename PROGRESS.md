# PROGRESS.md — Bumpguard Progress Tracker

## Status Summary
- **Current Phase**: v1.5 Milestone Complete — Evaluation Harness, CI/CD & ADR Portfolio
- **Overall Status**: Complete & Passing (35/35 automated tests pass)

---

## Roadmap Milestones Completed

### Option 1: v1.5 Evaluation Harness & Calibrated ML Model
- [x] Implemented manifest generator in `eval/manifest.py` with strict track separation:
  - Track 1: Diff Track (`compromised_lib` vs `benign`)
  - Track 2: New-Package Track (`malicious_intent` vs `benign`)
- [x] Implemented cluster-aware group splitting (`eval/splits.py`) preventing near-duplicate leakage
- [x] Implemented temporal time-based holdout splitting (`eval/splits.py`)
- [x] Implemented regularized logistic regression and Platt calibration (`eval/model.py`)
- [x] Exported calibrated parameters to `model_weights.json` and integrated with `bumpguard.score.scorer`
- [x] Implemented Wilson score 95% confidence intervals and PPV sensitivity analysis (`eval/metrics.py`)
- [x] Automated evaluation driver in `eval/run_eval.py` regenerating `eval/results/results.json`
- [x] Authored and verified unit tests in `tests/test_eval.py`

### Option 2: Live CI/CD Automation
- [x] Authored `.github/workflows/ci.yml` with least-privilege permissions
- [x] Integrated automated test execution (`python run_tests.py`)
- [x] Integrated evaluation smoke test execution (`python -m eval.run_eval`)
- [x] Integrated CLI diff verification and SARIF output generation checks

### Option 3: Architectural Decision Records & Interview Guide
- [x] Authored ADR `001-diff-first-architecture.md`
- [x] Authored ADR `002-calibrated-scoring-and-alert-budget.md`
- [x] Authored ADR `003-safe-in-memory-extraction.md`
- [x] Created comprehensive rehearsal interview guide in `docs/INTERVIEW_GUIDE.md`
- [x] Embedded empirical evaluation tables with Wilson confidence intervals in `README.md`

---

## Batch History (v1 & MVP Phases)

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
