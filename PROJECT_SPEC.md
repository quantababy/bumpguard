# PROJECT_SPEC.md — Bumpguard Specification

## 1. Project Overview
`bumpguard` is a fast, safe dependency update risk scanner that inspects dependency upgrades in pull requests and lockfile updates, comparing the old and new releases to flag only **new and risky behaviour**.

---

## 2. Target Architecture
The project is organized into two primary folders, integrated into a unified tool:
1. `backend/`: Rust workspace containing core types, lockfile parser, registry client, safe extractor, AST analyzer, prior scorer, report generators, and CLI / embedded server.
2. `frontend/`: Single-page visual interface (SPA) that displays interactive dependency risk reports, diff breakdowns, and evidence snippets, served directly by `bumpguard serve` or deployable standalone.

---

## 3. MVP Scope (Frozen)

### Must-Have
- **Ecosystem**: `npm` with `package-lock.json` parsing and version diffing (`base..head`).
- **Registry Integration**: Fetch metadata from npm registry (tarball URLs, integrity hashes, publish timestamps, maintainer lists).
- **Safe In-Memory Extraction**:
  - Raw archive extraction in memory with limits (max 50MB tarball, max 200MB unpacked, max 10k files).
  - Strict path sanitization rejecting `..`, absolute paths, symlinks.
- **Fact-Set Diff Engine**:
  - Hashing to skip unchanged files.
  - AST / pattern extraction of signals:
    - `BG-CODE-001`: Network calls (`http`, `https`, `net`, `dns`, `fetch`).
    - `BG-CODE-002`: Process execution (`child_process`, `exec`, `spawn`).
    - `BG-CODE-003`: Dynamic evaluation (`eval`, `new Function`, `vm`).
    - `BG-CODE-005`: Credential & sensitive file access (`.npmrc`, `.env`, SSH keys).
    - `BG-EXEC-001`: Install lifecycle scripts (`preinstall`, `install`, `postinstall`).
    - `BG-EXEC-002`: Build hook execution (`binding.gyp` presence).
  - Context tagging: `Install`, `Build`, `Import`, `Other`.
  - Fact diffing: `new_facts - old_facts`.
- **Scoring**: v0 heuristic scoring using rule priors weighted by execution context.
- **CLI Commands**:
  - `bumpguard diff --base <base> --head <head> [--fail-on <level>]`
  - `bumpguard serve [--port <port>]` (serves the integrated web UI)
- **Output Formats**: Markdown summary table, JSON report, CI exit codes (0 = pass, 1 = flagged findings, 2 = error).
- **Frontend Dashboard**: Visual report viewer to view scan results, filter by risk level, and inspect code evidence.

### Out of Scope (Deferred)
- PyPI / Python wheels and `.pth` parsing (v1).
- SARIF export and GitHub code scanning integration (v1).
- Expiring ignore list and `bumpguard.toml` configuration (v1).
- Machine learning / logistic regression & Platt scaling (v1.5).
- Hosted cloud backend, live sandboxing, or arbitrary binary execution.

---

## 4. Acceptance Criteria
1. Safe extraction unit & property tests pass; traversal paths like `../../etc/passwd` are safely dropped.
2. A synthetic lockfile bump correctly flags new dangerous code while ignoring unchanged dependencies.
3. Both CLI diff output (Markdown/JSON) and Frontend visualizer render the findings faithfully.
4. `cargo test` and `cargo clippy -- -D warnings` pass with zero warnings.
