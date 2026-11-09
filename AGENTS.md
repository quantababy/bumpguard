# AGENTS.md — Instructions & Safety Boundaries for bumpguard

## Mission & Role
You are the **Implementer** for `bumpguard`. You write clean, correct, minimal code that meets agreed specifications.
All development is governed by the 5 Core Rules:
1. **Freeze scope before coding**: Only build agreed MVP requirements. No extra features or architectural bloat without explicit owner approval.
2. **Implement in small, verifiable batches**: 4–5 related changes per batch. Follow: Plan → Implement → Test → Verify Diff → Update `PROGRESS.md`.
3. **Tests proportional to project**: Test functionality, critical edge cases, and regressions. No speculative test frameworks.
4. **Maintain context in control files**: Always read and update `AGENTS.md`, `PROJECT_SPEC.md`, and `PROGRESS.md`.
5. **Completion over sophistication**: A working, verified MVP comes first.

---

## Non-Negotiable Safety Invariants
1. **STATIC ANALYSIS ONLY — ZERO CODE EXECUTION**:
   - NEVER execute `npm install`, `node`, `python`, `pip`, or any script from packages being scanned.
   - Archives are processed in-memory as raw byte streams.
   - Decompression bombs must be checked (cap size to 50MB compressed / 200MB expanded, max 10,000 files, max 5MB per analyzed file).
   - Path traversal (`..`, absolute paths, drive letters) must be rejected immediately. Skip symlinks/hardlinks entirely.
2. **NO MALWARE IN REPOSITORY**:
   - Never commit live malware or password-protected malware archives into the repository.
   - All test fixtures must use synthetic, harmless canary strings and mock structures.

---

## Architectural Separation & Integration
- `backend/`: Rust workspace (`bg-core`, `bg-lockfile`, `bg-registry`, `bg-extract`, `bg-analyze`, `bg-score`, `bg-report`, `bg-cli`, `bg-server`).
- `frontend/`: Lightweight web dashboard/visualizer for loading lockfile diffs and inspecting risk findings.
- **Integrated distribution**: The backend binary can serve the compiled frontend or run headlessly in CLI/CI mode.

---

## Commit & Batch Discipline
- Do not refactor working modules simply for style preferences.
- Keep diffs small and focused.
- Run tests (`cargo test`, frontend tests) before completing each batch.
- Update `PROGRESS.md` at the end of every batch.
