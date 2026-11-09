# bumpguard

> Compare the old and new release of every dependency a pull request changes, and flag only what is new and risky.

`bumpguard` is a fast, safe dependency update risk scanner that inspects package updates in pull requests. By comparing the behavior between old and new releases, unchanged baseline behavior is ignored, keeping noise and false alarms to an absolute minimum.

---

## Key Features

- **Diff-First Architecture**: Only flags behavior (network, process execution, eval, credentials) that is *new* in the update. A package that has always spawned processes is not flagged for doing so again.
- **Strict In-Memory Safe Extraction**: Never executes package code or lifecycle scripts. Enforces strict path traversal rejection and decompression bomb limits.
- **npm Ecosystem Support (MVP)**: Full diffing across `package-lock.json` v1, v2, and v3 schemas.
- **Registry Signal Detection**: Checks for maintainer/publisher changes (`BG-META-001`), fresh release cooldowns under 72h (`BG-META-003`), and missing cryptographic integrity (`BG-POL-003`).
- **Composite GitHub Action**: Seamlessly integrates into PR workflows, outputting GitHub PR markdown comments.
- **Integrated Web Dashboard**: Built-in interactive visualizer to inspect lockfile diffs, explore findings, and copy PR reports.

---

## Quickstart

### 1. Run the CLI
```bash
# Scan between two Git commits or branches
python -m bumpguard.cli diff --base origin/main --head HEAD --fail-on high

# Or compare two package-lock.json files directly
python -m bumpguard.cli diff --base ./old-lock.json --head ./new-lock.json --format markdown
```

### 2. Launch the Integrated Visualizer
```bash
python -m bumpguard.cli serve --port 8080
# Open http://127.0.0.1:8080 in your browser to inspect scans visually
```

### 3. GitHub Action Setup
```yaml
name: dependency-risk
on:
  pull_request:
    paths: ["**/package-lock.json"]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: ./action
        with:
          base: ${{ github.event.pull_request.base.sha }}
          head: ${{ github.event.pull_request.head.sha }}
          fail-on: high
```

---

## Limitations (What bumpguard Cannot Do)
- **Not a dynamic sandbox**: It will not execute code to catch novel, heavily obfuscated, or time-delayed payloads.
- **Requires predecessor**: It compares old vs. new releases. Newly added zero-history packages are evaluated against metadata and new-package heuristics.
- **Findings are risk signals**: Findings represent risk signals to assist human code review, not definitive malice verdicts.
