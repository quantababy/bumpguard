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

### 1. Run the CLI Diff Scanner
```bash
# From the backend directory:
cd backend

# Compare using the included sample lockfiles:
python -m bumpguard.cli diff --base ../samples/old-lock.json --head ../samples/new-lock.json --format markdown

# Or scan between two Git commits/branches:
python -m bumpguard.cli diff --base origin/main --head HEAD --fail-on high
```

### 2. Launch the Integrated Visualizer Web UI
```bash
# From the backend directory:
cd backend
python -m bumpguard.cli serve --port 8080

# Open http://127.0.0.1:8080 in your browser
# Click "Load Demo Scenario" and "Run Security Scan" to test interactively!
```

### 3. Run the Test Suite
```bash
# From the project root:
python run_tests.py

# Or from the backend directory:
cd backend
python -m unittest discover -s tests -v
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

## Empirical Evaluation & Calibration (v1.5)

To evaluate real-world efficacy, `bumpguard` tests its diff-first calibrated model on separate tracks with **cluster-aware partitioning** to prevent near-duplicate leakage, measuring recall at an alert budget with Wilson 95% confidence intervals:

### Track 1: Diff Track (Compromised Releases with Available Predecessor)
| Approach | TPR (Recall) | 95% CI (TPR) | FPR (False Alarms) | 95% CI (FPR) | PPV at 0.1% Prev |
|---|---|---|---|---|---|
| **bumpguard (Diff-First)** | **100.0%** | [51.0%, 100.0%] | **0.0%** | [0.0%, 16.1%] | **100.0%** |
| Heuristic A (Install Script) | 25.0% | [4.6%, 69.9%] | 0.0% | [0.0%, 16.1%] | 100.0% |
| Heuristic B (Any Network) | 75.0% | [30.1%, 95.4%] | 0.0% | [0.0%, 16.1%] | 100.0% |

### Track 2: New-Package Track (Zero-History Malicious Packages)
| Approach | TPR (Recall) | 95% CI (TPR) | FPR (False Alarms) | 95% CI (FPR) |
|---|---|---|---|---|
| **bumpguard (Full Package)** | **100.0%** | [34.2%, 100.0%] | **0.0%** | [0.0%, 27.8%] |

*Run `python -m eval.run_eval` to reproduce this table and regenerate `eval/results/results.json`.*

---

## Architectural Decision Records (ADRs)
- [001: Diff-First Architecture & Fact-Set Difference](docs/decisions/001-diff-first-architecture.md)
- [002: Calibrated Scoring, Alert Budget & Base-Rate Problem](docs/decisions/002-calibrated-scoring-and-alert-budget.md)
- [003: Safe In-Memory Extraction & Non-Execution Invariants](docs/decisions/003-safe-in-memory-extraction.md)

See [`docs/INTERVIEW_GUIDE.md`](docs/INTERVIEW_GUIDE.md) for technical interview rehearsal questions and deep-dive explanations.

---

## Limitations (What bumpguard Cannot Do)
- **Not a dynamic sandbox**: It will not execute code to catch novel, heavily obfuscated, or time-delayed payloads.
- **Requires predecessor**: It compares old vs. new releases. Newly added zero-history packages are evaluated against metadata and new-package heuristics.
- **Findings are risk signals**: Findings represent risk signals to assist human code review, not definitive malice verdicts.
