# 001: Diff-First Architecture & Fact-Set Difference

**Status**: Accepted  
**Date**: 2026-11-10  

## Context
Traditional vulnerability and security scanners analyze entire package archives in isolation. However, in modern software development, legitimate libraries frequently perform network calls (e.g., Axios), spawn child processes (e.g., CLI tools), or read environment variables (e.g., bundlers). Scanning an entire package produces overwhelming false-alarm fatigue because developers already know their dependencies perform these actions.

## Decision
`bumpguard` implements a **diff-first architecture**:
1. Download both the predecessor version and the new version of every updated dependency.
2. Hash all files to skip unchanged code.
3. Extract AST and code facts only from new or modified files.
4. Key facts by `(kind, api, context)` at the package level.
5. Compute the fact difference: `added = facts(new) - facts(old)`. Only newly introduced behavior is scored.

## Consequences
- **Positive**: Unchanged baseline behaviors (like child_process in a CLI) produce zero false positives. Moving code between files during refactors does not flag new behavior.
- **Trade-off**: Requires an available predecessor release. For brand new packages with zero history, `bumpguard` switches to New-Package mode.

## Evidence
- `eval/results/results.json`: 0.0% false-positive rate on benign update bumps.
