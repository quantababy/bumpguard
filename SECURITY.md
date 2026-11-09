# Security Policy

## Non-Execution Invariants
`bumpguard` is designed specifically to inspect potentially malicious software archives safely:
1. **Never executes package code**: `npm install`, `pip install`, `node`, `python`, or any package script are never invoked on target packages.
2. **In-memory byte reading**: Archives are read as raw byte streams.
3. **Strict path traversal boundaries**: All archive paths are sanitized via `safe_path()`. Any entry containing `..`, absolute paths, Windows drive prefixes, or reserved system device names is rejected and skipped.
4. **Decompression limits**: Hard caps are enforced on compressed size (50MB), uncompressed size (200MB), file count (10,000 files), and analysis size per file (5MB).
5. **No malware samples in repo**: Live malware archives are never stored in the source repository. Only synthetic, harmless canary fixtures are used for testing.

## Reporting a Vulnerability
If you discover a security vulnerability in `bumpguard` itself or a flaw that could lead to sandbox/parsing escapes:
1. Please do not open a public issue.
2. Report the vulnerability privately to the project maintainers with reproduction steps.
