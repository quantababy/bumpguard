# 003: Safe In-Memory Extraction & Non-Execution Invariants

**Status**: Accepted  
**Date**: 2026-11-10  

## Context
Security scanners frequently process malicious archives that actively attempt to compromise the host system during scanning via:
1. Directory traversal zip/tar slips (e.g., `../../etc/cron.d/backdoor`).
2. Decompression bombs (e.g., 42.zip expansion ratio denial-of-service).
3. Automatic script execution hooks (e.g., `npm install` executing `preinstall`/`postinstall`).

## Decision
1. **Zero Execution**: `bumpguard` never executes `npm install`, `node`, `pip`, `python`, or any package lifecycle script.
2. **In-Memory Streaming**: Archives are read directly from memory byte streams without writing to local disk.
3. **Strict Path Sanitization (`safe_path`)**: Any entry containing `..`, absolute paths, Windows drive prefixes (`C:`), or reserved device names (`CON`, `NUL`) is dropped immediately.
4. **Hard Resource Limits**: Enforced 50MB compressed limit, 200MB uncompressed limit, 10,000 file limit, and 5MB per-file analysis cap.

## Consequences
- **Positive**: The scanner can safely inspect untrusted and hostile archives without risk of host infection or path traversal vulnerabilities.
- **Trade-off**: Requires dedicated in-memory archive extraction implementations for `.tar.gz` and `.whl` files.

## Evidence
- `backend/tests/test_extract.py`: Verified rejection of `../../` paths and decompression size limits.
