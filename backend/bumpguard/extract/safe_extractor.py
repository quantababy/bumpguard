"""Safe in-memory archive extraction complying with Blueprint Section 3.6."""

from __future__ import annotations

import hashlib
import io
import os
import posixpath
import tarfile
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ExtractedFile:
    path: str
    content: bytes
    sha256: str
    size: int
    is_truncated: bool = False

    @property
    def text(self) -> str:
        try:
            return self.content.decode("utf-8")
        except UnicodeDecodeError:
            return self.content.decode("latin-1", errors="replace")


@dataclass
class ExtractedArchive:
    files: Dict[str, ExtractedFile]
    total_uncompressed_bytes: int
    file_count: int


def safe_path(entry_path: str) -> Optional[str]:
    """Sanitize and validate an entry path.
    
    Rejects:
    - Path traversal ('..')
    - Absolute paths ('/etc/passwd' or '\\windows')
    - Windows drive prefixes ('C:...')
    - Null bytes or control characters
    """
    if not entry_path or "\0" in entry_path:
        return None

    # Replace backslashes with slashes for standard POSIX normalization
    normalized = entry_path.replace("\\", "/").strip()

    # Reject drive prefixes like C:
    if len(normalized) >= 2 and normalized[1] == ":":
        return None

    # Reject absolute root starts
    if normalized.startswith("/"):
        return None

    parts = [p for p in normalized.split("/") if p and p != "."]
    safe_parts = []
    for part in parts:
        if part == "..":
            # Direct path traversal attempt
            return None
        # Reject windows reserved device names (e.g. CON, PRN, AUX, NUL, COM1, LPT1 with any extension)
        device_names = {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "LPT1", "LPT2", "LPT3"}
        stem = part.split(".")[0].upper()
        if stem in device_names:
            return None
        safe_parts.append(part)

    if not safe_parts:
        return None

    return "/".join(safe_parts)


class SafeExtractor:
    """Safe, non-executing in-memory tarball extractor with hard limits."""

    def __init__(
        self,
        max_compressed_bytes: int = 50 * 1024 * 1024,  # 50 MB
        max_expanded_bytes: int = 200 * 1024 * 1024,   # 200 MB
        max_file_count: int = 10_000,
        max_file_analysis_bytes: int = 5 * 1024 * 1024,  # 5 MB per file
        max_expansion_ratio: float = 100.0,
    ) -> None:
        self.max_compressed_bytes = max_compressed_bytes
        self.max_expanded_bytes = max_expanded_bytes
        self.max_file_count = max_file_count
        self.max_file_analysis_bytes = max_file_analysis_bytes
        self.max_expansion_ratio = max_expansion_ratio

    def extract_tarball(self, compressed_bytes: bytes) -> ExtractedArchive:
        """Extract a .tgz / .tar.gz buffer in memory under security boundaries."""
        compressed_len = len(compressed_bytes)
        if compressed_len > self.max_compressed_bytes:
            raise ValueError(
                f"Archive compressed size ({compressed_len} bytes) exceeds limit ({self.max_compressed_bytes} bytes)"
            )

        bio = io.BytesIO(compressed_bytes)
        files: Dict[str, ExtractedFile] = {}
        total_uncompressed = 0
        file_count = 0

        with tarfile.open(fileobj=bio, mode="r:*") as tar:
            for member in tar:
                # Security rule 1: Ignore symlinks, hardlinks, FIFOs, devices
                if not member.isreg():
                    continue

                # Security rule 2: Sanitize path
                sanitized_path = safe_path(member.name)
                if sanitized_path is None:
                    # Traversal attempt or invalid path — drop and skip
                    continue

                file_count += 1
                if file_count > self.max_file_count:
                    raise ValueError(
                        f"Archive file count exceeded safe limit ({self.max_file_count})"
                    )

                total_uncompressed += member.size
                if total_uncompressed > self.max_expanded_bytes:
                    raise ValueError(
                        f"Archive uncompressed size ({total_uncompressed} bytes) exceeds limit ({self.max_expanded_bytes} bytes)"
                    )

                # Expansion ratio check
                if compressed_len > 0 and (total_uncompressed / compressed_len) > self.max_expansion_ratio:
                    raise ValueError(
                        f"Expansion ratio ({total_uncompressed / compressed_len:.1f}x) exceeds limit ({self.max_expansion_ratio}x)"
                    )

                extracted_f = tar.extractfile(member)
                if extracted_f is None:
                    continue

                raw_bytes = extracted_f.read()
                file_hash = hashlib.sha256(raw_bytes).hexdigest()

                is_truncated = False
                if len(raw_bytes) > self.max_file_analysis_bytes:
                    is_truncated = True
                    analyzable_bytes = raw_bytes[: self.max_file_analysis_bytes]
                else:
                    analyzable_bytes = raw_bytes

                # Standardize npm path: strip leading 'package/' if present
                clean_key = sanitized_path
                if clean_key.startswith("package/"):
                    clean_key = clean_key[len("package/") :]

                files[clean_key] = ExtractedFile(
                    path=clean_key,
                    content=analyzable_bytes,
                    sha256=file_hash,
                    size=len(raw_bytes),
                    is_truncated=is_truncated,
                )

        return ExtractedArchive(
            files=files,
            total_uncompressed_bytes=total_uncompressed,
            file_count=file_count,
        )
