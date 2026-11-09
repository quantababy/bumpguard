"""Safe in-memory wheel (.whl) ZIP extractor with traversal limits."""

from __future__ import annotations

import hashlib
import io
import zipfile
from typing import Dict, Optional

from bumpguard.extract.safe_extractor import ExtractedArchive, ExtractedFile, safe_path


class SafeWheelExtractor:
    """Safe in-memory ZIP extractor for Python wheels (.whl) enforcing limits."""

    def __init__(
        self,
        max_compressed_bytes: int = 50 * 1024 * 1024,
        max_expanded_bytes: int = 200 * 1024 * 1024,
        max_file_count: int = 10_000,
        max_file_analysis_bytes: int = 5 * 1024 * 1024,
        max_expansion_ratio: float = 100.0,
    ) -> None:
        self.max_compressed_bytes = max_compressed_bytes
        self.max_expanded_bytes = max_expanded_bytes
        self.max_file_count = max_file_count
        self.max_file_analysis_bytes = max_file_analysis_bytes
        self.max_expansion_ratio = max_expansion_ratio

    def extract_wheel(self, zip_bytes: bytes) -> ExtractedArchive:
        compressed_len = len(zip_bytes)
        if compressed_len > self.max_compressed_bytes:
            raise ValueError(f"Wheel size ({compressed_len}) exceeds limit ({self.max_compressed_bytes})")

        bio = io.BytesIO(zip_bytes)
        files: Dict[str, ExtractedFile] = {}
        total_uncompressed = 0
        file_count = 0

        with zipfile.ZipFile(bio, mode="r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue

                sanitized = safe_path(info.filename)
                if sanitized is None:
                    continue

                file_count += 1
                if file_count > self.max_file_count:
                    raise ValueError(f"Wheel file count exceeds limit ({self.max_file_count})")

                total_uncompressed += info.file_size
                if total_uncompressed > self.max_expanded_bytes:
                    raise ValueError(f"Wheel uncompressed bytes exceed limit ({self.max_expanded_bytes})")

                raw_bytes = zf.read(info)
                file_hash = hashlib.sha256(raw_bytes).hexdigest()

                is_truncated = False
                if len(raw_bytes) > self.max_file_analysis_bytes:
                    is_truncated = True
                    analyzable = raw_bytes[: self.max_file_analysis_bytes]
                else:
                    analyzable = raw_bytes

                files[sanitized] = ExtractedFile(
                    path=sanitized,
                    content=analyzable,
                    sha256=file_hash,
                    size=len(raw_bytes),
                    is_truncated=is_truncated,
                )

        return ExtractedArchive(
            files=files,
            total_uncompressed_bytes=total_uncompressed,
            file_count=file_count,
        )
