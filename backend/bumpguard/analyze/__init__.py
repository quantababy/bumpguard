"""Code fact extraction and diffing engine."""

from .analyzer import CodeFact, FactExtractor
from .diff_engine import PackageFactDiff, compare_package_archives

__all__ = ["CodeFact", "FactExtractor", "PackageFactDiff", "compare_package_archives"]
