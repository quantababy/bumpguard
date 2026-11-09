"""Lockfile parsing and diffing module."""

from .diff import diff_lockfiles
from .parser import LockfileEntry, parse_package_lock

__all__ = ["LockfileEntry", "parse_package_lock", "diff_lockfiles"]
