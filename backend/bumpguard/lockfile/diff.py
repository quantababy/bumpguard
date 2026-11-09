"""Lockfile diffing engine: compares base and head lockfile entries."""

from __future__ import annotations

from typing import Dict, List, Tuple

from bumpguard.core.types import Ecosystem, PackageRef
from .parser import LockfileEntry


def diff_lockfiles(
    base_entries: Dict[str, LockfileEntry],
    head_entries: Dict[str, LockfileEntry],
    ignore_dev: bool = False,
) -> Tuple[List[PackageRef], List[str]]:
    """Compare base and head lockfiles.
    
    Returns:
    - changed_or_added: List of PackageRef for packages that are new or updated.
    - removed: List of package names removed.
    """
    changed: List[PackageRef] = []
    removed: List[str] = []

    # Check packages in head against base
    for name, head_entry in head_entries.items():
        if ignore_dev and head_entry.dev:
            continue

        base_entry = base_entries.get(name)
        if base_entry is None:
            # Newly added dependency
            changed.append(
                PackageRef(
                    ecosystem=Ecosystem.NPM,
                    name=name,
                    old_version=None,
                    new_version=head_entry.version,
                )
            )
        elif base_entry.version != head_entry.version:
            # Upgraded or downgraded version
            changed.append(
                PackageRef(
                    ecosystem=Ecosystem.NPM,
                    name=name,
                    old_version=base_entry.version,
                    new_version=head_entry.version,
                )
            )

    # Check for removed packages
    for name, base_entry in base_entries.items():
        if ignore_dev and base_entry.dev:
            continue
        if name not in head_entries:
            removed.append(name)

    return changed, removed
