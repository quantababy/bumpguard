"""Parser for npm package-lock.json (supporting v1, v2, and v3 formats)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class LockfileEntry:
    name: str
    version: str
    resolved: Optional[str] = None
    integrity: Optional[str] = None
    dev: bool = False


def _normalize_package_name(key: str) -> str:
    """Normalize npm package keys like 'node_modules/@scope/pkg' to '@scope/pkg'."""
    if key.startswith("node_modules/"):
        return key[len("node_modules/") :]
    # If nested like node_modules/foo/node_modules/bar, take the last segment or path
    parts = key.split("node_modules/")
    if len(parts) > 1:
        return parts[-1]
    return key


def parse_package_lock(content: str) -> Dict[str, LockfileEntry]:
    """Parse package-lock.json string into a dictionary of package_name -> LockfileEntry."""
    data = json.loads(content)
    entries: Dict[str, LockfileEntry] = {}

    # Lockfile v2 and v3 use the "packages" map
    if "packages" in data and isinstance(data["packages"], dict):
        for path_key, pkg_info in data["packages"].items():
            if not path_key or path_key == "":
                # Root application itself
                continue
            name = pkg_info.get("name") or _normalize_package_name(path_key)
            version = pkg_info.get("version", "")
            resolved = pkg_info.get("resolved")
            integrity = pkg_info.get("integrity")
            dev = pkg_info.get("dev", False)

            if name and version:
                entries[name] = LockfileEntry(
                    name=name,
                    version=version,
                    resolved=resolved,
                    integrity=integrity,
                    dev=dev,
                )

    # Legacy lockfile v1 uses the "dependencies" map
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        def _parse_v1_deps(deps_dict: dict):
            for name, pkg_info in deps_dict.items():
                version = pkg_info.get("version", "")
                resolved = pkg_info.get("resolved")
                integrity = pkg_info.get("integrity")
                dev = pkg_info.get("dev", False)
                if name and version:
                    entries[name] = LockfileEntry(
                        name=name,
                        version=version,
                        resolved=resolved,
                        integrity=integrity,
                        dev=dev,
                    )
                if "dependencies" in pkg_info and isinstance(pkg_info["dependencies"], dict):
                    _parse_v1_deps(pkg_info["dependencies"])

        _parse_v1_deps(data["dependencies"])

    return entries
