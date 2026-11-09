"""Parser for Python dependency files (requirements.txt and poetry.lock)."""

from __future__ import annotations

import re
from typing import Dict, Tuple

from bumpguard.core.types import Ecosystem, PackageRef
from bumpguard.lockfile.parser import LockfileEntry

REQ_LINE = re.compile(r"""^([A-Za-z0-9_\-\.]+)\s*==\s*([A-Za-z0-9_\-\.]+)""")


def parse_requirements_txt(content: str) -> Dict[str, LockfileEntry]:
    """Parse pip requirements.txt pinned dependencies (pkg==ver)."""
    entries: Dict[str, LockfileEntry] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = REQ_LINE.match(line)
        if m:
            name, ver = m.group(1).lower(), m.group(2)
            entries[name] = LockfileEntry(name=name, version=ver)
    return entries
