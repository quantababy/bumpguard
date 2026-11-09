"""Core type definitions corresponding to Section 3.4 of the Build Blueprint."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class Ecosystem(str, Enum):
    NPM = "npm"
    PYPI = "pypi"

    def __str__(self) -> str:
        return self.value


class FactKind(str, Enum):
    Network = "Network"
    Exec = "Exec"
    DynamicEval = "DynamicEval"
    EnvRead = "EnvRead"
    SensitiveFs = "SensitiveFs"
    Obfuscation = "Obfuscation"
    Publish = "Publish"
    Native = "Native"

    def __str__(self) -> str:
        return self.value


class Context(str, Enum):
    Install = "Install"
    Build = "Build"
    Import = "Import"
    Other = "Other"

    def __str__(self) -> str:
        return self.value


class Severity(str, Enum):
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Critical = "Critical"

    def __str__(self) -> str:
        return self.value

    @property
    def level(self) -> int:
        order = {
            Severity.Low: 1,
            Severity.Medium: 2,
            Severity.High: 3,
            Severity.Critical: 4,
        }
        return order[self]

    def meets_threshold(self, threshold: Severity) -> bool:
        return self.level >= threshold.level


@dataclass(frozen=True)
class Fact:
    kind: FactKind
    api: str
    context: Context

    def to_dict(self) -> Dict[str, str]:
        return {
            "kind": self.kind.value,
            "api": self.api,
            "context": self.context.value,
        }


@dataclass(frozen=True)
class PackageRef:
    ecosystem: Ecosystem
    name: str
    old_version: Optional[str]
    new_version: str

    @property
    def is_new_package(self) -> bool:
        return self.old_version is None

    @property
    def change_label(self) -> str:
        if self.old_version is None:
            return f"added {self.new_version}"
        return f"{self.old_version} → {self.new_version}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ecosystem": self.ecosystem.value,
            "name": self.name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "change_label": self.change_label,
        }


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    weight: float
    package: PackageRef
    file: Optional[str] = None
    line: Optional[int] = None
    evidence: str = ""
    why: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "weight": self.weight,
            "package": self.package.to_dict(),
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "why": self.why,
        }
