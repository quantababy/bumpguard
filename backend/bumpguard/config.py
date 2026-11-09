"""Configuration loader and expiring ignore rules for bumpguard (Section 7.4)."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # type: ignore

from bumpguard.core.types import Finding, Severity


@dataclass
class IgnoreRule:
    package: str
    rule: str
    reason: str
    expires: datetime.date

    def is_expired(self, current_date: Optional[datetime.date] = None) -> bool:
        if current_date is None:
            current_date = datetime.date.today()
        return current_date > self.expires

    def matches(self, package_name: str, rule_id: str, current_date: Optional[datetime.date] = None) -> bool:
        """Check if an ignore rule applies and is not expired."""
        if self.is_expired(current_date):
            return False
        pkg_match = self.package == "*" or self.package == package_name
        rule_match = self.rule == "*" or self.rule == rule_id
        return pkg_match and rule_match


@dataclass
class BumpguardConfig:
    fail_on: Severity = Severity.High
    max_findings_in_comment: int = 15
    npm_enabled: bool = True
    pypi_enabled: bool = True
    timeout_seconds: int = 20
    registry_concurrency: int = 16
    ignores: List[IgnoreRule] = field(default_factory=list)

    def filter_findings(
        self,
        package_name: str,
        findings: List[Finding],
        current_date: Optional[datetime.date] = None,
    ) -> List[Finding]:
        """Filter out findings that match active (unexpired) ignore rules."""
        active: List[Finding] = []
        for f in findings:
            ignored = any(
                rule.matches(package_name, f.rule_id, current_date)
                for rule in self.ignores
            )
            if not ignored:
                active.append(f)
        return active


def parse_config_toml(content: str) -> BumpguardConfig:
    """Parse TOML string into BumpguardConfig."""
    data = tomllib.loads(content)

    policy = data.get("policy", {})
    fail_on_str = policy.get("fail_on", "high").capitalize()
    try:
        fail_on = Severity[fail_on_str]
    except KeyError:
        fail_on = Severity.High

    max_findings = policy.get("max_findings_in_comment", 15)

    ecosystems = data.get("ecosystems", {})
    npm_enabled = ecosystems.get("npm", True)
    pypi_enabled = ecosystems.get("pypi", True)

    network = data.get("network", {})
    timeout_sec = network.get("timeout_seconds", 20)
    concurrency = network.get("registry_concurrency", 16)

    ignores: List[IgnoreRule] = []
    for raw_ignore in data.get("ignore", []):
        pkg = raw_ignore.get("package", "*")
        rule = raw_ignore.get("rule", "*")
        reason = raw_ignore.get("reason", "")
        expires_raw = raw_ignore.get("expires", "")
        try:
            if isinstance(expires_raw, datetime.date):
                expires = expires_raw
            else:
                expires = datetime.date.fromisoformat(str(expires_raw))
        except Exception:
            expires = datetime.date(2000, 1, 1)  # invalid/missing expires immediately

        ignores.append(
            IgnoreRule(package=pkg, rule=rule, reason=reason, expires=expires)
        )

    return BumpguardConfig(
        fail_on=fail_on,
        max_findings_in_comment=max_findings,
        npm_enabled=npm_enabled,
        pypi_enabled=pypi_enabled,
        timeout_seconds=timeout_sec,
        registry_concurrency=concurrency,
        ignores=ignores,
    )


def load_config(config_path: Optional[str] = None) -> BumpguardConfig:
    """Load configuration from specified file or search standard locations."""
    candidates = []
    if config_path:
        candidates.append(Path(config_path))
    else:
        candidates.append(Path("bumpguard.toml"))
        candidates.append(Path("../bumpguard.toml"))

    for p in candidates:
        if p.is_file():
            try:
                return parse_config_toml(p.read_text(encoding="utf-8"))
            except Exception:
                pass

    return BumpguardConfig()
