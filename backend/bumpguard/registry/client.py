"""npm registry client with polite retries and metadata fact extraction."""

from __future__ import annotations

import datetime
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from bumpguard.core.types import Finding, PackageRef, Severity
from bumpguard.fixtures import SYNTHETIC_ARCHIVES, SYNTHETIC_METADATA


@dataclass
class VersionMetadata:
    version: str
    tarball_url: Optional[str] = None
    integrity: Optional[str] = None
    publisher: Optional[str] = None
    published_at: Optional[datetime.datetime] = None
    has_install_script: bool = False
    has_binding_gyp: bool = False


@dataclass
class PackageMetadata:
    name: str
    versions: Dict[str, VersionMetadata] = field(default_factory=dict)
    maintainers: List[str] = field(default_factory=list)


class NpmRegistryClient:
    """Client for npm registry queries with caching and signal analysis."""

    def __init__(self, registry_base: str = "https://registry.npmjs.org", timeout: int = 15) -> None:
        self.registry_base = registry_base.rstrip("/")
        self.timeout = timeout
        self._cache: Dict[str, Dict[str, Any]] = {}

    def fetch_packument(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Fetch raw packument JSON from registry or return cached/synthetic fixture."""
        if package_name in self._cache:
            return self._cache[package_name]

        # Check synthetic fixtures first for demo / canary testing
        if package_name in SYNTHETIC_METADATA:
            synth = SYNTHETIC_METADATA[package_name]
            self._cache[package_name] = synth
            return synth

        url = f"{self.registry_base}/{package_name}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "bumpguard/0.1.0 (Dependency Update Risk Scanner)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self._cache[package_name] = data
                return data
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
            return None

    def fetch_tarball(
        self,
        package_name: str,
        version: str,
        tarball_url: Optional[str] = None,
    ) -> Optional[bytes]:
        """Fetch package release tarball bytes from synthetic cache or live registry."""
        # 1. Check synthetic in-memory fixtures
        if package_name in SYNTHETIC_ARCHIVES and version in SYNTHETIC_ARCHIVES[package_name]:
            return SYNTHETIC_ARCHIVES[package_name][version]

        # 2. Live network fetch if URL provided or reconstructable
        url = tarball_url or f"{self.registry_base}/{package_name}/-/{package_name}-{version}.tgz"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "bumpguard/0.1.0 (Dependency Update Risk Scanner)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read()
        except Exception:
            return None

    def parse_metadata(self, packument: Dict[str, Any]) -> PackageMetadata:
        """Parse raw packument into structured PackageMetadata."""
        name = packument.get("name", "")
        versions_raw = packument.get("versions", {})
        time_raw = packument.get("time", {})
        maintainers_raw = packument.get("maintainers", [])
        maintainers = [m.get("name", "") for m in maintainers_raw if isinstance(m, dict)]

        versions: Dict[str, VersionMetadata] = {}
        for ver, info in versions_raw.items():
            if isinstance(info, VersionMetadata):
                versions[ver] = info
                continue

            dist = info.get("dist", {}) if isinstance(info, dict) else {}
            tarball = dist.get("tarball") or (info.get("tarball_url") if isinstance(info, dict) else None)
            integrity = dist.get("integrity") or (info.get("integrity") if isinstance(info, dict) else None)

            npm_user = info.get("_npmUser", {}) if isinstance(info, dict) else {}
            publisher = None
            if isinstance(info, dict):
                publisher = info.get("publisher") or (npm_user.get("name") if isinstance(npm_user, dict) else None)

            published_at = info.get("published_at") if isinstance(info, dict) else None
            if not published_at and ver in time_raw:
                try:
                    # npm timestamps are ISO 8601 strings
                    ts_str = time_raw[ver].replace("Z", "+00:00")
                    published_at = datetime.datetime.fromisoformat(ts_str)
                except Exception:
                    published_at = None

            scripts = info.get("scripts", {}) if isinstance(info, dict) else {}
            has_install_script = any(
                hook in scripts
                for hook in ["preinstall", "install", "postinstall", "prepare"]
            )
            has_binding_gyp = bool(info.get("gypfile")) if isinstance(info, dict) else False

            versions[ver] = VersionMetadata(
                version=ver,
                tarball_url=tarball,
                integrity=integrity,
                publisher=publisher,
                published_at=published_at,
                has_install_script=has_install_script,
                has_binding_gyp=has_binding_gyp,
            )

        return PackageMetadata(name=name, versions=versions, maintainers=maintainers)

    def evaluate_metadata_rules(
        self,
        package_ref: PackageRef,
        metadata: PackageMetadata,
        current_time: Optional[datetime.datetime] = None,
    ) -> List[Finding]:
        """Evaluate BG-META-001, BG-META-003, and BG-POL-003 metadata rules."""
        findings: List[Finding] = []
        if current_time is None:
            current_time = datetime.datetime.now(datetime.timezone.utc)

        new_ver_meta = metadata.versions.get(package_ref.new_version)
        if not new_ver_meta:
            return findings

        # Rule BG-META-001: Publisher or maintainer set changed since previous release
        if package_ref.old_version:
            old_ver_meta = metadata.versions.get(package_ref.old_version)
            if old_ver_meta and old_ver_meta.publisher and new_ver_meta.publisher:
                if old_ver_meta.publisher != new_ver_meta.publisher:
                    findings.append(
                        Finding(
                            rule_id="BG-META-001",
                            severity=Severity.Medium,
                            weight=5.0,
                            package=package_ref,
                            file="package.json",
                            evidence=f"Publisher changed: '{old_ver_meta.publisher}' -> '{new_ver_meta.publisher}'",
                            why="Maintainer or publisher handover detected on release",
                        )
                    )

        # Rule BG-META-003: Very fresh release (< 72 hours old)
        if new_ver_meta.published_at:
            pub_time = new_ver_meta.published_at
            if pub_time.tzinfo is None:
                pub_time = pub_time.replace(tzinfo=datetime.timezone.utc)
            age = current_time - pub_time
            if datetime.timedelta(0) <= age < datetime.timedelta(hours=72):
                hours_old = int(age.total_seconds() // 3600)
                findings.append(
                    Finding(
                        rule_id="BG-META-003",
                        severity=Severity.Low,
                        weight=3.0,
                        package=package_ref,
                        file="package.json",
                        evidence=f"Published {hours_old} hours ago (< 72h threshold)",
                        why="Fresh release cooldown period active",
                    )
                )

        # Rule BG-POL-003: Missing integrity value
        if not new_ver_meta.integrity:
            findings.append(
                Finding(
                    rule_id="BG-POL-003",
                    severity=Severity.High,
                    weight=9.0,
                    package=package_ref,
                    file="package.json",
                    evidence="No integrity hash registered for version",
                    why="Release lacks cryptographic integrity verification",
                )
            )

        return findings
