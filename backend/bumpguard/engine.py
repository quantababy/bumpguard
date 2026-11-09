"""Unified dependency scanning engine executing the full Bumpguard pipeline."""

from __future__ import annotations

from typing import List, Optional

from bumpguard.analyze.diff_engine import compare_package_archives
from bumpguard.core.types import Finding, PackageRef
from bumpguard.extract.safe_extractor import SafeExtractor
from bumpguard.registry.client import NpmRegistryClient
from bumpguard.score.scorer import ScoredPackage, calculate_package_risk


def scan_package_update(
    pkg: PackageRef,
    client: Optional[NpmRegistryClient] = None,
    extractor: Optional[SafeExtractor] = None,
) -> ScoredPackage:
    """Execute complete pipeline for a changed or added package:
    1. Resolve registry metadata and evaluate metadata rules.
    2. Fetch release tarballs safely in-memory.
    3. Extract files with path & size limits.
    4. Compute fact-set diff: new_facts - old_facts.
    5. Aggregate findings and compute risk score.
    """
    if client is None:
        client = NpmRegistryClient()
    if extractor is None:
        extractor = SafeExtractor()

    findings: List[Finding] = []

    # Step 1: Evaluate registry metadata signals
    packument = client.fetch_packument(pkg.name)
    tarball_url = None
    if packument:
        meta = client.parse_metadata(packument)
        findings.extend(client.evaluate_metadata_rules(pkg, meta))
        new_ver_meta = meta.versions.get(pkg.new_version)
        if new_ver_meta:
            tarball_url = new_ver_meta.tarball_url

    # Step 2 & 3: In-memory safe fetch and extraction
    old_archive = None
    if pkg.old_version:
        old_bytes = client.fetch_tarball(pkg.name, pkg.old_version)
        if old_bytes:
            try:
                old_archive = extractor.extract_tarball(old_bytes)
            except Exception:
                old_archive = None

    new_bytes = client.fetch_tarball(pkg.name, pkg.new_version, tarball_url=tarball_url)
    if new_bytes:
        try:
            new_archive = extractor.extract_tarball(new_bytes)
            # Step 4: Compare archives & extract fact diffs
            diff_result = compare_package_archives(pkg, old_archive, new_archive)
            findings.extend(diff_result.added_findings)
        except Exception:
            pass

    # Step 5: Score aggregated findings
    return calculate_package_risk(pkg, findings)
