"""Fact-set difference engine implementing Section 3.5 of Build Blueprint."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from bumpguard.core.types import Context, Fact, FactKind, Finding, PackageRef, Severity
from bumpguard.extract.safe_extractor import ExtractedArchive, ExtractedFile
from .analyzer import CodeFact, FactExtractor


@dataclass
class PackageFactDiff:
    package: PackageRef
    added_code_facts: List[CodeFact] = field(default_factory=list)
    added_findings: List[Finding] = field(default_factory=list)


def compare_package_archives(
    package_ref: PackageRef,
    old_archive: Optional[ExtractedArchive],
    new_archive: ExtractedArchive,
) -> PackageFactDiff:
    """Compare old and new extracted release archives for a package.
    
    1. Skip unchanged files based on SHA256.
    2. Extract facts from new and changed files.
    3. Calculate fact-set difference: new_facts - old_facts.
    4. Check build/lifecycle scripts and binding.gyp.
    """
    diff_result = PackageFactDiff(package=package_ref)
    extractor = FactExtractor()

    # Step 1: Detect lifecycle script changes in package.json
    new_pkg_json = new_archive.files.get("package.json")
    old_pkg_json = old_archive.files.get("package.json") if old_archive else None

    new_scripts = {}
    if new_pkg_json:
        try:
            new_scripts = json.loads(new_pkg_json.text).get("scripts", {})
        except Exception:
            new_scripts = {}

    old_scripts = {}
    if old_pkg_json:
        try:
            old_scripts = json.loads(old_pkg_json.text).get("scripts", {})
        except Exception:
            old_scripts = {}

    for hook in ["preinstall", "install", "postinstall", "prepare"]:
        new_hook_cmd = new_scripts.get(hook)
        old_hook_cmd = old_scripts.get(hook)
        if new_hook_cmd and new_hook_cmd != old_hook_cmd:
            diff_result.added_findings.append(
                Finding(
                    rule_id="BG-EXEC-001",
                    severity=Severity.High if hook in ["preinstall", "install", "postinstall"] else Severity.Medium,
                    weight=7.0,
                    package=package_ref,
                    file="package.json",
                    evidence=f"scripts.{hook} = '{new_hook_cmd}'",
                    why=f"New or modified lifecycle hook: {hook}",
                )
            )

    # Step 2: Detect binding.gyp addition (BG-EXEC-002)
    new_has_gyp = "binding.gyp" in new_archive.files
    old_has_gyp = old_archive is not None and "binding.gyp" in old_archive.files
    if new_has_gyp and not old_has_gyp:
        diff_result.added_findings.append(
            Finding(
                rule_id="BG-EXEC-002",
                severity=Severity.High,
                weight=7.0,
                package=package_ref,
                file="binding.gyp",
                evidence="binding.gyp native build descriptor added",
                why="Implicit native node-gyp build configured",
            )
        )

    # Step 3: Identify entry points
    new_import_entries, new_install_entries = set(), set()
    if new_pkg_json:
        new_import_entries, new_install_entries = extractor.identify_entry_points(new_pkg_json.text)

    old_import_entries, old_install_entries = set(), set()
    if old_pkg_json:
        old_import_entries, old_install_entries = extractor.identify_entry_points(old_pkg_json.text)

    # Step 4: Extract old facts
    old_facts: Set[Fact] = set()
    if old_archive:
        for path, file in old_archive.files.items():
            ctx = Context.Other
            if path in old_install_entries:
                ctx = Context.Install
            elif path in old_import_entries or path.endswith(("/index.js", "index.js", "main.js")):
                ctx = Context.Import
            facts = extractor.extract_file_facts(file, ctx)
            for f in facts:
                old_facts.add(f.fact)

    # Step 5: Extract new facts from changed or added files only
    new_code_facts_map: Dict[Fact, CodeFact] = {}
    for path, new_file in new_archive.files.items():
        # Optimization: skip file if old file exists and SHA256 is identical
        if old_archive and path in old_archive.files:
            if old_archive.files[path].sha256 == new_file.sha256:
                continue

        ctx = Context.Other
        if path in new_install_entries:
            ctx = Context.Install
        elif path in new_import_entries or path.endswith(("/index.js", "index.js", "main.js")):
            ctx = Context.Import

        facts = extractor.extract_file_facts(new_file, ctx)
        for cf in facts:
            if cf.fact not in new_code_facts_map:
                new_code_facts_map[cf.fact] = cf

    # Step 6: Fact set difference: new_facts - old_facts
    rule_weights = {
        "BG-CODE-001": 7.0,
        "BG-CODE-002": 6.0,
        "BG-CODE-003": 6.0,
        "BG-CODE-005": 9.0,
        "BG-CODE-006": 10.0,
    }
    rule_severities = {
        "BG-CODE-001": Severity.High,
        "BG-CODE-002": Severity.Medium,
        "BG-CODE-003": Severity.Medium,
        "BG-CODE-005": Severity.Critical,
        "BG-CODE-006": Severity.Critical,
    }

    for fact, code_fact in new_code_facts_map.items():
        if fact not in old_facts:
            diff_result.added_code_facts.append(code_fact)
            rule_id = code_fact.rule_id
            diff_result.added_findings.append(
                Finding(
                    rule_id=rule_id,
                    severity=rule_severities.get(rule_id, Severity.Medium),
                    weight=rule_weights.get(rule_id, 5.0),
                    package=package_ref,
                    file=code_fact.file,
                    line=code_fact.line,
                    evidence=code_fact.evidence,
                    why=f"New {fact.kind.value} call ({fact.api}) introduced in {fact.context.value} context",
                )
            )

    return diff_result
