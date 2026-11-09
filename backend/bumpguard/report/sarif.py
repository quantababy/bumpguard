"""SARIF v2.1.0 generator for GitHub Code Scanning integration."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from bumpguard.core.types import Severity
from bumpguard.score.scorer import ScoredPackage

RULE_DEFINITIONS = {
    "BG-POL-001": {"name": "ScriptApprovalWidened", "desc": "A script-approval list grew or widened in this pull request"},
    "BG-POL-002": {"name": "RemoteDependencyAdded", "desc": "New Git or remote-URL dependency added"},
    "BG-POL-003": {"name": "IntegrityHashMismatch", "desc": "Integrity hash differs from registry or is missing"},
    "BG-META-001": {"name": "PublisherChanged", "desc": "Publisher or maintainer changed since previous release"},
    "BG-META-003": {"name": "FreshReleaseCooldown", "desc": "Release is under 72 hours old"},
    "BG-EXEC-001": {"name": "LifecycleScriptAdded", "desc": "New or modified lifecycle install script"},
    "BG-EXEC-002": {"name": "BindingGypAdded", "desc": "New binding.gyp file triggers implicit native build"},
    "BG-EXEC-003": {"name": "PythonPersistenceTrick", "desc": "New .pth file or setup hook introduced"},
    "BG-CODE-001": {"name": "NewNetworkAccess", "desc": "New network call introduced in update"},
    "BG-CODE-002": {"name": "NewProcessExecution", "desc": "New child process execution introduced"},
    "BG-CODE-003": {"name": "DynamicEvaluation", "desc": "Dynamic evaluation (eval, vm) introduced"},
    "BG-CODE-005": {"name": "CredentialAccess", "desc": "Access to secrets, credentials, or token environment variables"},
    "BG-CODE-006": {"name": "WormPropagation", "desc": "Self-propagating worm publish or workflow tampering call"},
}


def severity_to_sarif_level(sev: Severity) -> str:
    """Map bumpguard Severity to SARIF level: error, warning, note, none."""
    if sev in (Severity.Critical, Severity.High):
        return "error"
    elif sev == Severity.Medium:
        return "warning"
    else:
        return "note"


def format_sarif_report(scored_packages: List[ScoredPackage]) -> str:
    """Generate SARIF 2.1.0 JSON report."""
    sarif_rules: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for pkg_result in scored_packages:
        for finding in pkg_result.findings:
            rule_id = finding.rule_id
            if rule_id not in sarif_rules:
                meta = RULE_DEFINITIONS.get(rule_id, {"name": rule_id, "desc": finding.why})
                sarif_rules[rule_id] = {
                    "id": rule_id,
                    "name": meta["name"],
                    "shortDescription": {"text": meta["desc"]},
                    "defaultConfiguration": {
                        "level": severity_to_sarif_level(finding.severity)
                    },
                }

            file_path = finding.file or "package.json"
            line_no = finding.line or 1

            result_entry = {
                "ruleId": rule_id,
                "level": severity_to_sarif_level(finding.severity),
                "message": {
                    "text": f"[{pkg_result.package.name} {pkg_result.package.change_label}] {finding.why}. Evidence: {finding.evidence}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": line_no,
                                "startColumn": 1,
                            },
                        }
                    }
                ],
            }
            sarif_results.append(result_entry)

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bumpguard",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/OWNER/bumpguard",
                        "rules": list(sarif_rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)
