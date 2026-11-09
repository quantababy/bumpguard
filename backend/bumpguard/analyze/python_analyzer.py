"""Code fact extractor for Python ecosystem (.py, .pth, wheels)."""

from __future__ import annotations

import re
from typing import List, Set

from bumpguard.analyze.analyzer import CodeFact, is_ignored_path
from bumpguard.core.types import Context, Fact, FactKind, Finding, PackageRef, Severity
from bumpguard.extract.safe_extractor import ExtractedArchive, ExtractedFile

PY_PATTERNS = {
    # BG-CODE-001: Network
    "BG-CODE-001": [
        (re.compile(r"""\b(?:import\s+(?:urllib|requests|httpx|aiohttp|socket)|from\s+(?:urllib|requests|httpx|aiohttp|socket)\s+import)"""), "py-network-import", FactKind.Network),
        (re.compile(r"""\b(?:requests\.(?:get|post|put)|urllib\.request\.urlopen|socket\.socket)\s*\("""), "py-network-call", FactKind.Network),
    ],
    # BG-CODE-002: Process
    "BG-CODE-002": [
        (re.compile(r"""\b(?:subprocess\.(?:run|Popen|call|check_output)|os\.system|os\.popen)\s*\("""), "py-process-exec", FactKind.Exec),
    ],
    # BG-CODE-003: Dynamic Eval
    "BG-CODE-003": [
        (re.compile(r"""\b(?:eval|exec|compile)\s*\("""), "py-dynamic-eval", FactKind.DynamicEval),
    ],
    # BG-CODE-005: Sensitive Secrets
    "BG-CODE-005": [
        (re.compile(r"""os\.environ(?:\[|\.get\()\s*['"](?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN|SLACK_TOKEN)['"]"""), "py-credential-env", FactKind.EnvRead),
        (re.compile(r"""['"](?:\.env|id_rsa|id_ed25519|\.aws/credentials)['"]"""), "py-sensitive-path", FactKind.SensitiveFs),
    ],
}


class PythonFactExtractor:
    """Extracts facts from Python source files and checks persistence hooks (.pth)."""

    def extract_file_facts(self, file: ExtractedFile, context: Context) -> List[CodeFact]:
        if is_ignored_path(file.path) or not file.path.endswith(".py"):
            return []

        facts: List[CodeFact] = []
        for line_no, line in enumerate(file.text.splitlines(), 1):
            for rule_id, rule_patterns in PY_PATTERNS.items():
                for regex, api_name, fact_kind in rule_patterns:
                    if regex.search(line):
                        evidence = line.strip()
                        if len(evidence) > 120:
                            evidence = evidence[:117] + "..."
                        fact = Fact(kind=fact_kind, api=api_name, context=context)
                        facts.append(
                            CodeFact(
                                fact=fact,
                                file=file.path,
                                line=line_no,
                                evidence=evidence,
                                rule_id=rule_id,
                            )
                        )
        return facts

    def check_pth_files(self, archive: ExtractedArchive, package_ref: PackageRef) -> List[Finding]:
        """Check for malicious .pth files in archive (BG-EXEC-003 persistence trick)."""
        findings: List[Finding] = []
        for path in archive.files.keys():
            if path.endswith(".pth"):
                findings.append(
                    Finding(
                        rule_id="BG-EXEC-003",
                        severity=Severity.High,
                        weight=8.0,
                        package=package_ref,
                        file=path,
                        evidence=f"Discovered .pth persistence file: {path}",
                        why="Python .pth file triggers execution on interpreter start-up",
                    )
                )
        return findings
