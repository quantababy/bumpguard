"""AST and pattern fact extractor for JavaScript / Node.js packages."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from bumpguard.core.types import Context, Fact, FactKind
from bumpguard.extract.safe_extractor import ExtractedFile


@dataclass(frozen=True)
class CodeFact:
    fact: Fact
    file: str
    line: int
    evidence: str
    rule_id: str


# Regular expressions for high-fidelity fact patterns in JS/TS
PATTERNS = {
    # BG-CODE-001: Network calls
    "BG-CODE-001": [
        (re.compile(r"""(?:require\s*\(\s*['"](?:https?|net|dgram|dns|node:https?|node:net)['"]\s*\)|import\s+.*?from\s+['"](?:https?|net|dgram|dns|node:https?|node:net)['"])"""), "network-module", FactKind.Network),
        (re.compile(r"""\b(?:fetch|https?\.get|https?\.request)\s*\("""), "fetch/http-request", FactKind.Network),
    ],
    # BG-CODE-002: Process execution
    "BG-CODE-002": [
        (re.compile(r"""(?:require\s*\(\s*['"](?:child_process|node:child_process)['"]\s*\)|import\s+.*?from\s+['"](?:child_process|node:child_process)['"])"""), "child_process", FactKind.Exec),
        (re.compile(r"""\b(?:exec|execSync|spawn|spawnSync|fork)\s*\("""), "exec-call", FactKind.Exec),
    ],
    # BG-CODE-003: Dynamic evaluation
    "BG-CODE-003": [
        (re.compile(r"""\b(?:eval|new\s+Function|vm\.runInContext|vm\.runInThisContext)\s*\("""), "dynamic-eval", FactKind.DynamicEval),
    ],
    # BG-CODE-005: Sensitive files & credentials
    "BG-CODE-005": [
        (re.compile(r"""['"](?:\.npmrc|\.env|id_rsa|id_ed25519|\.aws/credentials|\.ssh/)['"]"""), "sensitive-filepath", FactKind.SensitiveFs),
        (re.compile(r"""(?:NPM_TOKEN|NODE_AUTH_TOKEN|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|SLACK_TOKEN)"""), "credential-token-env", FactKind.EnvRead),
    ],
    # BG-CODE-006: Self-propagating worm behaviour
    "BG-CODE-006": [
        (re.compile(r"""npm\s+publish"""), "npm-publish", FactKind.Publish),
        (re.compile(r"""\.github/workflows/"""), "workflow-tampering", FactKind.Publish),
    ],
}


def is_ignored_path(path: str) -> bool:
    """Ignore documentation, tests, and mock directories per Section 3.5."""
    lower = path.lower()
    ignored_prefixes = (
        "test/",
        "tests/",
        "__tests__/",
        "fixture/",
        "fixtures/",
        "docs/",
        "example/",
        "examples/",
    )
    return lower.startswith(ignored_prefixes)


class FactExtractor:
    """Extracts facts from code files with context attribution."""

    @staticmethod
    def identify_entry_points(package_json_content: str) -> Tuple[Set[str], Set[str]]:
        """Parse package.json to identify (import_entries, install_script_files)."""
        import_entries: Set[str] = set()
        install_script_entries: Set[str] = set()

        try:
            data = json.loads(package_json_content)
        except Exception:
            return import_entries, install_script_entries

        # Main / module / exports entry files
        for key in ["main", "module"]:
            val = data.get(key)
            if isinstance(val, str):
                import_entries.add(val.lstrip("./"))

        exports = data.get("exports")
        if isinstance(exports, str):
            import_entries.add(exports.lstrip("./"))
        elif isinstance(exports, dict):
            for exp_val in exports.values():
                if isinstance(exp_val, str):
                    import_entries.add(exp_val.lstrip("./"))

        bin_val = data.get("bin")
        if isinstance(bin_val, str):
            import_entries.add(bin_val.lstrip("./"))
        elif isinstance(bin_val, dict):
            for v in bin_val.values():
                if isinstance(v, str):
                    import_entries.add(v.lstrip("./"))

        # Lifecycle scripts
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            for hook in ["preinstall", "install", "postinstall", "prepare"]:
                cmd = scripts.get(hook)
                if isinstance(cmd, str):
                    # Check if script invokes a node file like "node scripts/install.js"
                    parts = cmd.split()
                    for p in parts:
                        if p.endswith(".js") or p.endswith(".mjs") or p.endswith(".cjs"):
                            install_script_entries.add(p.lstrip("./"))

        return import_entries, install_script_entries

    def extract_file_facts(
        self,
        file: ExtractedFile,
        context: Context,
    ) -> List[CodeFact]:
        """Analyze a single file and extract CodeFacts."""
        if is_ignored_path(file.path):
            return []

        # Only scan JS/TS/JSON/Gyp files
        if not file.path.endswith((".js", ".mjs", ".cjs", ".ts", ".json", ".gyp")):
            return []

        facts: List[CodeFact] = []
        lines = file.text.splitlines()

        for line_no, line in enumerate(lines, 1):
            for rule_id, rule_patterns in PATTERNS.items():
                for regex, api_name, fact_kind in rule_patterns:
                    match = regex.search(line)
                    if match:
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
