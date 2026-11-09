"""Markdown and JSON report formatting per Section 7.5 of Build Blueprint."""

from __future__ import annotations

import json
from typing import Dict, List

from bumpguard.score.scorer import ScoredPackage


def format_markdown_report(scored_packages: List[ScoredPackage]) -> str:
    """Generate concise pull request markdown comment adhering to Section 7.5."""
    total_packages = len(scored_packages)
    flagged = [p for p in scored_packages if p.needs_review]
    clean_count = total_packages - len(flagged)

    if not flagged:
        return (
            f"### bumpguard: {total_packages} updates scanned\n\n"
            f"All {total_packages} updates had no new risk signals. Clean! "
            f"Risk signals are for review, not verdicts."
        )

    lines = [
        f"### bumpguard: {len(flagged)} of {total_packages} updates need review\n",
        "| Package | Change | Risk | Why |",
        "|---|---|---|---|",
    ]

    for p in flagged:
        change_str = p.package.change_label
        risk_str = p.risk_level.value
        why_str = "; ".join(p.reasons[:3]) if p.reasons else "elevated risk score"
        lines.append(f"| {p.package.name} | {change_str} | {risk_str} | {why_str} |")

    lines.append("")
    lines.append(
        f"{clean_count} updates had no new risk signals. Risk signals are for review, not verdicts."
    )
    return "\n".join(lines)


def format_json_report(scored_packages: List[ScoredPackage]) -> str:
    """Format structured machine-readable JSON output."""
    total = len(scored_packages)
    flagged = [p for p in scored_packages if p.needs_review]

    data = {
        "summary": {
            "total_packages": total,
            "needing_review": len(flagged),
            "clean_packages": total - len(flagged),
        },
        "packages": [p.to_dict() for p in scored_packages],
    }
    return json.dumps(data, indent=2)
