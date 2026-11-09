"""Scoring implementation following Section 5.1 of Build Blueprint."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from bumpguard.core.types import Context, Finding, PackageRef, Severity


CONTEXT_MULTIPLIERS = {
    Context.Install: 2.0,
    Context.Build: 1.8,
    Context.Import: 1.5,
    Context.Other: 1.0,
}


@dataclass
class ScoredPackage:
    package: PackageRef
    findings: List[Finding]
    total_score: float
    risk_level: Severity
    reasons: List[str] = field(default_factory=list)

    @property
    def needs_review(self) -> bool:
        return self.risk_level in (Severity.Medium, Severity.High, Severity.Critical)

    def to_dict(self):
        return {
            "package": self.package.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "total_score": round(self.total_score, 2),
            "risk_level": self.risk_level.value,
            "reasons": self.reasons,
            "needs_review": self.needs_review,
        }


def calculate_package_risk(
    package_ref: PackageRef,
    findings: List[Finding],
) -> ScoredPackage:
    """Calculate the aggregate risk score and assign a risk level."""
    if not findings:
        return ScoredPackage(
            package=package_ref,
            findings=[],
            total_score=0.0,
            risk_level=Severity.Low,
            reasons=[],
        )

    total_score = 0.0
    has_critical_override = False
    reasons: List[str] = []

    for f in findings:
        weight = f.weight

        # Critical override rules per Section 5.1 item 5
        if f.rule_id in ("BG-CODE-006", "BG-KNOWN-001"):
            has_critical_override = True

        total_score += weight
        if f.why and f.why not in reasons:
            reasons.append(f.why)

    # Determine risk level from calibrated thresholds
    if has_critical_override or total_score >= 18.0:
        level = Severity.Critical
    elif total_score >= 10.0:
        level = Severity.High
    elif total_score >= 4.0:
        level = Severity.Medium
    else:
        level = Severity.Low

    return ScoredPackage(
        package=package_ref,
        findings=findings,
        total_score=total_score,
        risk_level=level,
        reasons=reasons,
    )
