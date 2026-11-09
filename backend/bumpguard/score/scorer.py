"""Scoring implementation following Section 5.1 of Build Blueprint."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from bumpguard.core.types import Context, Finding, PackageRef, Severity

_CALIBRATED_WEIGHTS: Optional[Dict] = None

def _load_calibrated_weights() -> Optional[Dict]:
    global _CALIBRATED_WEIGHTS
    if _CALIBRATED_WEIGHTS is not None:
        return _CALIBRATED_WEIGHTS

    candidates = [
        Path(__file__).parent.parent / "model_weights.json",
        Path("backend/bumpguard/model_weights.json"),
        Path("../backend/bumpguard/model_weights.json"),
    ]
    for p in candidates:
        if p.is_file():
            try:
                _CALIBRATED_WEIGHTS = json.loads(p.read_text(encoding="utf-8"))
                return _CALIBRATED_WEIGHTS
            except Exception:
                pass
    return None


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

    # Check calibrated model first per Section 5.1
    weights_data = _load_calibrated_weights()
    if weights_data and not has_critical_override:
        # Build feature map from findings
        weights = weights_data.get("weights", {})
        intercept = weights_data.get("intercept", -1.5)
        platt_a = weights_data.get("platt_a", 1.0)
        platt_b = weights_data.get("platt_b", 0.0)

        # Feature mapping from findings
        rule_to_feature = {
            "BG-CODE-001": "new_network_call",
            "BG-CODE-002": "new_process_exec",
            "BG-CODE-003": "new_eval",
            "BG-CODE-005": "new_credential_read",
            "BG-CODE-006": "worm_propagation",
            "BG-EXEC-001": "has_install_script",
            "BG-EXEC-002": "has_binding_gyp",
            "BG-EXEC-003": "has_pth_file",
            "BG-META-001": "publisher_changed",
            "BG-META-003": "fresh_release",
        }

        raw_logit = intercept
        for f in findings:
            feat_name = rule_to_feature.get(f.rule_id)
            if feat_name and feat_name in weights:
                raw_logit += weights[feat_name]

        cal_logit = platt_a * raw_logit + platt_b
        cal_prob = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, cal_logit))))
        total_score = round(cal_prob * 100.0, 2)

        if cal_prob >= 0.70:
            level = Severity.Critical
        elif cal_prob >= 0.40:
            level = Severity.High
        elif cal_prob >= 0.15:
            level = Severity.Medium
        else:
            level = Severity.Low
    else:
        # Prior rule weight heuristic fallback
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
