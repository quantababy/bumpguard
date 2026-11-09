"""Evaluation metrics, Wilson score confidence intervals, and PPV sensitivity (Sections 5.2-5.4)."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Tuple


def wilson_score_interval(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """Calculate Wilson score interval for proportion k/n."""
    if n == 0:
        return 0.0, 1.0

    p = k / n
    # z for 95% confidence is ~1.959964
    z = 1.959964 if confidence == 0.95 else 2.575829
    denom = 1.0 + (z**2) / n
    centre = (p + (z**2) / (2 * n)) / denom
    spread = (z * math.sqrt((p * (1.0 - p) / n) + ((z**2) / (4 * (n**2))))) / denom

    low = max(0.0, centre - spread)
    high = min(1.0, centre + spread)
    return round(low, 4), round(high, 4)


def calculate_ppv(tpr: float, fpr: float, prevalence: float) -> float:
    """Compute Positive Predictive Value (PPV) under assumed prevalence pi:
    PPV = (TPR * pi) / (TPR * pi + FPR * (1 - pi))
    """
    numerator = tpr * prevalence
    denominator = numerator + fpr * (1.0 - prevalence)
    if denominator == 0.0:
        return 0.0
    return round(numerator / denominator, 4)


@dataclass
class TrackResult:
    track_name: str
    total_samples: int
    positives: int
    negatives: int
    tp: int
    fp: int
    tn: int
    fn: int
    tpr: float
    tpr_ci_low: float
    tpr_ci_high: float
    fpr: float
    fpr_ci_low: float
    fpr_ci_high: float
    ppv_table: Dict[str, float]  # prevalence -> PPV


def evaluate_predictions(
    y_true: List[int],
    y_scores: List[float],
    threshold: float,
    track_name: str,
) -> TrackResult:
    """Evaluate binary predictions at a given decision threshold."""
    total = len(y_true)
    positives = sum(y_true)
    negatives = total - positives

    tp = sum(1 for yt, ys in zip(y_true, y_scores) if yt == 1 and ys >= threshold)
    fp = sum(1 for yt, ys in zip(y_true, y_scores) if yt == 0 and ys >= threshold)
    tn = sum(1 for yt, ys in zip(y_true, y_scores) if yt == 0 and ys < threshold)
    fn = sum(1 for yt, ys in zip(y_true, y_scores) if yt == 1 and ys < threshold)

    tpr = round(tp / positives, 4) if positives > 0 else 0.0
    fpr = round(fp / negatives, 4) if negatives > 0 else 0.0

    tpr_low, tpr_high = wilson_score_interval(tp, positives)
    fpr_low, fpr_high = wilson_score_interval(fp, negatives)

    # Sensitivity analysis across typical dependency update prevalences
    ppv_table = {
        "1e-2 (1%)": calculate_ppv(tpr, fpr, 0.01),
        "1e-3 (0.1%)": calculate_ppv(tpr, fpr, 0.001),
        "1e-4 (0.01%)": calculate_ppv(tpr, fpr, 0.0001),
    }

    return TrackResult(
        track_name=track_name,
        total_samples=total,
        positives=positives,
        negatives=negatives,
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        tpr=tpr,
        tpr_ci_low=tpr_low,
        tpr_ci_high=tpr_high,
        fpr=fpr,
        fpr_ci_low=fpr_low,
        fpr_ci_high=fpr_high,
        ppv_table=ppv_table,
    )
