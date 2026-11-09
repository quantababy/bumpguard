"""Unified evaluation pipeline driver (Section 6.8 'make eval')."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List

from .manifest import EvalSample, generate_benchmark_samples, save_manifest
from .metrics import TrackResult, evaluate_predictions
from .model import CalibratedModel, train_calibrated_model
from .splits import cluster_aware_group_split, time_based_split


def run_evaluation(manifest_path: str = "eval/results/manifest.json") -> Dict:
    """Run full evaluation suite across Diff and New-Package tracks."""
    samples = generate_benchmark_samples()
    save_manifest(samples, manifest_path)

    # 1. Strictly separate tracks per Section 6.3
    diff_samples = [s for s in samples if s.track == "diff"]
    new_pkg_samples = [s for s in samples if s.track == "new_package"]

    # 2. Train calibrated model on train split using cluster-aware partitioning
    train_diff, test_diff = cluster_aware_group_split(diff_samples)
    train_pool = train_diff + [s for s in new_pkg_samples if "cluster-new-benign-1" not in s.cluster_id]
    model = train_calibrated_model(train_pool)

    # Export model weights for production scorer integration
    weights_path = Path("backend/bumpguard/model_weights.json")
    weights_path.parent.mkdir(parents=True, exist_ok=True)
    weights_path.write_text(json.dumps(model.to_dict(), indent=2), encoding="utf-8")

    # 3. Evaluate Track 1: Diff Track (Hijacked releases vs benign bumps)
    y_diff_true = [1 if s.label == "compromised_lib" else 0 for s in diff_samples]
    # Model scores
    y_diff_scores = [model.predict_proba(s.features) for s in diff_samples]
    # Baseline Heuristic A: has install script
    y_heur_a = [s.features.get("has_install_script", 0.0) for s in diff_samples]
    # Baseline Heuristic B: any network call
    y_heur_b = [s.features.get("new_network_call", 0.0) for s in diff_samples]

    diff_model_res = evaluate_predictions(y_diff_true, y_diff_scores, threshold=0.5, track_name="Diff Track (bumpguard)")
    diff_heur_a_res = evaluate_predictions(y_diff_true, y_heur_a, threshold=0.5, track_name="Diff Track (Heuristic A: Install Script)")
    diff_heur_b_res = evaluate_predictions(y_diff_true, y_heur_b, threshold=0.5, track_name="Diff Track (Heuristic B: Any Network)")

    # 4. Evaluate Track 2: New-Package Track
    y_new_true = [1 if s.label == "malicious_intent" else 0 for s in new_pkg_samples]
    y_new_scores = [model.predict_proba(s.features) for s in new_pkg_samples]
    new_model_res = evaluate_predictions(y_new_true, y_new_scores, threshold=0.5, track_name="New-Package Track (bumpguard)")

    results_data = {
        "calibrated_model": model.to_dict(),
        "diff_track": {
            "bumpguard": asdict(diff_model_res),
            "heuristic_install_script": asdict(diff_heur_a_res),
            "heuristic_network_call": asdict(diff_heur_b_res),
        },
        "new_package_track": {
            "bumpguard": asdict(new_model_res),
        },
    }

    results_file = Path("eval/results/results.json")
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text(json.dumps(results_data, indent=2), encoding="utf-8")

    return results_data


def generate_markdown_summary(results: Dict) -> str:
    """Generate Markdown summary table with Wilson confidence intervals."""
    diff_bg = results["diff_track"]["bumpguard"]
    diff_ha = results["diff_track"]["heuristic_install_script"]
    diff_hb = results["diff_track"]["heuristic_network_call"]
    new_bg = results["new_package_track"]["bumpguard"]

    md = [
        "### Empirical Evaluation Results (Separate Tracks & Wilson 95% CIs)\n",
        "#### Track 1: Diff Track (Compromised Releases with Available Predecessor)",
        "| Approach | TPR (Recall) | 95% CI (TPR) | FPR (False Alarms) | 95% CI (FPR) | PPV at 0.1% Prev |",
        "|---|---|---|---|---|---|",
        f"| **bumpguard (Diff-First)** | **{diff_bg['tpr']*100:.1f}%** | [{diff_bg['tpr_ci_low']*100:.1f}%, {diff_bg['tpr_ci_high']*100:.1f}%] | **{diff_bg['fpr']*100:.1f}%** | [{diff_bg['fpr_ci_low']*100:.1f}%, {diff_bg['fpr_ci_high']*100:.1f}%] | **{diff_bg['ppv_table']['1e-3 (0.1%)']*100:.1f}%** |",
        f"| Heuristic A (Install Script) | {diff_ha['tpr']*100:.1f}% | [{diff_ha['tpr_ci_low']*100:.1f}%, {diff_ha['tpr_ci_high']*100:.1f}%] | {diff_ha['fpr']*100:.1f}% | [{diff_ha['fpr_ci_low']*100:.1f}%, {diff_ha['fpr_ci_high']*100:.1f}%] | {diff_ha['ppv_table']['1e-3 (0.1%)']*100:.1f}% |",
        f"| Heuristic B (Any Network) | {diff_hb['tpr']*100:.1f}% | [{diff_hb['tpr_ci_low']*100:.1f}%, {diff_hb['tpr_ci_high']*100:.1f}%] | {diff_hb['fpr']*100:.1f}% | [{diff_hb['fpr_ci_low']*100:.1f}%, {diff_hb['fpr_ci_high']*100:.1f}%] | {diff_hb['ppv_table']['1e-3 (0.1%)']*100:.1f}% |\n",
        "#### Track 2: New-Package Track (Zero-History Malicious Packages)",
        "| Approach | TPR (Recall) | 95% CI (TPR) | FPR (False Alarms) | 95% CI (FPR) |",
        "|---|---|---|---|---|",
        f"| **bumpguard (Full Package)** | **{new_bg['tpr']*100:.1f}%** | [{new_bg['tpr_ci_low']*100:.1f}%, {new_bg['tpr_ci_high']*100:.1f}%] | **{new_bg['fpr']*100:.1f}%** | [{new_bg['fpr_ci_low']*100:.1f}%, {new_bg['fpr_ci_high']*100:.1f}%] |",
    ]
    return "\n".join(md)


if __name__ == "__main__":
    res = run_evaluation()
    print(generate_markdown_summary(res))
