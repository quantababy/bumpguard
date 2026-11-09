"""Unit tests for evaluation harness, splits, and calibrated scoring."""

import unittest

from eval.manifest import generate_benchmark_samples
from eval.metrics import calculate_ppv, evaluate_predictions, wilson_score_interval
from eval.model import train_calibrated_model
from eval.splits import cluster_aware_group_split, time_based_split


class TestEvalPipeline(unittest.TestCase):
    def test_wilson_confidence_interval(self):
        # 10 successes out of 10 -> high proportion, confidence interval bounds in [0, 1]
        low, high = wilson_score_interval(10, 10)
        self.assertGreater(low, 0.65)
        self.assertEqual(high, 1.0)

        # 0 successes out of 100
        low, high = wilson_score_interval(0, 100)
        self.assertEqual(low, 0.0)
        self.assertLess(high, 0.05)

    def test_ppv_calculation(self):
        # At TPR = 0.9, FPR = 0.01, prevalence = 0.01
        ppv = calculate_ppv(0.9, 0.01, 0.01)
        # Expected ~0.476 (47.6%) per Section 5.2 table
        self.assertAlmostEqual(ppv, 0.4762, places=2)

    def test_cluster_aware_splitting_no_leakage(self):
        samples = generate_benchmark_samples()
        train, test = cluster_aware_group_split(samples)

        train_clusters = {s.cluster_id for s in train}
        test_clusters = {s.cluster_id for s in test}

        # Crucial security invariant: train and test sets must NOT share any cluster_ids
        shared = train_clusters.intersection(test_clusters)
        self.assertEqual(len(shared), 0, f"Data leakage detected! Shared clusters: {shared}")

    def test_time_based_split(self):
        samples = generate_benchmark_samples()
        train, test = time_based_split(samples, cutoff_date="2026-08-01")

        for s in train:
            self.assertLess(s.published_date, "2026-08-01")
        for s in test:
            self.assertGreaterEqual(s.published_date, "2026-08-01")


if __name__ == "__main__":
    unittest.main()
