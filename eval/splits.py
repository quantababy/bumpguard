"""Cluster-aware and temporal dataset splitting schemes (Section 6.4)."""

from __future__ import annotations

from typing import Dict, List, Tuple

from .manifest import EvalSample


def time_based_split(
    samples: List[EvalSample], cutoff_date: str = "2026-08-01"
) -> Tuple[List[EvalSample], List[EvalSample]]:
    """Temporal split: train on earlier releases, test on later ones.
    Simulates real-world scenario where detector trains on historical attacks
    and evaluates on future, evolving attackers.
    """
    train = [s for s in samples if s.published_date < cutoff_date]
    test = [s for s in samples if s.published_date >= cutoff_date]
    return train, test


def cluster_aware_group_split(
    samples: List[EvalSample], test_cluster_modulo: int = 3
) -> Tuple[List[EvalSample], List[EvalSample]]:
    """Cluster-aware group split: ensures near-duplicate packages sharing
    a cluster_id never appear in both train and test splits, preventing data leakage.
    """
    train: List[EvalSample] = []
    test: List[EvalSample] = []

    for s in samples:
        # Group by hash of cluster_id to ensure determinism
        group_val = sum(ord(c) for c in s.cluster_id)
        if (group_val % test_cluster_modulo) == 0:
            test.append(s)
        else:
            train.append(s)

    return train, test
