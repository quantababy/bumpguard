"""Manifest generator for Bumpguard evaluation pipeline (Section 6.4)."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class EvalSample:
    sample_id: str
    ecosystem: str
    name: str
    version: str
    predecessor_version: Optional[str]
    track: str  # "diff" or "new_package"
    label: str  # "compromised_lib", "malicious_intent", or "benign"
    cluster_id: str  # Cluster ID to prevent near-duplicate leakage
    published_date: str  # "YYYY-MM-DD" for temporal split
    source: str
    features: Dict[str, float]


def generate_benchmark_samples() -> List[EvalSample]:
    """Generate canonical evaluation dataset with strictly separated tracks.
    
    Track 1: Diff Track (compromised_lib vs benign updates with predecessor)
    Track 2: New-Package Track (malicious_intent vs benign initial releases)
    """
    samples: List[EvalSample] = []

    # --- TRACK 1: DIFF TRACK (compromised_lib vs benign updates) ---
    # 1. Compromised libraries (hijacked accounts, backdoored updates)
    samples.append(
        EvalSample(
            sample_id="diff-mal-001",
            ecosystem="npm",
            name="left-padz",
            version="1.2.4",
            predecessor_version="1.2.3",
            track="diff",
            label="compromised_lib",
            cluster_id="cluster-exfil-net",
            published_date="2026-06-15",
            source="synthetic_compromised",
            features={
                "has_install_script": 0.0,
                "new_network_call": 1.0,
                "new_process_exec": 0.0,
                "new_eval": 0.0,
                "new_credential_read": 0.0,
                "publisher_changed": 1.0,
                "fresh_release": 1.0,
                "import_context": 1.0,
            },
        )
    )
    samples.append(
        EvalSample(
            sample_id="diff-mal-002",
            ecosystem="npm",
            name="event-stream-canary",
            version="3.3.6",
            predecessor_version="3.3.5",
            track="diff",
            label="compromised_lib",
            cluster_id="cluster-flatmap-stream",
            published_date="2026-07-01",
            source="synthetic_compromised",
            features={
                "has_install_script": 0.0,
                "new_network_call": 1.0,
                "new_process_exec": 0.0,
                "new_eval": 1.0,
                "new_credential_read": 1.0,
                "publisher_changed": 1.0,
                "fresh_release": 1.0,
                "import_context": 1.0,
            },
        )
    )
    samples.append(
        EvalSample(
            sample_id="diff-mal-003",
            ecosystem="npm",
            name="native-gyp-attack",
            version="2.0.1",
            predecessor_version="2.0.0",
            track="diff",
            label="compromised_lib",
            cluster_id="cluster-gyp-abuse",
            published_date="2026-08-10",
            source="synthetic_compromised",
            features={
                "has_install_script": 0.0,
                "new_network_call": 0.0,
                "new_process_exec": 1.0,
                "new_eval": 0.0,
                "new_credential_read": 0.0,
                "publisher_changed": 0.0,
                "fresh_release": 1.0,
                "has_binding_gyp": 1.0,
                "import_context": 0.0,
            },
        )
    )
    samples.append(
        EvalSample(
            sample_id="diff-mal-004",
            ecosystem="npm",
            name="lifecycle-trojan",
            version="1.4.0",
            predecessor_version="1.3.9",
            track="diff",
            label="compromised_lib",
            cluster_id="cluster-postinstall-curl",
            published_date="2026-09-02",
            source="synthetic_compromised",
            features={
                "has_install_script": 1.0,
                "new_network_call": 1.0,
                "new_process_exec": 1.0,
                "new_eval": 0.0,
                "new_credential_read": 1.0,
                "publisher_changed": 1.0,
                "fresh_release": 1.0,
                "import_context": 0.0,
            },
        )
    )

    # 2. Benign updates with existing behavior (Crucial: testing false-alarm reduction)
    for i in range(1, 21):
        # Benign packages that spawn processes or make network calls as part of normal functionality
        is_cli = (i % 2 == 0)
        samples.append(
            EvalSample(
                sample_id=f"diff-benign-{i:03d}",
                ecosystem="npm",
                name=f"popular-lib-{i}",
                version="2.1.0",
                predecessor_version="2.0.9",
                track="diff",
                label="benign",
                cluster_id=f"cluster-benign-family-{i % 5}",
                published_date=f"2026-0{min(9, (i % 8) + 1):02d}-15",
                source="benign_corpus",
                features={
                    # Diff-first design: existing network/exec is NOT new!
                    "has_install_script": 0.0,
                    "new_network_call": 0.0,
                    "new_process_exec": 0.0,
                    "new_eval": 0.0,
                    "new_credential_read": 0.0,
                    "publisher_changed": 0.0,
                    "fresh_release": 0.0,
                    "import_context": 0.0,
                },
            )
        )

    # --- TRACK 2: NEW-PACKAGE TRACK (malicious_intent vs benign new packages) ---
    samples.append(
        EvalSample(
            sample_id="new-mal-001",
            ecosystem="npm",
            name="suspicious-telemetry",
            version="1.0.0",
            predecessor_version=None,
            track="new_package",
            label="malicious_intent",
            cluster_id="cluster-worm-prop",
            published_date="2026-10-01",
            source="synthetic_malicious",
            features={
                "has_install_script": 0.0,
                "new_network_call": 1.0,
                "new_process_exec": 1.0,
                "new_eval": 0.0,
                "new_credential_read": 1.0,
                "worm_propagation": 1.0,
                "publisher_changed": 0.0,
                "fresh_release": 1.0,
                "import_context": 1.0,
            },
        )
    )
    samples.append(
        EvalSample(
            sample_id="new-mal-002",
            ecosystem="pypi",
            name="pth-backdoor-pkg",
            version="0.1.0",
            predecessor_version=None,
            track="new_package",
            label="malicious_intent",
            cluster_id="cluster-pth-persist",
            published_date="2026-10-15",
            source="synthetic_malicious",
            features={
                "has_install_script": 0.0,
                "new_network_call": 1.0,
                "new_process_exec": 0.0,
                "new_eval": 0.0,
                "new_credential_read": 0.0,
                "has_pth_file": 1.0,
                "fresh_release": 1.0,
                "import_context": 1.0,
            },
        )
    )

    for i in range(1, 11):
        samples.append(
            EvalSample(
                sample_id=f"new-benign-{i:03d}",
                ecosystem="npm",
                name=f"fresh-new-utility-{i}",
                version="1.0.0",
                predecessor_version=None,
                track="new_package",
                label="benign",
                cluster_id=f"cluster-new-benign-{i % 3}",
                published_date=f"2026-10-{i + 10:02d}",
                source="benign_corpus",
                features={
                    "has_install_script": 0.0,
                    "new_network_call": 0.0,
                    "new_process_exec": 0.0,
                    "new_eval": 0.0,
                    "new_credential_read": 0.0,
                    "fresh_release": 1.0,
                    "import_context": 0.0,
                },
            )
        )

    return samples


def save_manifest(samples: List[EvalSample], output_path: str) -> None:
    """Save manifest to JSON / Parquet-compatible file."""
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    records = [asdict(s) for s in samples]
    p.write_text(json.dumps(records, indent=2), encoding="utf-8")


def load_manifest(input_path: str) -> List[EvalSample]:
    """Load manifest records."""
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    return [EvalSample(**d) for d in data]
