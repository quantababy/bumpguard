"""Unit tests for registry metadata evaluation."""

import datetime
import unittest

from bumpguard.core.types import Ecosystem, PackageRef, Severity
from bumpguard.registry.client import NpmRegistryClient, PackageMetadata, VersionMetadata


class TestRegistry(unittest.TestCase):
    def test_metadata_rules_evaluation(self):
        client = NpmRegistryClient()

        fixed_now = datetime.datetime(2026, 11, 10, 12, 0, 0, tzinfo=datetime.timezone.utc)
        pub_old = datetime.datetime(2025, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        pub_new = datetime.datetime(2026, 11, 10, 2, 0, 0, tzinfo=datetime.timezone.utc) # 10 hours old

        metadata = PackageMetadata(
            name="test-lib",
            versions={
                "1.0.0": VersionMetadata(
                    version="1.0.0",
                    publisher="alice",
                    published_at=pub_old,
                    integrity="sha512-old",
                ),
                "1.1.0": VersionMetadata(
                    version="1.1.0",
                    publisher="mallory", # Publisher changed!
                    published_at=pub_new, # Fresh release! (< 72h)
                    integrity=None,      # Missing integrity!
                ),
            },
        )

        pkg_ref = PackageRef(
            ecosystem=Ecosystem.NPM,
            name="test-lib",
            old_version="1.0.0",
            new_version="1.1.0",
        )

        findings = client.evaluate_metadata_rules(pkg_ref, metadata, current_time=fixed_now)
        rule_ids = {f.rule_id for f in findings}

        self.assertIn("BG-META-001", rule_ids) # Publisher changed
        self.assertIn("BG-META-003", rule_ids) # Fresh release (< 72h)
        self.assertIn("BG-POL-003", rule_ids)  # Missing integrity


if __name__ == "__main__":
    unittest.main()
