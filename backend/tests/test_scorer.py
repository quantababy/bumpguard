"""Unit tests for package risk calculation and critical overrides."""

import unittest

from bumpguard.core.types import Ecosystem, Finding, PackageRef, Severity
from bumpguard.score.scorer import calculate_package_risk


class TestScorer(unittest.TestCase):
    def test_clean_package_scores_zero(self):
        pkg = PackageRef(Ecosystem.NPM, "clean-pkg", "1.0.0", "1.0.1")
        scored = calculate_package_risk(pkg, [])

        self.assertEqual(scored.total_score, 0.0)
        self.assertEqual(scored.risk_level, Severity.Low)
        self.assertFalse(scored.needs_review)

    def test_moderate_package_scores_medium_or_high(self):
        pkg = PackageRef(Ecosystem.NPM, "mod-pkg", "2.0.0", "2.1.0")
        f1 = Finding(
            rule_id="BG-CODE-001",
            severity=Severity.High,
            weight=7.0,
            package=pkg,
            why="New network call",
        )
        f2 = Finding(
            rule_id="BG-META-001",
            severity=Severity.Medium,
            weight=5.0,
            package=pkg,
            why="Publisher changed",
        )

        scored = calculate_package_risk(pkg, [f1, f2])
        self.assertEqual(scored.total_score, 12.0)
        self.assertEqual(scored.risk_level, Severity.High)
        self.assertTrue(scored.needs_review)

    def test_worm_propagation_critical_override(self):
        pkg = PackageRef(Ecosystem.NPM, "worm-pkg", "1.0.0", "1.0.1")
        f = Finding(
            rule_id="BG-CODE-006",
            severity=Severity.Critical,
            weight=10.0,
            package=pkg,
            why="npm publish call in codebase",
        )

        scored = calculate_package_risk(pkg, [f])
        self.assertEqual(scored.risk_level, Severity.Critical)
        self.assertTrue(scored.needs_review)


if __name__ == "__main__":
    unittest.main()
