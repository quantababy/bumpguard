"""Unit tests for report formatting."""

import json
import unittest

from bumpguard.core.types import Ecosystem, Finding, PackageRef, Severity
from bumpguard.report.reporter import format_json_report, format_markdown_report
from bumpguard.score.scorer import ScoredPackage


class TestReporter(unittest.TestCase):
    def test_markdown_clean_report(self):
        pkg = PackageRef(Ecosystem.NPM, "safe-pkg", "1.0.0", "1.0.1")
        scored = ScoredPackage(
            package=pkg,
            findings=[],
            total_score=0.0,
            risk_level=Severity.Low,
        )
        md = format_markdown_report([scored])
        self.assertIn("1 updates scanned", md)
        self.assertIn("All 1 updates had no new risk signals", md)

    def test_markdown_flagged_report(self):
        pkg = PackageRef(Ecosystem.NPM, "left-padz", "1.2.3", "1.2.4")
        f = Finding(
            rule_id="BG-CODE-001",
            severity=Severity.High,
            weight=7.0,
            package=pkg,
            why="new network call at import",
        )
        scored = ScoredPackage(
            package=pkg,
            findings=[f],
            total_score=10.5,
            risk_level=Severity.High,
            reasons=["new network call at import"],
        )
        md = format_markdown_report([scored])
        self.assertIn("1 of 1 updates need review", md)
        self.assertIn("| left-padz | 1.2.3 → 1.2.4 | High | new network call at import |", md)

    def test_json_report_structure(self):
        pkg = PackageRef(Ecosystem.NPM, "left-padz", "1.2.3", "1.2.4")
        scored = ScoredPackage(
            package=pkg,
            findings=[],
            total_score=0.0,
            risk_level=Severity.Low,
        )
        raw_json = format_json_report([scored])
        data = json.loads(raw_json)
        self.assertEqual(data["summary"]["total_packages"], 1)
        self.assertEqual(data["summary"]["needing_review"], 0)
        self.assertEqual(data["packages"][0]["package"]["name"], "left-padz")


if __name__ == "__main__":
    unittest.main()
