"""Unit tests for SARIF report formatting."""

import json
import unittest

from bumpguard.core.types import Ecosystem, Finding, PackageRef, Severity
from bumpguard.report.sarif import format_sarif_report
from bumpguard.score.scorer import ScoredPackage


class TestSarif(unittest.TestCase):
    def test_sarif_schema_structure(self):
        pkg = PackageRef(Ecosystem.NPM, "left-padz", "1.2.3", "1.2.4")
        f = Finding(
            rule_id="BG-CODE-001",
            severity=Severity.High,
            weight=7.0,
            package=pkg,
            file="index.js",
            line=4,
            evidence="require('https').get(...)",
            why="New Network call introduced",
        )
        scored = ScoredPackage(
            package=pkg,
            findings=[f],
            total_score=10.0,
            risk_level=Severity.High,
            reasons=["New Network call introduced"],
        )

        sarif_json = format_sarif_report([scored])
        doc = json.loads(sarif_json)

        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"]), 1)
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "bumpguard")
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)
        self.assertEqual(run["tool"]["driver"]["rules"][0]["id"], "BG-CODE-001")
        self.assertEqual(len(run["results"]), 1)
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "index.js",
        )


if __name__ == "__main__":
    unittest.main()
