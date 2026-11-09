"""Unit tests for configuration loading and expiring ignore rules."""

import datetime
import unittest

from bumpguard.config import parse_config_toml
from bumpguard.core.types import Ecosystem, Finding, PackageRef, Severity


class TestConfig(unittest.TestCase):
    def test_parse_config_and_unexpired_ignore(self):
        toml_content = """
        [policy]
        fail_on = "critical"
        max_findings_in_comment = 10

        [ecosystems]
        npm = true
        pypi = false

        [[ignore]]
        package = "esbuild"
        rule = "BG-EXEC-001"
        reason = "known binary download"
        expires = "2027-01-01"
        """

        config = parse_config_toml(toml_content)
        self.assertEqual(config.fail_on, Severity.Critical)
        self.assertEqual(config.max_findings_in_comment, 10)
        self.assertFalse(config.pypi_enabled)
        self.assertEqual(len(config.ignores), 1)

        pkg = PackageRef(Ecosystem.NPM, "esbuild", "0.19.0", "0.20.0")
        f1 = Finding(rule_id="BG-EXEC-001", severity=Severity.High, weight=7.0, package=pkg)
        f2 = Finding(rule_id="BG-CODE-001", severity=Severity.High, weight=7.0, package=pkg)

        # On 2026-11-10, rule is NOT expired -> BG-EXEC-001 is ignored, BG-CODE-001 remains
        today = datetime.date(2026, 11, 10)
        filtered = config.filter_findings("esbuild", [f1, f2], current_date=today)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].rule_id, "BG-CODE-001")

    def test_expired_ignore_rule_does_not_filter(self):
        toml_content = """
        [[ignore]]
        package = "esbuild"
        rule = "BG-EXEC-001"
        reason = "expired ignore"
        expires = "2026-01-01"
        """
        config = parse_config_toml(toml_content)
        pkg = PackageRef(Ecosystem.NPM, "esbuild", "0.19.0", "0.20.0")
        f = Finding(rule_id="BG-EXEC-001", severity=Severity.High, weight=7.0, package=pkg)

        # On 2026-11-10, the ignore expired on 2026-01-01 -> rule must trigger!
        today = datetime.date(2026, 11, 10)
        filtered = config.filter_findings("esbuild", [f], current_date=today)
        self.assertEqual(len(filtered), 1)


if __name__ == "__main__":
    unittest.main()
