"""Unit tests for core bumpguard data structures."""

import unittest

from bumpguard.core.types import (
    Context,
    Ecosystem,
    Fact,
    FactKind,
    Finding,
    PackageRef,
    Severity,
)


class TestCoreTypes(unittest.TestCase):
    def test_fact_equality_and_hashing(self):
        f1 = Fact(kind=FactKind.Network, api="fetch", context=Context.Import)
        f2 = Fact(kind=FactKind.Network, api="fetch", context=Context.Import)
        f3 = Fact(kind=FactKind.Network, api="fetch", context=Context.Install)

        self.assertEqual(f1, f2)
        self.assertNotEqual(f1, f3)
        self.assertEqual(hash(f1), hash(f2))

        # Test set deduplication and difference
        s1 = {f1, f3}
        s2 = {f2}
        diff = s1 - s2
        self.assertEqual(diff, {f3})

    def test_package_ref_change_label(self):
        pkg_bump = PackageRef(
            ecosystem=Ecosystem.NPM,
            name="express",
            old_version="4.18.2",
            new_version="4.19.0",
        )
        self.assertFalse(pkg_bump.is_new_package)
        self.assertEqual(pkg_bump.change_label, "4.18.2 → 4.19.0")

        pkg_new = PackageRef(
            ecosystem=Ecosystem.NPM,
            name="mal-pkg",
            old_version=None,
            new_version="1.0.0",
        )
        self.assertTrue(pkg_new.is_new_package)
        self.assertEqual(pkg_new.change_label, "added 1.0.0")

    def test_severity_ordering(self):
        self.assertTrue(Severity.High.meets_threshold(Severity.Medium))
        self.assertTrue(Severity.Critical.meets_threshold(Severity.High))
        self.assertFalse(Severity.Low.meets_threshold(Severity.High))

    def test_finding_serialization(self):
        pkg = PackageRef(
            ecosystem=Ecosystem.NPM,
            name="axios",
            old_version="1.5.0",
            new_version="1.6.0",
        )
        finding = Finding(
            rule_id="BG-CODE-001",
            severity=Severity.High,
            weight=7.0,
            package=pkg,
            file="lib/core/dispatchRequest.js",
            line=42,
            evidence="require('http')",
            why="new network call introduced",
        )
        data = finding.to_dict()
        self.assertEqual(data["rule_id"], "BG-CODE-001")
        self.assertEqual(data["severity"], "High")
        self.assertEqual(data["package"]["name"], "axios")


if __name__ == "__main__":
    unittest.main()
