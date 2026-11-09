"""Unit tests for lockfile parsing and diff generation."""

import json
import unittest

from bumpguard.lockfile.diff import diff_lockfiles
from bumpguard.lockfile.parser import parse_package_lock


class TestLockfile(unittest.TestCase):
    def test_parse_v2_v3_packages(self):
        content = json.dumps({
            "name": "my-app",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "my-app", "version": "1.0.0"},
                "node_modules/left-pad": {
                    "version": "1.2.3",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.3.tgz",
                    "integrity": "sha512-test123",
                    "dev": False,
                },
                "node_modules/@scope/tool": {
                    "version": "2.0.0",
                    "dev": True,
                },
            },
        })

        entries = parse_package_lock(content)
        self.assertIn("left-pad", entries)
        self.assertEqual(entries["left-pad"].version, "1.2.3")
        self.assertEqual(entries["left-pad"].integrity, "sha512-test123")
        self.assertFalse(entries["left-pad"].dev)

        self.assertIn("@scope/tool", entries)
        self.assertEqual(entries["@scope/tool"].version, "2.0.0")
        self.assertTrue(entries["@scope/tool"].dev)

    def test_diff_lockfiles(self):
        base_json = json.dumps({
            "packages": {
                "node_modules/left-pad": {"version": "1.2.3"},
                "node_modules/old-dep": {"version": "0.1.0"},
                "node_modules/stable-dep": {"version": "1.0.0"},
            }
        })
        head_json = json.dumps({
            "packages": {
                "node_modules/left-pad": {"version": "1.2.4"},  # Bumped
                "node_modules/new-dep": {"version": "3.0.0"},   # Added
                "node_modules/stable-dep": {"version": "1.0.0"}, # Unchanged
            }
        })

        base = parse_package_lock(base_json)
        head = parse_package_lock(head_json)

        changed, removed = diff_lockfiles(base, head)

        # Verify changed/added
        names = {p.name: p for p in changed}
        self.assertIn("left-pad", names)
        self.assertEqual(names["left-pad"].old_version, "1.2.3")
        self.assertEqual(names["left-pad"].new_version, "1.2.4")

        self.assertIn("new-dep", names)
        self.assertIsNone(names["new-dep"].old_version)
        self.assertEqual(names["new-dep"].new_version, "3.0.0")

        self.assertNotIn("stable-dep", names)
        self.assertEqual(removed, ["old-dep"])


if __name__ == "__main__":
    unittest.main()
