"""Unit tests for code fact extraction and fact-set diffing."""

import hashlib
import unittest

from bumpguard.analyze.analyzer import FactExtractor
from bumpguard.analyze.diff_engine import compare_package_archives
from bumpguard.core.types import Context, Ecosystem, FactKind, PackageRef, Severity
from bumpguard.extract.safe_extractor import ExtractedArchive, ExtractedFile


def _make_file(path: str, content: str) -> ExtractedFile:
    raw = content.encode("utf-8")
    return ExtractedFile(
        path=path,
        content=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
    )


class TestAnalyzer(unittest.TestCase):
    def test_fact_extraction_patterns(self):
        extractor = FactExtractor()
        file = _make_file(
            "index.js",
            """
            const http = require('http');
            const { exec } = require('child_process');
            eval('2 + 2');
            const token = process.env.NPM_TOKEN;
            """,
        )

        facts = extractor.extract_file_facts(file, Context.Import)
        rule_ids = {cf.rule_id for cf in facts}
        kinds = {cf.fact.kind for cf in facts}

        self.assertIn("BG-CODE-001", rule_ids) # Network
        self.assertIn("BG-CODE-002", rule_ids) # Exec
        self.assertIn("BG-CODE-003", rule_ids) # DynamicEval
        self.assertIn("BG-CODE-005", rule_ids) # Token

        self.assertIn(FactKind.Network, kinds)
        self.assertIn(FactKind.Exec, kinds)
        self.assertIn(FactKind.DynamicEval, kinds)
        self.assertIn(FactKind.EnvRead, kinds)

    def test_fact_diff_moving_code_is_not_new(self):
        pkg = PackageRef(Ecosystem.NPM, "moving-lib", "1.0.0", "1.1.0")

        # In 1.0.0, child_process is in lib/worker.js
        old_archive = ExtractedArchive(
            files={
                "package.json": _make_file("package.json", '{"name":"moving-lib","main":"index.js"}'),
                "lib/worker.js": _make_file("lib/worker.js", "const cp = require('child_process'); cp.exec('ls');"),
            },
            total_uncompressed_bytes=100,
            file_count=2,
        )

        # In 1.1.0, the same child_process call is refactored into lib/runner.js (same Context.Other)
        new_archive = ExtractedArchive(
            files={
                "package.json": _make_file("package.json", '{"name":"moving-lib","main":"index.js"}'),
                "lib/runner.js": _make_file("lib/runner.js", "const cp = require('child_process'); cp.exec('ls');"),
            },
            total_uncompressed_bytes=100,
            file_count=2,
        )

        diff = compare_package_archives(pkg, old_archive, new_archive)

        # Moving existing behavior within the same execution context should NOT flag as newly added behavior
        exec_findings = [f for f in diff.added_findings if f.rule_id == "BG-CODE-002"]
        self.assertEqual(len(exec_findings), 0)

    def test_fact_diff_detects_new_network_call_and_gyp(self):
        pkg = PackageRef(Ecosystem.NPM, "demo-lib", "1.0.0", "1.0.1")

        old_archive = ExtractedArchive(
            files={
                "package.json": _make_file("package.json", '{"name":"demo-lib","main":"index.js"}'),
                "index.js": _make_file("index.js", "function add(a, b) { return a + b; }"),
            },
            total_uncompressed_bytes=80,
            file_count=2,
        )

        new_archive = ExtractedArchive(
            files={
                "package.json": _make_file(
                    "package.json",
                    '{"name":"demo-lib","main":"index.js","scripts":{"postinstall":"node post.js"}}',
                ),
                "index.js": _make_file("index.js", "function add(a, b) { return a + b; }"),
                "post.js": _make_file("post.js", "const https = require('https'); https.get('https://example.com');"),
                "binding.gyp": _make_file("binding.gyp", '{"targets": [{"target_name": "addon"}]}'),
            },
            total_uncompressed_bytes=250,
            file_count=4,
        )

        diff = compare_package_archives(pkg, old_archive, new_archive)
        rule_ids = {f.rule_id for f in diff.added_findings}

        self.assertIn("BG-EXEC-001", rule_ids) # New postinstall script
        self.assertIn("BG-EXEC-002", rule_ids) # New binding.gyp
        self.assertIn("BG-CODE-001", rule_ids) # New network call


if __name__ == "__main__":
    unittest.main()
