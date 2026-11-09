"""Unit and integration tests for CLI parser and diff commands."""

import json
import tempfile
import unittest
from pathlib import Path

from bumpguard.cli import build_parser, cmd_diff


class TestCli(unittest.TestCase):
    def test_parser_subcommands(self):
        parser = build_parser()
        args = parser.parse_args(["diff", "--base", "v1.0.0", "--head", "v1.1.0", "--fail-on", "medium"])
        self.assertEqual(args.subcommand, "diff")
        self.assertEqual(args.base, "v1.0.0")
        self.assertEqual(args.fail_on, "medium")

    def test_cli_diff_file_paths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            base_file = Path(tmpdir) / "base.json"
            head_file = Path(tmpdir) / "head.json"

            base_file.write_text(json.dumps({
                "packages": {
                    "node_modules/my-pkg": {"version": "1.0.0"}
                }
            }))
            head_file.write_text(json.dumps({
                "packages": {
                    "node_modules/my-pkg": {"version": "1.0.1"}
                }
            }))

            parser = build_parser()
            args = parser.parse_args([
                "diff",
                "--base", str(base_file),
                "--head", str(head_file),
                "--format", "json",
            ])

            # Should return 0 since no critical findings exist
            code = cmd_diff(args)
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
