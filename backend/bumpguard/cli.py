"""Command-line interface for bumpguard."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from bumpguard.core.types import Ecosystem, PackageRef, Severity
from bumpguard.lockfile.diff import diff_lockfiles
from bumpguard.lockfile.parser import parse_package_lock
from bumpguard.registry.client import NpmRegistryClient
from bumpguard.report.reporter import format_json_report, format_markdown_report
from bumpguard.score.scorer import ScoredPackage, calculate_package_risk
from bumpguard.server import run_server


def read_lockfile_from_ref_or_file(ref_or_path: str, filename: str = "package-lock.json") -> str:
    """Read lockfile either directly from filesystem or from a git revision."""
    p = Path(ref_or_path)
    if p.is_file():
        return p.read_text(encoding="utf-8")

    # If directory, look for package-lock.json inside
    if p.is_dir() and (p / filename).is_file():
        return (p / filename).read_text(encoding="utf-8")

    # If it looks like a file path (has extension or path separator) and is missing on disk
    if p.suffix in (".json", ".yaml", ".yml", ".lock") or "/" in ref_or_path or "\\" in ref_or_path:
        raise FileNotFoundError(
            f"File '{ref_or_path}' was not found. Please verify the file path."
        )

    # Otherwise, try git show <ref>:<filename>
    try:
        cmd = ["git", "show", f"{ref_or_path}:{filename}"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except Exception:
        raise FileNotFoundError(
            f"Git reference or commit '{ref_or_path}' could not be resolved with file '{filename}'."
        )


def cmd_diff(args: argparse.Namespace) -> int:
    """Execute bumpguard diff command."""
    try:
        base_content = read_lockfile_from_ref_or_file(args.base)
        head_content = read_lockfile_from_ref_or_file(args.head)
    except Exception as err:
        sys.stderr.write(f"Error loading lockfiles: {err}\n")
        return 2

    base_entries = parse_package_lock(base_content)
    head_entries = parse_package_lock(head_content)

    changed, removed = diff_lockfiles(base_entries, head_entries, ignore_dev=args.ignore_dev)
    client = NpmRegistryClient()

    scored_packages: List[ScoredPackage] = []
    for pkg in changed:
        findings = []
        # Query registry for metadata signals
        packument = client.fetch_packument(pkg.name)
        if packument:
            meta = client.parse_metadata(packument)
            findings.extend(client.evaluate_metadata_rules(pkg, meta))

        scored = calculate_package_risk(pkg, findings)
        scored_packages.append(scored)

    # Format output
    if args.format == "json":
        print(format_json_report(scored_packages))
    else:
        print(format_markdown_report(scored_packages))

    # Evaluate fail-on threshold
    fail_threshold = Severity[args.fail_on.capitalize()]
    exceeded = [
        p for p in scored_packages
        if p.risk_level.meets_threshold(fail_threshold)
    ]

    return 1 if exceeded else 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Execute bumpguard serve command to launch integrated server and UI."""
    frontend_dir = args.frontend_dir
    if not frontend_dir:
        # Default to sibling frontend/ directory
        default_frontend = Path(__file__).resolve().parent.parent.parent / "frontend"
        if default_frontend.is_dir():
            frontend_dir = str(default_frontend)

    run_server(port=args.port, host=args.host, frontend_path=frontend_dir)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bumpguard",
        description="Dependency Update Risk Scanner — flags new and risky behaviour in package updates.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Subcommand: diff
    diff_p = subparsers.add_parser("diff", help="Diff packages between two git refs or lockfile paths")
    diff_p.add_argument("--base", required=True, help="Base commit ref or package-lock.json path")
    diff_p.add_argument("--head", required=True, help="Head commit ref or package-lock.json path")
    diff_p.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="high",
        help="Severity threshold to return exit code 1 (default: high)",
    )
    diff_p.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Report output format (default: markdown)",
    )
    diff_p.add_argument("--ignore-dev", action="store_true", help="Ignore devDependencies")

    # Subcommand: serve
    serve_p = subparsers.add_parser("serve", help="Launch integrated web dashboard & API server")
    serve_p.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    serve_p.add_argument("--host", default="127.0.0.1", help="Host address to bind (default: 127.0.0.1)")
    serve_p.add_argument("--frontend-dir", help="Custom path to frontend static assets")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.subcommand == "diff":
        sys.exit(cmd_diff(args))
    elif args.subcommand == "serve":
        sys.exit(cmd_serve(args))
    else:
        parser.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
