"""Embedded HTTP server for bumpguard API and frontend visualizer."""

from __future__ import annotations

import json
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional

from bumpguard.core.types import Ecosystem, PackageRef, Severity
from bumpguard.engine import scan_package_update
from bumpguard.extract.safe_extractor import SafeExtractor
from bumpguard.lockfile.diff import diff_lockfiles
from bumpguard.lockfile.parser import parse_package_lock
from bumpguard.registry.client import NpmRegistryClient
from bumpguard.score.scorer import ScoredPackage


class BumpguardRequestHandler(BaseHTTPRequestHandler):
    frontend_dir: Optional[Path] = None

    def log_message(self, format, *args):
        # Keep server quiet during scans
        pass

    def do_GET(self):
        url_path = self.path.split("?")[0]

        if url_path == "/api/health":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b'{"status": "ok", "service": "bumpguard", "version": "0.1.0"}')
            return

        # Serve static frontend files
        if self.frontend_dir and self.frontend_dir.exists():
            clean_path = url_path.lstrip("/")
            if not clean_path or clean_path == "":
                clean_path = "index.html"

            file_path = (self.frontend_dir / clean_path).resolve()
            # Ensure no path escape outside frontend_dir
            if str(file_path).startswith(str(self.frontend_dir.resolve())) and file_path.is_file():
                content_type, _ = mimetypes.guess_type(str(file_path))
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", content_type or "text/plain")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                with open(file_path, "rb") as f:
                    self.wfile.write(f.read())
                return

        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        self.wfile.write(b"Not Found")

    def do_POST(self):
        url_path = self.path.split("?")[0]

        if url_path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception as e:
                self.send_response(HTTPStatus.BAD_REQUEST)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Invalid JSON body: {e}"}).encode())
                return

            base_content = payload.get("base_lockfile", "{}")
            head_content = payload.get("head_lockfile", "{}")

            try:
                base_entries = parse_package_lock(base_content)
                head_entries = parse_package_lock(head_content)
                changed, removed = diff_lockfiles(base_entries, head_entries)

                client = NpmRegistryClient()
                extractor = SafeExtractor()
                scored_packages: list[ScoredPackage] = []

                for pkg in changed:
                    scored = scan_package_update(pkg, client=client, extractor=extractor)
                    scored_packages.append(scored)

                flagged = [p for p in scored_packages if p.needs_review]
                resp_data = {
                    "summary": {
                        "total_packages": len(scored_packages),
                        "needing_review": len(flagged),
                        "clean_packages": len(scored_packages) - len(flagged),
                        "removed_packages": len(removed),
                    },
                    "packages": [p.to_dict() for p in scored_packages],
                }

                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(resp_data).encode("utf-8"))
            except Exception as ex:
                self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(ex)}).encode("utf-8"))
            return

        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()


def run_server(port: int = 8080, host: str = "127.0.0.1", frontend_path: Optional[str] = None):
    handler = BumpguardRequestHandler
    if frontend_path:
        handler.frontend_dir = Path(frontend_path)

    server = ThreadingHTTPServer((host, port), handler)
    print(f"[*] bumpguard server running at http://{host}:{port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")
        server.server_close()
