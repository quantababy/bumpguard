"""Integration tests for the embedded server and frontend static serving."""

import json
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from bumpguard.server import BumpguardRequestHandler, ThreadingHTTPServer


class TestServerIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        frontend_dir = Path(__file__).resolve().parent.parent.parent / "frontend"
        BumpguardRequestHandler.frontend_dir = frontend_dir

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), BumpguardRequestHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_health_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/api/health"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertEqual(data["status"], "ok")
            self.assertEqual(data["service"], "bumpguard")

    def test_frontend_static_serving(self):
        url = f"http://127.0.0.1:{self.port}/"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)
            html = resp.read().decode()
            self.assertIn("bumpguard", html)
            self.assertIn("Lockfile Diff Scanner", html)

    def test_scan_api_endpoint(self):
        url = f"http://127.0.0.1:{self.port}/api/scan"
        payload = json.dumps({
            "base_lockfile": json.dumps({"packages": {"node_modules/foo": {"version": "1.0.0"}}}),
            "head_lockfile": json.dumps({"packages": {"node_modules/foo": {"version": "1.0.1"}}}),
        }).encode("utf-8")

        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode())
            self.assertIn("summary", data)
            self.assertEqual(data["summary"]["total_packages"], 1)


if __name__ == "__main__":
    unittest.main()
