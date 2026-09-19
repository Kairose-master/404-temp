"""HTTP routing and concurrency checks; real EVM coverage lives in Docker smoke."""
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts import serve


HEALTHY = {"ok": True, "service": "trust404", "solc": ["0.8.24"], "missing": []}
MISSING = {"ok": False, "service": "trust404", "solc": [], "missing": ["solc 0.8.24"]}


class LocalWebServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class QuietHandler(serve.WebHandler):
            def log_message(self, *args):
                pass
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, method, path, body=None):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            conn.request(method, path, body=body)
            response = conn.getresponse()
            raw = response.read()
            headers = dict(response.getheaders())
            self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
            return response.status, raw, headers
        finally:
            conn.close()

    def test_public_pages_and_bundled_zip_library_are_accessible(self):
        for path, marker in (("/", b"TRUST404"), ("/index.html", b"TRUST404"),
                             ("/analysis.html", b"TRUST404"), ("/analysis", b"TRUST404"),
                             ("/track04.html", b"TRUST404"), ("/METHOD.md", b"TRUST404"),
                             ("/vendor/jszip.min.js", b"JSZip")):
            with self.subTest(path=path):
                status, body, _ = self.request("GET", path)
                self.assertEqual(status, 200)
                self.assertIn(marker, body)

    def test_static_query_string_does_not_change_the_file(self):
        status, body, _ = self.request("GET", "/index.html?theme=light")
        self.assertEqual(status, 200)
        self.assertIn(b"TRUST404", body)

    def test_private_files_directories_and_traversals_are_not_served(self):
        for path in ("/.git/config", "/.env", "/README.md", "/api/prove.py",
                     "/agent/agent.py", "/scripts/serve.py", "/targets/",
                     "/../.git/config", "/%2e%2e/.git/config", "/index.html/../README.md",
                     "/%252e%252e/.git/config"):
            with self.subTest(path=path):
                status, body, _ = self.request("GET", path)
                self.assertEqual(status, 404)
                self.assertEqual(json.loads(body), {"error": "Not found"})

    def test_head_uses_same_static_allowlist_and_has_no_body(self):
        for path, expected in (("/index.html", 200), ("/track04.html", 200),
                               ("/.git/config", 404), ("/api/prove.py", 404)):
            with self.subTest(path=path):
                status, body, _ = self.request("HEAD", path)
                self.assertEqual(status, expected)
                self.assertEqual(body, b"")

    def test_post_to_non_api_path_is_rejected(self):
        status, body, _ = self.request("POST", "/index.html", body=b"{}")
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body), {"error": "Not found"})

    def test_health_reports_readiness_and_missing_dependencies(self):
        for expected, health in ((200, HEALTHY), (503, MISSING)):
            with self.subTest(ready=health["ok"]), patch.object(serve, "runtime_status", return_value=health):
                status, body, headers = self.request("GET", "/api/health")
                self.assertEqual(status, expected)
                self.assertEqual(json.loads(body), health)
                self.assertEqual(headers.get("Cache-Control"), "no-store")

    def test_missing_python_dependencies_are_reported_without_installation(self):
        with patch.object(serve.importlib, "import_module", side_effect=ImportError("not installed")):
            status = serve.runtime_status()
        self.assertFalse(status["ok"])
        self.assertEqual(set(status["missing"]), {"solcx", "web3", "eth_tester", "eth", "solc 0.8.24"})

    def test_proofs_are_serialized_while_health_and_static_remain_responsive(self):
        entered = threading.Event()
        release = threading.Event()
        calls = []

        def blocked_proof(handler):
            calls.append(handler.path)
            entered.set()
            if not release.wait(timeout=5):
                return handler._send(500, {"error": "test timed out"})
            return handler._send(200, {"name": "ReentrantVault", "proven": True})

        with patch.object(serve.ProofHandler, "do_GET", blocked_proof), \
                patch.object(serve, "runtime_status", return_value=HEALTHY), \
                ThreadPoolExecutor(max_workers=1) as executor:
            first = executor.submit(self.request, "GET", "/api/prove?target=ReentrantVault")
            try:
                self.assertTrue(entered.wait(timeout=2), "first proof never started")
                for method, body in (("GET", None), ("POST", b'{"contract":"contract Vault {}"}')):
                    status, raw, _ = self.request(method, "/api/prove", body)
                    self.assertEqual(status, 503)
                    self.assertIn("error", json.loads(raw))
                self.assertEqual(len(calls), 1, "a second proof entered the global engine")
                status, raw, _ = self.request("GET", "/api/health")
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(raw), HEALTHY)
                self.assertEqual(self.request("GET", "/")[0], 200)
                self.assertFalse(first.done(), "proof should remain blocked during these requests")
            finally:
                release.set()
            self.assertEqual(first.result(timeout=2)[0], 200)
            self.assertEqual(self.request("GET", "/api/prove?target=ReentrantVault")[0], 200)
            self.assertEqual(len(calls), 2, "proof lock was not released")


if __name__ == "__main__":
    unittest.main()
