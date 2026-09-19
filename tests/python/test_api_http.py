"""Exercise the public HTTP boundary without downloading a Solidity compiler."""
import http.client
import json
import sys
import threading
import unittest
from http.server import HTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from api import prove as api


class CustomRequestValidation(unittest.TestCase):
    def assert_invalid(self, payload, status=400):
        with patch.object(api, "_run_custom_data") as engine:
            result = api._run_custom(json.dumps(payload))
        self.assertEqual(result.get("error_type"), "invalid_request", result)
        self.assertEqual(result.get("status"), status, result)
        engine.assert_not_called()

    def test_json_must_be_an_object(self):
        for payload in (None, [], 1, "source", True):
            with self.subTest(payload=payload):
                self.assert_invalid(payload)

    def test_source_fields_must_be_strings(self):
        for field in ("contract", "invariants", "targetName", "exploitOverride"):
            for value in (42, ["source"], {}):
                with self.subTest(field=field, value=value):
                    self.assert_invalid({"contract": "contract Vault {}", field: value})

    def test_empty_contract_is_rejected(self):
        for payload in ({}, {"contract": "  "}, {"contract": None}):
            self.assert_invalid(payload)

    def test_malformed_manifest_is_rejected_before_execution(self):
        for manifest in ([], "[]", "{", {"deploy": None}, {"target": []},
                         {"invariants": "Invariants.sol"}, {"deploy": {"constructor_args": 7}},
                         {"deploy": {"value_wei": -1}}, {"deploy": {"value_wei": True}},
                         {"invariants": {"predicates": "checkAll"}}):
            with self.subTest(manifest=manifest):
                self.assert_invalid({"contract": "contract Vault {}", "manifest": manifest})

    def test_bad_dependency_or_llm_values_are_rejected(self):
        for extra in ({"sources": []}, {"sources": {"lib.sol": 1}},
                      {"llm": []}, {"llm": {"base": 1}}):
            with self.subTest(extra=extra):
                self.assert_invalid({"contract": "contract Vault {}", **extra})

    def test_source_limits_apply_before_flattening(self):
        with patch.object(api, "MAX_SRC", 32):
            self.assert_invalid({"contract": "x" * 33}, 413)
            self.assert_invalid({"contract": "contract Vault {}", "sources": {"lib.sol": "x" * 33}}, 413)

    def test_json_encoded_manifest_and_optional_empty_fields_work(self):
        payload = {"contract": "contract Vault {}", "invariants": None,
                   "manifest": json.dumps({"deploy": {"constructor_args": [], "value_wei": "0"}})}
        expected = {"name": "Vault", "proven": False, "mode": "analyze"}
        with patch.object(api, "_run_custom_data", return_value=expected) as engine:
            result = api._run_custom(json.dumps(payload))
        self.assertEqual(result, expected)
        self.assertEqual(engine.call_args.args[0]["manifest"]["deploy"]["value_wei"], "0")


class HttpBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        class QuietHandler(api.handler):
            def log_message(self, *args):
                pass
        cls.server = HTTPServer(("127.0.0.1", 0), QuietHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, method, path="/api/prove", body=None, headers=None):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            raw = response.read()
            self.assertEqual(int(response.getheader("Content-Length")), len(raw))
            self.assertEqual(response.getheader("Cache-Control"), "no-store")
            return response.status, json.loads(raw)
        finally:
            conn.close()

    def test_target_listing_and_unknown_target(self):
        status, payload = self.request("GET")
        self.assertEqual(status, 200)
        self.assertIn("ReentrantVault", payload["targets"])
        status, payload = self.request("GET", "/api/prove?target=missing")
        self.assertEqual(status, 404)
        self.assertIn("unknown target", payload["error"])

    def test_bad_json_and_bad_utf8_return_json_errors(self):
        for body in (b"[]", b"null", b"{", b'{"contract":1}', b"\xff"):
            with self.subTest(body=body):
                status, payload = self.request("POST", body=body)
                self.assertEqual(status, 400)
                self.assertIn("error", payload)

    def test_oversize_body_is_rejected_without_reading_it(self):
        status, payload = self.request("POST", headers={"Content-Length": str(api.MAX_BODY + 1)})
        self.assertEqual(status, 413)
        self.assertIn("too large", payload["error"])

    def test_bad_length_and_unsupported_transfer_encoding(self):
        for headers in ({"Content-Length": "-1"}, {"Content-Length": "invalid"},
                        {"Content-Length": "0", "Transfer-Encoding": "chunked"}):
            with self.subTest(headers=headers):
                status, payload = self.request("POST", headers=headers)
                self.assertEqual(status, 400)
                self.assertIn("error", payload)

    def test_valid_post_and_unexpected_execution_error_are_json(self):
        body = json.dumps({"contract": "contract Vault {}"})
        with patch.object(api, "_run_custom_data", return_value={"name": "Vault", "proven": False}):
            status, payload = self.request("POST", body=body)
        self.assertEqual(status, 200)
        self.assertEqual(payload["name"], "Vault")
        with patch.object(api, "_run_custom_data", side_effect=RuntimeError("engine unavailable")):
            status, payload = self.request("POST", body=body)
        self.assertEqual(status, 500)
        self.assertEqual(payload["error_type"], "execution_error")


if __name__ == "__main__":
    unittest.main()
