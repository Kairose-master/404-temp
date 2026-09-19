#!/usr/bin/env python3
"""Serve the web console and real proof API from the same local origin."""
import argparse
import importlib
import os
from pathlib import Path
import sys
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from api.prove import handler as ProofHandler  # noqa: E402

# The proof engine selects solc and budgets through process-global state.
# Serialize proofs, while health checks and the UI remain responsive.
PROOF_LOCK = threading.Lock()
STATIC_FILES = {
    "/": "index.html", "/index.html": "index.html",
    "/analysis": "analysis.html", "/analysis.html": "analysis.html",
    "/track04": "track04.html", "/track04.html": "track04.html",
    "/METHOD.md": "METHOD.md", "/vendor/jszip.min.js": "vendor/jszip.min.js",
    "/vendor/LICENSE.markdown": "vendor/LICENSE.markdown",
}


def runtime_status():
    """Check installed tools without downloading or changing compiler state."""
    missing = []
    for module in ("solcx", "web3", "eth_tester", "eth"):
        try:
            importlib.import_module(module)
        except ImportError:
            missing.append(module)
    versions = []
    if "solcx" not in missing:
        import solcx
        versions = [str(v) for v in solcx.get_installed_solc_versions()]
    if "0.8.24" not in versions:
        missing.append("solc 0.8.24")
    return {"ok": not missing, "service": "trust404", "solc": versions,
            "missing": missing}


class WebHandler(ProofHandler, SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def _path(self):
        return unquote(urlsplit(self.path).path)

    def _proof(self, method):
        if not PROOF_LOCK.acquire(blocking=False):
            # Do not reuse a connection whose request body we have not read.
            self.close_connection = True
            return self._send(503, {"error": "다른 증명이 실행 중입니다. 완료 후 다시 시도하세요."})
        try:
            return method(self)
        finally:
            PROOF_LOCK.release()

    def do_GET(self):
        path = self._path()
        if path == "/api/health":
            status = runtime_status()
            return self._send(200 if status["ok"] else 503, status)
        if path == "/api/prove":
            return self._proof(ProofHandler.do_GET)
        if path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        if path not in STATIC_FILES:
            return self._send(404, {"error": "Not found"})
        self.path = "/" + STATIC_FILES[path]
        return SimpleHTTPRequestHandler.do_GET(self)

    def do_HEAD(self):
        path = self._path()
        if path not in STATIC_FILES:
            self.send_response(404)
            self.end_headers()
            return
        self.path = "/" + STATIC_FILES[path]
        return SimpleHTTPRequestHandler.do_HEAD(self)

    def do_POST(self):
        if self._path() != "/api/prove":
            self.close_connection = True
            return self._send(404, {"error": "Not found"})
        return self._proof(ProofHandler.do_POST)


def main():
    parser = argparse.ArgumentParser(description="TRUST404 browser console + proof API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    args = parser.parse_args()
    status = runtime_status()
    if not status["ok"]:
        parser.exit(2, "Runtime not ready: " + ", ".join(status["missing"]) +
                    "\nUse: docker compose up --build\n"
                    "Local setup: pip install -r agent/requirements.txt\n"
                    "Then: python scripts/serve.py --help (see README for solc setup)\n")
    try:
        server = ThreadingHTTPServer((args.host, args.port), WebHandler)
    except OSError as exc:
        parser.exit(2, f"Cannot listen on {args.host}:{args.port}: {exc}\n"
                    "Choose another port with --port (Docker: TRUST404_PORT).\n")
    print(f"TRUST404 ready — open http://localhost:{args.port}", flush=True)
    print("Local EVM only. Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
