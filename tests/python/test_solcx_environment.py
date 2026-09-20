"""Engine imports must preserve the compiler cache used by local setup."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]


class CompilerEnvironment(unittest.TestCase):
    def check_import(self, overrides, expected):
        env = os.environ.copy()
        for key in ("VERCEL", "SOLCX_BINARY_PATH"):
            env.pop(key, None)
        env.update(overrides)
        result = subprocess.run(
            [sys.executable, "-c",
             "import api.prove, os; print(repr(os.environ.get('SOLCX_BINARY_PATH')))"],
            cwd=ROOT, env=env, capture_output=True, text=True, check=True,
        )
        self.assertEqual(result.stdout.strip(), repr(expected))

    def test_local_import_preserves_default_cache(self):
        self.check_import({}, None)

    def test_serverless_uses_writable_cache(self):
        self.check_import({"VERCEL": "1"}, "/tmp/solcx-bin")

    def test_explicit_cache_is_preserved(self):
        for runtime in ("0", "1"):
            with self.subTest(runtime=runtime):
                self.check_import({"VERCEL": runtime, "SOLCX_BINARY_PATH": "/opt/solc"},
                                  "/opt/solc")
