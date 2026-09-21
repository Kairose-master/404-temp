"""Retry behavior for the Docker solc installer; no network required."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "install_solc_versions", ROOT / "agent" / "install_solc_versions.py")
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)


class SolcInstaller(unittest.TestCase):
    def test_retries_an_interrupted_download(self):
        calls = []

        def flaky(version):
            calls.append(version)
            if len(calls) < 3:
                raise OSError("connection reset")

        sleeps = []
        installer.install_versions(["0.8.24"], flaky, sleep=sleeps.append)
        self.assertEqual(calls, ["0.8.24"] * 3)
        self.assertEqual(sleeps, [1, 2])

    def test_deduplicates_versions(self):
        calls = []
        installer.install_versions(["0.8.24", "0.8.24"], calls.append, sleep=lambda _: None)
        self.assertEqual(calls, ["0.8.24"])

    def test_exhausted_retries_fail_the_build(self):
        def broken(_version):
            raise OSError("offline")

        with self.assertRaisesRegex(RuntimeError, "after 2 attempts"):
            installer.install_versions(
                ["0.8.20"], broken, attempts=2, sleep=lambda _: None)


if __name__ == "__main__":
    unittest.main()
