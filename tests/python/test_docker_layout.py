"""Fast guard for a real clean-image build failure; Docker CI is authoritative."""
import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


class DockerLayout(unittest.TestCase):
    def test_custom_solcx_directory_is_created_before_install(self):
        dockerfile = (ROOT / "agent" / "Dockerfile").read_text()
        create = 'mkdir -p "$SOLCX_BINARY_PATH"'
        install = "solcx.install_solc('0.8.24')"
        self.assertIn(create, dockerfile)
        self.assertIn(install, dockerfile)
        self.assertLess(dockerfile.index(create), dockerfile.index(install))

    def test_importing_engine_does_not_replace_local_solcx_path(self):
        spec = importlib.util.spec_from_file_location(
            "prove_without_solcx_override", ROOT / "api" / "prove.py")
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {}, clear=True):
            spec.loader.exec_module(module)
            self.assertNotIn("SOLCX_BINARY_PATH", os.environ)


if __name__ == "__main__":
    unittest.main()
