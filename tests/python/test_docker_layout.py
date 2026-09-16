"""Fast guard for a real clean-image build failure; Docker CI is authoritative."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class DockerLayout(unittest.TestCase):
    def test_custom_solcx_directory_is_created_before_install(self):
        dockerfile = (ROOT / "agent" / "Dockerfile").read_text()
        create = 'mkdir -p "$SOLCX_BINARY_PATH"'
        install = "solcx.install_solc('0.8.24')"
        self.assertIn(create, dockerfile)
        self.assertIn(install, dockerfile)
        self.assertLess(dockerfile.index(create), dockerfile.index(install))


if __name__ == "__main__":
    unittest.main()
