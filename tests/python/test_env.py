#!/usr/bin/env python3
"""Environment gates from the Track 04 review. No solc, no forge."""
import compileall
import py_compile
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))


class Env(unittest.TestCase):
    def test_agent_py_compiles(self):
        py_compile.compile(str(ROOT / "agent" / "agent.py"), doraise=True)

    def test_python_trees_compile(self):
        for d in ("agent", "api", "trust404", "tests"):
            ok = compileall.compile_dir(str(ROOT / d), quiet=1)
            self.assertTrue(ok, d)

    def test_forge_std_shim_exists(self):
        p = ROOT / "lib" / "forge-std" / "src" / "Test.sol"
        self.assertTrue(p.is_file())
        txt = p.read_text()
        self.assertIn("abstract contract Test", txt)
        self.assertIn("readFile", txt)

    def test_harness_and_dockerfile_pin_foundry(self):
        df = (ROOT / "agent" / "Dockerfile").read_text()
        self.assertIn("foundryup --install 1.7.1", df)
        self.assertIn("COPY lib /work/lib", df)
        self.assertIn("compileall", df)
        self.assertTrue((ROOT / "harness" / "src" / "Harness.sol").is_file())

    def test_safe_write_rejects_escape(self):
        from verify import _safe_write
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p = _safe_write(td, "../etc/passwd", "no")
            self.assertTrue(str(p).startswith(str(Path(td).resolve())))
            self.assertFalse(p.as_posix().endswith("/etc/passwd"))

    def test_proof_result_parse(self):
        from verify import _parse_proof_result
        out = '    emit ProofResult(proven: true, firstViolated: "vaultSolvent")'
        proven, v = _parse_proof_result(out)
        self.assertTrue(proven)
        self.assertEqual(v, "vaultSolvent")
        proven, _ = _parse_proof_result('emit ProofResult(false, "")')
        self.assertFalse(proven)

    def test_verifier_unavailable_is_exit_2(self):
        src = (ROOT / "agent" / "agent.py").read_text()
        self.assertIn("return EXIT_ERROR", src)
        self.assertIn("INCONCLUSIVE", src)

    def test_safevault_attempt_swallows_reentrant_revert(self):
        t = (ROOT / "test" / "Prove.t.sol").read_text()
        self.assertIn("try t.withdraw()", t)
        self.assertIn("catch", t)
