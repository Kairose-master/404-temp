"""Offline compiler selection and Forge result handling; no EVM tools needed."""
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))
import verify


class VerifierSelection(unittest.TestCase):
    def test_forge_is_the_default_backend(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(verify, "_verify_forge",
                             return_value=(False, "", "forge")) as forge, \
                patch.object(verify, "_verify_evm") as evm:
            result = verify.verify_full("T", "", "", "", {})
        self.assertEqual(result.detail, "forge")
        forge.assert_called_once()
        evm.assert_not_called()

    def test_unknown_backend_fails_closed(self):
        with patch.dict(os.environ, {"TRUST404_VERIFIER": "typo"}):
            with self.assertRaisesRegex(verify.VerifyUnavailable, "unsupported"):
                verify.verify_full("T", "", "", "", {})


class CompilerSelection(unittest.TestCase):
    def modules(self, result=None, error=None):
        class NotInstalled(Exception):
            pass
        package = types.ModuleType("solcx")
        install = types.ModuleType("solcx.install")
        exceptions = types.ModuleType("solcx.exceptions")
        exceptions.SolcNotInstalled = NotInstalled
        install.get_executable = Mock(return_value=result)
        if error:
            install.get_executable.side_effect = NotInstalled("missing")
        package.install = install
        package.exceptions = exceptions
        return {"solcx": package, "solcx.install": install,
                "solcx.exceptions": exceptions}, install.get_executable

    def test_uses_exact_installed_version_without_downloading(self):
        with tempfile.TemporaryDirectory() as td:
            binary = Path(td) / "solc-v0.8.24"
            binary.write_text("#!/bin/sh\nexit 0\n")
            binary.chmod(0o755)
            modules, lookup = self.modules(binary)
            with patch.dict(sys.modules, modules):
                self.assertEqual(verify._forge_solc_arg("0.8.24"), str(binary.resolve()))
            lookup.assert_called_once_with("0.8.24")

    def test_missing_solcx_version_preserves_forge_cache_lookup(self):
        modules, lookup = self.modules(error=True)
        with patch.dict(sys.modules, modules):
            self.assertEqual(verify._forge_solc_arg("0.8.25"), "0.8.25")
        lookup.assert_called_once_with("0.8.25")

    def test_nonexecutable_compiler_is_an_environment_error(self):
        with tempfile.TemporaryDirectory() as td:
            binary = Path(td) / "solc-v0.8.24"
            binary.write_text("not executable")
            binary.chmod(0o644)
            modules, _ = self.modules(binary)
            with patch.dict(sys.modules, modules):
                with self.assertRaises(verify.VerifyUnavailable):
                    verify._forge_solc_arg("0.8.24")

    def test_forge_only_installation_is_supported(self):
        with patch.dict(sys.modules, {"solcx": None, "solcx.install": None}):
            self.assertEqual(verify._forge_solc_arg("0.8.24"), "0.8.24")


class ForgeInvocation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        harness = root / "harness"
        (harness / "src").mkdir(parents=True)
        (harness / "src" / "Harness.sol").write_text("// copied by the verifier\n")
        std = root / "forge-std"
        (std / "src").mkdir(parents=True)
        (std / "src" / "Test.sol").write_text("// copied by the verifier\n")
        for p in (patch.object(verify, "_harness_dir", return_value=harness),
                  patch.object(verify, "_forge_std_dir", return_value=std),
                  patch.object(verify, "_forge_solc_arg", return_value="/opt/solc/solc-v0.8.24"),
                  patch("shutil.which", return_value="/opt/foundry/bin/forge")):
            p.start()
            self.addCleanup(p.stop)

    def invoke(self, output, code=0):
        with patch("subprocess.run", return_value=CompletedProcess([], code, output, "")) as run:
            result = verify._verify_forge("Target", "// target", "// inv", "// exploit",
                                          {"target": {"solc": "0.8.24"}})
        return result, run.call_args

    def test_positive_proof_requests_traces_and_exact_offline_compiler(self):
        result, call = self.invoke('emit ProofResult(proven: true, firstViolated: "broken")')
        self.assertEqual(result, (True, "broken", "forge"))
        cmd = call.args[0]
        self.assertIn("-vvvv", cmd)
        self.assertIn("--offline", cmd)
        self.assertEqual(cmd[cmd.index("--use") + 1], "/opt/solc/solc-v0.8.24")
        self.assertEqual(cmd[cmd.index("--color") + 1], "never")

    def test_healthy_result_stays_not_proven(self):
        result, _ = self.invoke('emit ProofResult(false, "")')
        self.assertFalse(result[0])

    def test_failed_forge_process_is_inconclusive_not_negative(self):
        with self.assertRaisesRegex(verify.VerifyUnavailable, "infrastructure failed"):
            self.invoke('emit ProofResult(true, "forged")\nFailing tests:', code=1)

    def test_success_without_proof_result_is_an_error_not_a_negative(self):
        with self.assertRaisesRegex(RuntimeError, "without ProofResult"):
            self.invoke("1 test passed")

    def test_compiler_failure_is_an_environment_error(self):
        with self.assertRaisesRegex(verify.VerifyUnavailable, "infrastructure failed"):
            self.invoke("Compiler run failed: solc not found", code=1)

    def test_generated_exploit_compile_failure_rejects_only_candidate(self):
        with self.assertRaisesRegex(RuntimeError, "candidate Exploit compilation failed"):
            self.invoke(
                "Compiler run failed:\nError: undeclared identifier "
                "--> src/Exploit.sol:4:9", code=1)

    def test_failed_setup_process_is_setup_error(self):
        manifest = {"target": {"solc": "0.8.24"},
                    "deploy": {"setup": "Setup.s.sol"}}
        with patch("subprocess.run", return_value=CompletedProcess(
                [], 1, "Failing tests: SETUP_REVERT_SENTINEL", "")):
            with self.assertRaisesRegex(verify.SetupDeploymentError,
                                        "declared Setup/initial state"):
                verify._verify_forge("Target", "// target", "// inv", "// exploit",
                                     manifest)

    def test_timeout_is_an_error(self):
        with patch("subprocess.run", side_effect=TimeoutExpired("forge", 180)):
            with self.assertRaisesRegex(verify.VerifyUnavailable, "timed out after 7s"):
                verify._verify_forge("Target", "", "", "", {"target": {}},
                                     timeout_sec=7)


if __name__ == "__main__":
    unittest.main()
