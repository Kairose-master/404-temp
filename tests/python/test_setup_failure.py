#!/usr/bin/env python3
"""A declared Setup is mandatory; failure must not become another target."""
import contextlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))
import verify

FIX = ROOT / "tests/fixtures/counterexamples/SetupRevertsZeroArg"


class SetupPolicy(unittest.TestCase):
    def setUp(self):
        self.w3 = Mock()
        self.w3.eth.get_code.return_value = b"\x01"
        self.art = {"abi": [], "bin": "6000"}
        self.arts = {"Target": self.art, "Helper": self.art, "Setup": self.art}
        self.compiled = {"contracts": {"Setup.s.sol": {"Setup": {
            "abi": [], "evm": {"bytecode": {"object": "6001"}},
        }}}}
        self.deploy = Mock(return_value=("contract", "address"))

    def deploy_target(self, dep):
        return verify._deploy_target(self.w3, self.compiled, self.arts,
                                     "Target", dep, "sender", self.deploy)

    def test_no_setup_preserves_direct_constructor(self):
        with patch.object(verify, "_deploy_via_setup") as setup:
            self.assertEqual(self.deploy_target({"value_wei": "7"}), ("contract", "address"))
        self.deploy.assert_called_once_with(self.art, [], value=7)
        setup.assert_not_called()

    def test_success_uses_declared_artifact_without_extra_deployments(self):
        with patch.object(verify, "_deploy_via_setup", return_value="target") as setup:
            result = self.deploy_target({"setup": "Setup.s.sol", "constructor_args": ["ignored"],
                                         "helpers": [{"contract": "Helper"}]})
        self.assertEqual(result[1], "target")
        setup.assert_called_once_with(self.w3, {"abi": [], "bin": "6001"}, "sender", None)
        self.deploy.assert_not_called()

    def test_setup_exception_cannot_fall_back(self):
        cause = RuntimeError("Setup.run reverted")
        with patch.object(verify, "_deploy_via_setup", side_effect=cause):
            with self.assertRaisesRegex(verify.SetupDeploymentError, "fallback is forbidden") as cm:
                self.deploy_target({"setup": "Setup.s.sol"})
        self.assertIs(cm.exception.__cause__, cause)
        self.assertIsInstance(cm.exception, verify.VerifyUnavailable)
        self.deploy.assert_not_called()

    def test_missing_or_wrong_source_setup_cannot_fall_back(self):
        for name in ("Missing.s.sol", "other/Setup.s.sol"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(verify.SetupDeploymentError, "missing declared Setup"):
                    self.deploy_target({"setup": name})
        self.deploy.assert_not_called()

    def test_empty_setup_key_is_not_absent_setup(self):
        for value in (None, "", " ", False, [], {}):
            with self.subTest(value=value):
                with self.assertRaisesRegex(verify.SetupDeploymentError, "nonempty source path"):
                    self.deploy_target({"setup": value})
        self.deploy.assert_not_called()

    def test_no_target_code_is_not_a_valid_setup(self):
        self.w3.eth.get_code.return_value = b""
        with patch.object(verify, "_deploy_via_setup", return_value="target"):
            with self.assertRaisesRegex(verify.SetupDeploymentError, "no deployed code"):
                self.deploy_target({"setup": "Setup.s.sol"})
        self.deploy.assert_not_called()

    def test_failed_setup_constructor_stops_before_run(self):
        self.w3.eth.wait_for_transaction_receipt.return_value = {"status": 0, "contractAddress": None}
        with self.assertRaisesRegex(RuntimeError, "Setup constructor deployment failed"):
            verify._deploy_via_setup(self.w3, self.art, "sender")
        self.w3.eth.contract.return_value.functions.run.assert_not_called()

    def test_failed_setup_run_receipt_is_rejected(self):
        self.w3.eth.wait_for_transaction_receipt.side_effect = [
            {"status": 1, "contractAddress": "setup"}, {"status": 0},
        ]
        with self.assertRaisesRegex(RuntimeError, "Setup.run reverted"):
            verify._deploy_via_setup(self.w3, self.art, "sender")


def _installed_solc():
    try:
        import solcx
        solcx.set_solc_version("0.8.24")
        return True
    except Exception:
        return False


def _inputs():
    man = json.loads((FIX / "manifest.json").read_text())
    return dict(target_name=man["target"]["name"],
                target_src=(FIX / man["target"]["src"]).read_text(),
                invariants_src=(FIX / "Invariants.sol").read_text(),
                exploit_src=(FIX / "Exploit.sol").read_text(),
                manifest=man, seed=42,
                extra_sources={"Setup.s.sol": (FIX / "Setup.s.sol").read_text()})


@unittest.skipUnless(_installed_solc(), "solc 0.8.24 not installed; Docker gate never skips")
class SetupFailureEVM(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"TRUST404_VERIFIER": "evm", "ANTHROPIC_API_KEY": "",
                                     "LLM_API_KEY": "", "LLM_BASE_URL": ""})
        env.start()
        self.addCleanup(env.stop)

    def test_real_revert_cannot_prove_zero_arg_target(self):
        with self.assertRaisesRegex(verify.SetupDeploymentError, "Setup.run reverted"):
            verify.verify_full(**_inputs())

    def test_same_exploit_proves_when_setup_is_not_declared(self):
        args = _inputs()
        del args["manifest"]["deploy"]["setup"]
        args["extra_sources"] = None
        result = verify.verify_full(**args)
        self.assertTrue(result.proven, result.detail)
        self.assertEqual(result.violated, "unbroken")

    def test_successful_declared_setup_still_proves(self):
        args = _inputs()
        args["extra_sources"]["Setup.s.sol"] = args["extra_sources"]["Setup.s.sol"].replace(
            'revert("SETUP_REVERT_SENTINEL");', 'return address(target);')
        result = verify.verify_full(**args)
        self.assertTrue(result.proven, result.detail)
        self.assertEqual(result.violated, "unbroken")

    def test_real_setup_constructor_revert_is_inconclusive(self):
        args = _inputs()
        args["extra_sources"]["Setup.s.sol"] = args["extra_sources"]["Setup.s.sol"].replace(
            "contract Setup {", 'contract Setup { constructor() { revert("CTOR_FAIL"); }')
        with self.assertRaisesRegex(verify.SetupDeploymentError, "Setup constructor deployment failed"):
            verify.verify_full(**args)

    def test_cli_emits_inconclusive_and_exit_2(self):
        # Only candidate selection is controlled: deployment/verification remain real.
        spec = importlib.util.spec_from_file_location("setup_failure_agent", ROOT / "agent/agent.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        engine = SimpleNamespace(iter_engine_candidates=lambda *a, **k: iter([
            ("template", "setup-regression", (FIX / "Exploit.sol").read_text()),
        ]))
        with tempfile.TemporaryDirectory() as td, patch.object(cli, "_load_engine", return_value=engine):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cli.main(["--contract", str(FIX / "src/SetupRevertsZeroArg.sol"),
                               "--invariants", str(FIX / "Invariants.sol"),
                               "--manifest", str(FIX / "manifest.json"),
                               "--out", td, "--max-attempts", "1", "--timeout", "30"])
            self.assertEqual(rc, cli.EXIT_ERROR)
            self.assertIn("INCONCLUSIVE", output.getvalue())
            payload = json.loads((Path(td) / "result.json").read_text())
            self.assertFalse(payload["proven"])
            self.assertFalse(payload["verifier_available"])
            self.assertIn("Setup.run reverted", (Path(td) / "attempts.log").read_text())


@unittest.skipUnless(_installed_solc() and shutil.which("forge"),
                     "forge/solc unavailable")
class SetupFailureForge(unittest.TestCase):
    def test_real_setup_revert_is_inconclusive(self):
        with patch.dict(os.environ, {"TRUST404_VERIFIER": "forge"}):
            with self.assertRaisesRegex(verify.SetupDeploymentError,
                                        "declared Setup/initial state"):
                verify.verify_full(**_inputs())
