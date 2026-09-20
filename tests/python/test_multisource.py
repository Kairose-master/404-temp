#!/usr/bin/env python3
"""Imported attack surfaces must be searched and verified canonically."""
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
from unittest.mock import patch
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

from trust404.abi import analysis_source_views, load_extra_sources
from verify import verify_full

FIX = ROOT / "tests/fixtures/counterexamples/ImportedOwner"


def _installed_solc():
    try:
        import solcx
        solcx.set_solc_version("0.8.24")
        return True
    except Exception:
        return False


def _inputs():
    manifest_path = FIX / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    target_path = FIX / manifest["target"]["src"]
    return dict(
        target_name="ImportedOwner",
        target_src=target_path.read_text(),
        invariants_src=(FIX / "Invariants.sol").read_text(),
        exploit_src=(FIX / "Exploit.sol").read_text(),
        manifest=manifest,
        seed=42,
        extra_sources=load_extra_sources(manifest_path, target_path, manifest),
    )


class AnalysisScope(unittest.TestCase):
    def test_inherited_surface_is_kept_but_unrelated_helper_is_context_only(self):
        manifest_path = FIX / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        target_path = FIX / manifest["target"]["src"]
        extras = load_extra_sources(manifest_path, target_path, manifest)
        extras["src/Unrelated.sol"] = """
        contract Unrelated {
            function sweep(address to) external {
                (bool ok,) = to.call{value: address(this).balance}("");
                require(ok);
            }
        }
        """
        surface, context = analysis_source_views(
            target_path.read_text(), extras, manifest)
        self.assertIn("contract OwnerBase", surface)
        self.assertIn("function setOwner", surface)
        self.assertNotIn("contract Unrelated", surface)
        self.assertIn("contract Unrelated", context)

    def test_manifest_named_setup_is_excluded_from_both_analysis_views(self):
        target = """
        import {Base} from "./Base.sol";
        contract Target is Base {}
        """
        extras = {
            "src/Base.sol": "contract Base { function ping() external {} }",
            "scripts/Bootstrap.sol": (
                "contract Bootstrap { function sweep(address to) external { "
                "(bool ok,) = to.call{value: address(this).balance}(\"\"); require(ok); } }")
        }
        manifest = {
            "target": {"name": "Target"},
            "deploy": {"setup": "scripts/Bootstrap.sol"},
            "invariants": {"contract": "checks/Rules.sol"},
        }
        surface, context = analysis_source_views(target, extras, manifest)
        self.assertIn("contract Base", surface)
        self.assertNotIn("Bootstrap", surface)
        self.assertNotIn("Bootstrap", context)


@unittest.skipUnless(_installed_solc(), "solc 0.8.24 unavailable")
class MultiSourceEVM(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {
            "TRUST404_VERIFIER": "evm", "ANTHROPIC_API_KEY": "",
            "LLM_API_KEY": "", "LLM_BASE_URL": "",
        })
        env.start()
        self.addCleanup(env.stop)

    def test_relative_import_compiles_and_known_poc_proves(self):
        result = verify_full(**_inputs())
        self.assertTrue(result.proven, result.detail)
        self.assertEqual(result.violated, "ownerUnchanged")

    def test_canonical_target_wins_over_same_named_sibling_artifact(self):
        inputs = _inputs()
        inputs["extra_sources"]["zzz/Shadow.sol"] = (
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n"
            "contract ImportedOwner {}\n"
        )
        result = verify_full(**inputs)
        self.assertTrue(result.proven, result.detail)
        self.assertEqual(result.violated, "ownerUnchanged")

    def test_agent_discovers_inherited_owner_write(self):
        spec = importlib.util.spec_from_file_location("multisource_agent", ROOT / "agent/agent.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as td:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cli.main([
                    "--contract", str(FIX / "src/ImportedOwner.sol"),
                    "--invariants", str(FIX / "Invariants.sol"),
                    "--manifest", str(FIX / "manifest.json"),
                    "--out", td, "--seed", "42", "--max-attempts", "8",
                    "--timeout", "30",
                ])
            self.assertEqual(rc, cli.EXIT_FOUND, output.getvalue())
            result = json.loads((Path(td) / "result.json").read_text())
            self.assertTrue(result["proven"])
            self.assertEqual(result["invariant_violated"], "ownerUnchanged")


@unittest.skipUnless(_installed_solc() and shutil.which("forge"),
                     "forge/solc unavailable")
class MultiSourceForge(unittest.TestCase):
    def test_known_poc_proves_with_forge(self):
        with patch.dict(os.environ, {"TRUST404_VERIFIER": "forge"}):
            result = verify_full(**_inputs())
        self.assertTrue(result.proven, result.detail)
        self.assertEqual(result.violated, "ownerUnchanged")


class VerificationAccounting(unittest.TestCase):
    def test_fuzz_discovery_evidence_is_preserved_in_result(self):
        spec = importlib.util.spec_from_file_location(
            "fuzz_evidence_agent", ROOT / "agent/agent.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)

        source = """pragma solidity 0.8.24;
        contract Exploit { function run(address) external payable {} }
        """
        metadata = {"discovery": {
            "kind": "abi-sequence-fuzz", "round": 1, "depth": 1,
            "trace": {
                "predicate_before": {"allHold": True, "firstViolated": ""},
                "predicate_after": {"allHold": False,
                                    "firstViolated": "ownerUnchanged"},
                "calls": [{"index": 0, "function": "seize()",
                           "success": True}],
                "reproducer": [{"function": "seize()", "arguments": [],
                                "value_wei": "0", "calldata": "0x12345678"}],
                "minimization": {"original_calls": 1, "final_calls": 1,
                                 "one_minimal": True},
            },
        }}

        def stream(*args, **kwargs):
            yield "fuzz", "fuzz(seize)", source, metadata

        engine = SimpleNamespace(iter_engine_candidates=stream)
        proven = SimpleNamespace(
            tuple=lambda: (True, "ownerUnchanged", "forge"), profit=None)
        target = ROOT / "targets/BoundedOwner"
        with tempfile.TemporaryDirectory() as td, \
                patch.object(cli, "_load_engine", return_value=engine), \
                patch.object(cli, "verify_full", return_value=proven), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main([
                "--contract", str(target / "src/BoundedOwner.sol"),
                "--invariants", str(target / "Invariants.sol"),
                "--manifest", str(target / "manifest.json"),
                "--out", td, "--max-attempts", "2", "--timeout", "30",
            ])
            payload = json.loads((Path(td) / "result.json").read_text())
        self.assertEqual(cli.EXIT_FOUND, rc)
        self.assertEqual(["seize()"], payload["derivation"]["call_path"])
        self.assertIn("seize()", payload["how"])
        self.assertTrue(payload["exploit_trace"]["trace"]
                        ["predicate_after"]["allHold"] is False)

    def test_rejected_fuzz_candidate_continues_to_next_sequence(self):
        spec = importlib.util.spec_from_file_location("fuzz_retry_agent", ROOT / "agent/agent.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)

        first = """pragma solidity 0.8.24;
        contract Exploit { function run(address) external payable {} receive() external payable {} }
        """
        second = """pragma solidity 0.8.24;
        contract Exploit {
            function run(address t) external payable { (bool ok,) = t.call(\"\"); ok; }
            receive() external payable {}
        }
        """

        def stream(*args, **kwargs):
            yield "fuzz", "sequence-one", first
            yield "fuzz", "sequence-two", second

        engine = SimpleNamespace(iter_engine_candidates=stream)
        rejected = SimpleNamespace(tuple=lambda: (False, "", "forge"), profit=None)
        proven = SimpleNamespace(tuple=lambda: (True, "ownerUnchanged", "forge"), profit=None)
        target = ROOT / "targets/BoundedOwner"
        with tempfile.TemporaryDirectory() as td, \
                patch.object(cli, "_load_engine", return_value=engine), \
                patch.object(cli, "verify_full", side_effect=[rejected, proven]), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main([
                "--contract", str(target / "src/BoundedOwner.sol"),
                "--invariants", str(target / "Invariants.sol"),
                "--manifest", str(target / "manifest.json"),
                "--out", td, "--max-attempts", "5", "--timeout", "30",
            ])
            payload = json.loads((Path(td) / "result.json").read_text())
        self.assertEqual(cli.EXIT_FOUND, rc)
        self.assertEqual(2, payload["attempts"])
        self.assertEqual("sequence-two", payload["strategy"])
        self.assertEqual(2, payload["metrics"]["verified"])
        self.assertEqual(1, payload["metrics"]["rejected"])

    def test_search_exception_is_inconclusive_after_healthy_baseline(self):
        spec = importlib.util.spec_from_file_location("search_error_agent", ROOT / "agent/agent.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)

        def broken_stream(*args, **kwargs):
            raise RuntimeError("fuzz backend exploded")
            yield  # pragma: no cover

        engine = SimpleNamespace(iter_engine_candidates=broken_stream)
        healthy = SimpleNamespace(tuple=lambda: (False, "", "forge"), profit=None)
        target = ROOT / "targets/BoundedOwner"
        with tempfile.TemporaryDirectory() as td, \
                patch.object(cli, "_load_engine", return_value=engine), \
                patch.object(cli, "verify_full", return_value=healthy), \
                contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main([
                "--contract", str(target / "src/BoundedOwner.sol"),
                "--invariants", str(target / "Invariants.sol"),
                "--manifest", str(target / "manifest.json"),
                "--out", td, "--max-attempts", "5", "--timeout", "30",
            ])
            payload = json.loads((Path(td) / "result.json").read_text())
        self.assertEqual(cli.EXIT_ERROR, rc)
        self.assertTrue(payload["verifier_available"])
        self.assertFalse(payload["search_available"])
        self.assertEqual("candidate-stream", payload["search_errors"][0]["provider"])

    def test_all_candidate_errors_are_inconclusive(self):
        spec = importlib.util.spec_from_file_location("error_agent", ROOT / "agent/agent.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        engine = SimpleNamespace(iter_engine_candidates=lambda *a, **k: iter([]))
        with tempfile.TemporaryDirectory() as td, \
                patch.object(cli, "_load_engine", return_value=engine), \
                patch.object(cli, "verify_full", side_effect=RuntimeError("compiler exploded")):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = cli.main([
                    "--contract", str(FIX / "src/ImportedOwner.sol"),
                    "--invariants", str(FIX / "Invariants.sol"),
                    "--manifest", str(FIX / "manifest.json"),
                    "--out", td, "--max-attempts", "1", "--timeout", "30",
                ])
            self.assertEqual(rc, cli.EXIT_ERROR)
            self.assertIn("INCONCLUSIVE", output.getvalue())
            payload = json.loads((Path(td) / "result.json").read_text())
            self.assertFalse(payload["verifier_available"])
            self.assertEqual(payload["verified_attempts"], 0)
            self.assertEqual(len(payload["verification_errors"]), 1)

    def test_zero_attempt_budget_is_inconclusive(self):
        spec = importlib.util.spec_from_file_location("zero_agent", ROOT / "agent/agent.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as td, contextlib.redirect_stdout(io.StringIO()):
            rc = cli.main([
                "--contract", str(FIX / "src/ImportedOwner.sol"),
                "--invariants", str(FIX / "Invariants.sol"),
                "--manifest", str(FIX / "manifest.json"),
                "--out", td, "--max-attempts", "0", "--timeout", "30",
            ])
            payload = json.loads((Path(td) / "result.json").read_text())
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertFalse(payload["verifier_available"])
        self.assertEqual(payload["verified_attempts"], 0)

    def test_zero_attempt_budget_does_not_run_baseline(self):
        spec = importlib.util.spec_from_file_location("zero_baseline_agent", ROOT / "agent/agent.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as td, \
                patch.object(cli, "verify_full") as verify, \
                contextlib.redirect_stdout(io.StringIO()):
            cli.main([
                "--contract", str(FIX / "src/ImportedOwner.sol"),
                "--invariants", str(FIX / "Invariants.sol"),
                "--manifest", str(FIX / "manifest.json"),
                "--out", td, "--max-attempts", "0", "--timeout", "30",
            ])
        verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
