#!/usr/bin/env python3
"""DualSurface — one protocol, two labels. No solc."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.features import extract_features
from trust404.hkg import lift
from trust404.profit import THEFT, INTENDED_PATH, classify
from trust404.registry import should_run


SRC = (ROOT / "examples/frontier/DualSurface.sol").read_text()


class DualSurfaceExample(unittest.TestCase):
    def test_files_exist(self):
        base = ROOT / "examples/frontier"
        for n in ("DualSurface.sol", "Invariants.sol", "ExploitTheft.sol",
                  "ExploitSwap.sol", "manifest.json", "README.md"):
            self.assertTrue((base / n).is_file(), n)

    def test_both_surfaces_in_features(self):
        feats = extract_features(SRC, "DualSurface")
        self.assertIn("cei_violation", feats)
        self.assertIn("value_call", feats)
        self.assertTrue({"swap", "spot_price", "oracle"} & feats)

    def test_hkg_sees_vault_and_amm(self):
        m = lift(extract_features(SRC, "DualSurface"))
        self.assertIn("vault", m.protocols)
        self.assertIn("amm", m.protocols)
        self.assertIn("cei", m.causes)

    def test_reentrancy_synth_would_run_gatekeeper_would_not(self):
        feats = extract_features(SRC, "DualSurface")
        self.assertFalse(should_run("_synth_gatekeeper_one", feats))

    def test_labels(self):
        self.assertEqual(classify(True, 10**18), THEFT)
        self.assertEqual(classify(False, 10**18), INTENDED_PATH)

    def test_manifest_expect_theft_and_also_intended(self):
        man = json.loads((ROOT / "examples/frontier/manifest.json").read_text())
        self.assertEqual(man["frontier"]["expect"], "theft")
        self.assertEqual(man["frontier"]["also"], "intended_path")

    def test_invariants_name_both_predicates(self):
        inv = (ROOT / "examples/frontier/Invariants.sol").read_text()
        self.assertIn("vaultSolvent", inv)
        self.assertIn("ammBacked", inv)

    def test_theft_exploit_reenters_swap_exploit_does_not(self):
        theft = (ROOT / "examples/frontier/ExploitTheft.sol").read_text()
        swap = (ROOT / "examples/frontier/ExploitSwap.sol").read_text()
        self.assertIn("withdraw()", theft)
        self.assertIn("receive()", theft)
        self.assertIn("swap0to1", swap)
        self.assertNotIn("withdraw()", swap)

    def test_bench_mirror_scores_theft(self):
        from trust404.benches import score_fixture
        rec = score_fixture(ROOT / "benches/fixtures/dual_surface")
        self.assertEqual(rec["expect"], "theft")
        self.assertIn("cei_violation", rec["features"])
