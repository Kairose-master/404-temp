#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.benches import datasets, local_fixtures, score_fixture, summary
from trust404.features import extract_features


class Benches(unittest.TestCase):
    def test_manifest_has_upstream_and_local(self):
        ids = {d.id for d in datasets()}
        self.assertTrue({"verite", "scone", "evmbench", "track04", "frontier-local"} <= ids)

    def test_upstream_not_pretend_attached(self):
        for d in datasets():
            if d.id in ("verite", "scone", "evmbench", "poco-patch"):
                self.assertFalse(d.attached, d.id)

    def test_four_frontier_fixtures(self):
        names = {p.name for p in local_fixtures()}
        self.assertTrue(
            {"profit_drain", "grief_lock", "intended_arb", "cross_router", "dual_surface"}
            <= names
        )

    def test_intended_arb_is_the_frontier_class(self):
        p = ROOT / "benches/fixtures/intended_arb"
        rec = score_fixture(p)
        self.assertEqual(rec["expect"], "intended_path")
        self.assertTrue({"swap", "spot_price", "oracle"} & set(rec["features"]))

    def test_profit_drain_has_cei(self):
        src = (ROOT / "benches/fixtures/profit_drain/src/ProfitVault.sol").read_text()
        feats = extract_features(src, "ProfitVault")
        self.assertIn("cei_violation", feats)
        rec = score_fixture(ROOT / "benches/fixtures/profit_drain")
        self.assertEqual(rec["expect"], "theft")

    def test_grief_expect(self):
        rec = score_fixture(ROOT / "benches/fixtures/grief_lock")
        self.assertEqual(rec["expect"], "grief")

    def test_cross_router_world_flag(self):
        rec = score_fixture(ROOT / "benches/fixtures/cross_router")
        self.assertTrue(rec["cross_contract"])

    def test_summary_does_not_claim_verite_score(self):
        s = summary()
        self.assertEqual(s["n_attached_upstream"], 0)
        self.assertEqual(s["n_local"], 5)
        verite = next(d for d in s["datasets"] if d["id"] == "verite")
        self.assertEqual(verite["status"], "NOT_ATTACHED")
