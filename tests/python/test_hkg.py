#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.features import extract_features
from trust404.hkg import lift, order_by_hkg
from trust404.hkg import should_run_hkg
from trust404.registry import should_run
from trust404.targets import load_all


class HKG(unittest.TestCase):
    def test_graph_ranking_cannot_bypass_required_provider_features(self):
        self.assertFalse(should_run_hkg(
            "_synth_gatekeeper_one", {"gasleft_modulo"}))
        self.assertTrue(should_run_hkg(
            "_synth_gatekeeper_one", {"gasleft_modulo", "tx_origin_mask"}))

    def test_reentrant_vault_is_vault_cei(self):
        src = load_all()["ReentrantVault"]["src"]
        feats = extract_features(src, "ReentrantVault")
        m = lift(feats)
        self.assertIn("vault", m.protocols)
        self.assertIn("cei", m.causes)

    def test_safe_vault_has_mutex_not_theft_path_only(self):
        src = load_all()["SafeVault"]["src"]
        feats = extract_features(src, "SafeVault")
        m = lift(feats)
        self.assertIn("vault", m.protocols)
        # mutex is present — we must NOT skip generic fuzz, but Gatekeeper
        # family must stay off (flat registry already tests this)
        self.assertFalse(should_run("_synth_gatekeeper_one", feats))

    def test_truster_lifts_to_unpermissioned_callback(self):
        src = """
        interface IERC20 { function approve(address,uint256) external returns (bool); }
        contract Pool {
            IERC20 public token;
            function flashLoan(uint256 amount, address borrower, address target, bytes calldata data) external {
                target.call(data);
            }
        }
        """
        feats = extract_features(src, "Pool")
        m = lift(feats)
        self.assertIn("unpermissioned_callback", feats)
        self.assertIn("unpermissioned_callback", m.ranked_primitives)
        self.assertTrue(
            "callback" in m.protocols or "lending" in m.protocols
        )

    def test_order_puts_ranked_first(self):
        feats = extract_features(
            "contract C { function enter() external { require(gasleft() % 8191 == 0); } }",
            "C",
        )
        names = ["_synth_dex_drain", "_synth_gatekeeper_one", "_storage_attempt"]
        ordered = order_by_hkg(names, feats)
        self.assertEqual(ordered[0], "_synth_gatekeeper_one")

    def test_empty_features_preserve_order(self):
        names = ["a", "b"]
        self.assertEqual(order_by_hkg(names, set()), names)
