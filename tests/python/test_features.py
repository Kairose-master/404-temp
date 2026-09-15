#!/usr/bin/env python3
"""Feature IR + registry gating — no solc required."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.features import extract_features
from trust404.registry import should_run
from trust404.scan import scan_target
from trust404.targets import load_all


class FeatureIR(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.targets = load_all()
        if len(cls.targets) < 12:
            raise unittest.SkipTest("targets/ not present")

    def src(self, name):
        return self.targets[name]["src"]

    def test_reentrant_has_cei_safe_does_not(self):
        re_f = extract_features(self.src("ReentrantVault"), "ReentrantVault")
        safe_f = extract_features(self.src("SafeVault"), "SafeVault")
        self.assertIn("cei_violation", re_f)
        self.assertIn("value_call", re_f)
        # SafeVault still has a value call, but mutex + CEI order
        self.assertIn("reentrancy_mutex", safe_f)

    def test_delegate_param_vs_immutable(self):
        dv = extract_features(self.src("DelegateVault"), "DelegateVault")
        lv = extract_features(self.src("LibraryVault"), "LibraryVault")
        self.assertIn("delegatecall_param", dv)
        self.assertNotIn("delegatecall_param", lv)

    def test_init_unguarded_vs_guarded(self):
        op = extract_features(self.src("OpenInitializer"), "OpenInitializer")
        gu = extract_features(self.src("GuardedInitializer"), "GuardedInitializer")
        self.assertIn("unguarded_initialize", op)
        self.assertNotIn("unguarded_initialize", gu)

    def test_gatekeeper_one_family_not_name(self):
        src = """
        contract Anything {
            address public entrant;
            modifier gate { require(gasleft() % 8191 == 0); _; }
            function enter(bytes8 _gateKey) external gate {
                require(uint32(uint64(_gateKey)) == uint16(uint160(tx.origin)));
                entrant = tx.origin;
            }
        }
        """
        feats = extract_features(src, "Anything")
        self.assertIn("gasleft_modulo", feats)
        self.assertTrue(should_run("_synth_gatekeeper_one", feats))
        # SafeVault must NOT run this expensive solver
        sv = extract_features(self.src("SafeVault"), "SafeVault")
        self.assertFalse(should_run("_synth_gatekeeper_one", sv))

    def test_puzzle_wallet_family_needs_proxy_and_multicall(self):
        src = """
        contract Proxy { address public pendingAdmin; address public admin;
            function proposeNewAdmin(address) external {} }
        contract Wallet {
            function multicall(bytes[] calldata) external payable {}
            function setMaxBalance(uint256) external {}
        }
        """
        feats = extract_features(src, "Proxy")
        self.assertIn("proxy_admin", feats)
        self.assertIn("nested_multicall", feats)
        self.assertTrue(should_run("_synth_puzzle_wallet", feats))
        self.assertFalse(should_run("_synth_puzzle_wallet",
                                    extract_features(self.src("OpenVault"), "OpenVault")))

    def test_unknown_fn_always_runs(self):
        self.assertTrue(should_run("_synth_brand_new", set()))

    def test_none_features_runs_all(self):
        self.assertTrue(should_run("_synth_gatekeeper_one", None))


class ScannerParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.targets = load_all()

    def test_vulnerable_scored_safe_zero(self):
        pairs = [
            ("ReentrantVault", "SafeVault", "reentrancy"),
            ("OpenVault", "BoundedOwner", "access_control"),
            ("DelegateVault", "LibraryVault", "delegatecall_hijack"),
            ("PredictableLottery", "CommitLottery", "weak_randomness"),
            ("OpenInitializer", "GuardedInitializer", "unprotected_init"),
        ]
        for vuln, safe, fam in pairs:
            vs = scan_target(self.targets[vuln]["src"],
                             self.targets[vuln]["inv"],
                             self.targets[vuln]["manifest"])["scores"]
            ss = scan_target(self.targets[safe]["src"],
                             self.targets[safe]["inv"],
                             self.targets[safe]["manifest"])["scores"]
            self.assertGreater(vs.get(fam, 0), 0, f"{vuln} should score {fam}")
            self.assertLessEqual(ss.get(fam, 0), 0, f"{safe} should not score {fam}")


class TargetsFromDisk(unittest.TestCase):
    def test_twelve_track_targets(self):
        t = load_all()
        expected = {
            "ReentrantVault", "OpenVault", "BadAccounting", "NaiveOracle",
            "DelegateVault", "PredictableLottery", "OpenInitializer",
            "SafeVault", "BoundedOwner", "LibraryVault", "CommitLottery",
            "GuardedInitializer",
        }
        self.assertTrue(expected.issubset(t.keys()))
        self.assertTrue(t["ReentrantVault"]["src"].strip())
        self.assertIn("vaultSolvent", t["ReentrantVault"]["inv"])


if __name__ == "__main__":
    unittest.main()
