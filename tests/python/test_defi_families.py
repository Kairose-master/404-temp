#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.features import extract_features
from trust404.registry import should_run
from trust404.synth_defi import iter_defi_families


TRUSTER = """
pragma solidity ^0.8.0;
interface IERC20 { function approve(address,uint256) external returns (bool); }
contract Pool {
    IERC20 public token;
    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data) external {
        uint256 b = token.balanceOf(address(this));
        target.call(data);
        require(token.balanceOf(address(this)) >= b);
    }
}
"""

UNSTOPPABLE = """
pragma solidity ^0.8.0;
interface IERC20 { function balanceOf(address) external view returns (uint256); function transfer(address,uint256) external returns (bool); }
contract Pool {
    IERC20 public token;
    uint256 public poolBalance;
    function flashLoan(uint256) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        assert(poolBalance == balanceBefore);
    }
    function deposit() external { poolBalance += token.balanceOf(address(this)); }
}
"""

SELFIE = """
pragma solidity ^0.8.0;
contract Pool {
    function flashLoan(uint256 amount) external {}
    function snapshot() external returns (uint256) { return 1; }
    function queueAction(address,uint128,bytes calldata) external returns (uint256) { return 1; }
}
"""

CLIMBER = """
pragma solidity ^0.8.0;
contract Timelock {
    function execute(address[] calldata, uint256[] calldata, bytes[] calldata, bytes32) external payable {}
    function schedule(address[] calldata, uint256[] calldata, bytes[] calldata, bytes32) external {}
    function updateDelay(uint64) external {}
    function grantRole(bytes32, address) external {}
}
"""


class DeFiFamilies(unittest.TestCase):
    def test_truster_features_and_synth(self):
        f = extract_features(TRUSTER, "Pool")
        self.assertIn("unpermissioned_callback", f)
        self.assertTrue(should_run("unpermissioned_callback", f))
        labels = [l for l, _ in iter_defi_families(TRUSTER, "Pool")]
        self.assertTrue(any(l.startswith("unpermissioned-callback") for l in labels))

    def test_unstoppable_donation_dos(self):
        f = extract_features(UNSTOPPABLE, "Pool")
        self.assertIn("donation_accounting_dos", f)
        labels = [l for l, _ in iter_defi_families(UNSTOPPABLE, "Pool")]
        self.assertIn("donation-accounting-dos", labels)

    def test_selfie_governance_flashloan(self):
        f = extract_features(SELFIE, "Pool")
        self.assertIn("governance_flashloan", f)
        labels = [l for l, _ in iter_defi_families(SELFIE, "Pool")]
        self.assertTrue(any(l.startswith("governance-flashloan") for l in labels))

    def test_climber_execute_before_schedule(self):
        f = extract_features(CLIMBER, "Timelock")
        self.assertIn("execute_before_schedule", f)
        labels = [l for l, _ in iter_defi_families(CLIMBER, "Timelock")]
        self.assertIn("execute-before-schedule", labels)

    def test_safevault_skips_defi_families(self):
        from trust404.targets import load_target
        t = load_target("SafeVault")
        if not t:
            self.skipTest("targets missing")
        f = extract_features(t["src"], "SafeVault")
        self.assertFalse(should_run("unpermissioned_callback", f))
        self.assertFalse(should_run("governance_flashloan", f))
        self.assertFalse(should_run("_synth_gatekeeper_one", f))
        self.assertFalse(should_run("_synth_puzzle_wallet", f))


if __name__ == "__main__":
    unittest.main()
