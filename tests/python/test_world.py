#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.features import extract_features
from trust404.world import contracts_in, plan_world


class WorldModel(unittest.TestCase):
    def test_cross_router_sees_three_contracts(self):
        src = (ROOT / "benches/fixtures/cross_router/src/CrossRouter.sol").read_text()
        cs = contracts_in(src)
        names = {c.name for c in cs}
        self.assertGreaterEqual(len(names), 3)
        self.assertTrue({"ToyToken", "ToyPair", "CrossRouter"} <= names)
        plan = plan_world(src, "CrossRouter", extract_features(src, "CrossRouter"))
        self.assertTrue(plan.cross_contract)
        self.assertIn("run(address", plan.folded_exploit)
        self.assertIn("function run(address", plan.folded_exploit)

    def test_single_vault_is_not_cross(self):
        src = """
        contract Vault {
            mapping(address => uint256) public balances;
            function withdraw() external {
                (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
                balances[msg.sender] = 0;
            }
        }
        """
        plan = plan_world(src, "Vault", extract_features(src, "Vault"))
        self.assertFalse(plan.cross_contract)
        self.assertEqual(len(plan.contracts), 1)

    def test_unpermissioned_callback_plans_token_drain(self):
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
        plan = plan_world(src, "Pool", feats)
        ons = [s.on for s in plan.steps]
        self.assertIn("$token", ons)
        self.assertIn("transferFrom", plan.folded_exploit)
