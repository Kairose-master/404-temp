import sys
import unittest
from itertools import islice
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.candidates import (
    candidate_fingerprint,
    invariant_dependencies,
    normalize_candidate,
    rank_template_families,
    schedule_candidates,
)
from trust404.world import iter_world_candidates


class CandidateIdentity(unittest.TestCase):
    def test_comments_pragma_and_whitespace_do_not_create_duplicates(self):
        a = """// SPDX-License-Identifier: MIT
        pragma solidity ^0.8.20;
        contract Exploit { function run(address t) external { I(t).go(1); } }
        """
        b = """pragma solidity >=0.8.0; /* provider note */
        contract Exploit{function run(address t)external{I(t).go(1);}}
        """
        self.assertEqual(candidate_fingerprint(a), candidate_fingerprint(b))

    def test_different_arguments_remain_distinct(self):
        a = "contract Exploit{function run(address t)external{I(t).go(1);}}"
        b = "contract Exploit{function run(address t)external{I(t).go(2);}}"
        self.assertNotEqual(candidate_fingerprint(a), candidate_fingerprint(b))
        self.assertNotEqual(normalize_candidate(a), normalize_candidate(b))


class CandidateRanking(unittest.TestCase):
    def test_invariant_dependencies_cover_track_state_classes(self):
        src = """
        function check(address target) external view returns (bool) {
            return target.balance > 1 && IV(target).owner() != address(0)
                && IV(target).totalDebt() <= IV(target).totalCollateral()
                && IERC20(target).totalSupply() >= IERC20(target).balanceOf(target);
        }
        """
        self.assertEqual(
            {"native_balance", "privilege", "debt", "collateral", "supply", "token_balance"},
            invariant_dependencies(src),
        )

    def test_invariant_relevant_template_wins_equal_score(self):
        findings = {
            "scores": {"reentrancy": 5, "access_control": 5},
            "reentrancy_deposit": {"name": "deposit"},
            "reentrancy_withdraw": {"name": "withdraw"},
            "access_setowner": {"name": "setOwner"},
        }
        ranked = rank_template_families(
            ["reentrancy", "access_control"], findings, {"privilege"}, 42)
        self.assertEqual("access_control", ranked[0])

    def test_stage_reservations_reach_synth_and_fuzz(self):
        raw = [
            ("template", "t1", "1", {}),
            ("template", "t2", "2", {}),
            ("template", "t3", "3", {}),
            ("template", "t4", "4", {}),
            ("synth", "s1", "5", {}),
            ("synth", "s2", "6", {}),
            ("fuzz", "f1", "7", {}),
        ]
        metrics = {}
        scheduled = list(islice(schedule_candidates(raw, 5, metrics), 5))
        self.assertEqual(["t1", "t2", "t3", "s1", "f1"],
                         [candidate[1] for candidate in scheduled])
        self.assertEqual(2, metrics["deferred"])

    def test_unused_reservation_returns_to_deferred_candidates(self):
        raw = [
            ("template", "t1", "1", {}),
            ("template", "t2", "2", {}),
            ("template", "t3", "3", {}),
            ("template", "t4", "4", {}),
            ("synth", "s1", "5", {}),
            ("synth", "s2", "6", {}),
        ]
        scheduled = list(schedule_candidates(raw, 5))
        self.assertEqual(["t1", "t2", "t3", "s1", "t4"],
                         [candidate[1] for candidate in scheduled])


class WorldCandidateGate(unittest.TestCase):
    def test_helper_contract_alone_is_not_a_candidate(self):
        src = """
        contract Helper { function ping() external {} }
        contract Vault { address public helper; constructor(address h) { helper = h; } }
        """
        self.assertEqual(list(iter_world_candidates(src, "Vault", {"multi_contract_unit"})), [])


if __name__ == "__main__":
    unittest.main()
