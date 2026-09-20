import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.candidates import candidate_fingerprint, normalize_candidate
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


class WorldCandidateGate(unittest.TestCase):
    def test_helper_contract_alone_is_not_a_candidate(self):
        src = """
        contract Helper { function ping() external {} }
        contract Vault { address public helper; constructor(address h) { helper = h; } }
        """
        self.assertEqual(list(iter_world_candidates(src, "Vault", {"multi_contract_unit"})), [])


if __name__ == "__main__":
    unittest.main()
