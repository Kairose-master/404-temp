#!/usr/bin/env python3
"""Fuzz search must use the same world and caller shape as Track 04."""
import os
import sys
import unittest
from itertools import islice
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

from api import prove


def _solc():
    try:
        import solcx
        solcx.set_solc_version("0.8.24")
        return True
    except Exception:
        return False


def _manifest(name, setup=None):
    deploy = {"constructor_args": [], "value_wei": "0"}
    if setup:
        deploy["setup"] = setup
    return {
        "schema": "trust404.track04.manifest/0.1",
        "target": {
            "name": name,
            "src": f"src/{name}.sol",
            "solc": "0.8.24",
            "evm_version": "cancun",
        },
        "deploy": deploy,
        "determinism": {
            "block_number": 21_000_000,
            "block_timestamp": 1_735_689_600,
            "seed": 42,
        },
        "invariants": {"contract": "Invariants.sol", "predicates": ["healthy"]},
    }


CALLER_TARGET = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract CallerSensitive {
    address public caller;
    function seize() external {
        require(msg.sender.code.length > 0, "contract caller required");
        caller = msg.sender;
    }
    function seizeAgain() external {
        require(msg.sender.code.length > 0, "contract caller required");
        caller = msg.sender;
    }
}
"""

CALLER_INVARIANTS = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
interface ICallerSensitive { function caller() external view returns (address); }
contract Invariants {
    function checkAll(address target) external view returns (bool, string memory) {
        if (ICallerSensitive(target).caller() != address(0)) return (false, "healthy");
        return (true, "");
    }
}
"""

ADDRESS_ARGUMENT_TARGET = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract AddressArgument {
    struct Claim { address who; bool enabled; }
    address public caller;
    function seize(Claim calldata claim) external {
        require(claim.who == msg.sender, "wrong caller argument");
        require(claim.enabled, "disabled");
        caller = claim.who;
    }
}
"""

ADDRESS_ARGUMENT_INVARIANTS = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
interface IAddressArgument { function caller() external view returns (address); }
contract Invariants {
    function checkAll(address target) external view returns (bool, string memory) {
        if (IAddressArgument(target).caller() != address(0)) return (false, "healthy");
        return (true, "");
    }
}
"""

COMPOSITE_TARGET = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract CompositeGate {
    bool public broken;
    function unlock(bytes4 key, int8 delta, uint256[] calldata path) external {
        require(key == bytes4(0xffffffff), "key");
        require(delta == -1, "delta");
        require(path.length == 0, "path");
        broken = true;
    }
}
"""

COMPOSITE_INVARIANTS = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
interface ICompositeGate { function broken() external view returns (bool); }
contract Invariants {
    function checkAll(address target) external view returns (bool, string memory) {
        if (ICompositeGate(target).broken()) return (false, "healthy");
        return (true, "");
    }
}
"""

SEQUENCE_TARGET = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract SequenceGate {
    bool public armed;
    bool public broken;
    function arm() external { armed = true; }
    function corrupt() external { require(armed, "not armed"); broken = true; }
}
"""

SEQUENCE_INVARIANTS = """
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
interface ISequenceGate { function broken() external view returns (bool); }
contract Invariants {
    function checkAll(address target) external view returns (bool, string memory) {
        if (ISequenceGate(target).broken()) return (false, "healthy");
        return (true, "");
    }
}
"""


class FuzzCodegen(unittest.TestCase):
    def test_codegen_keeps_actions_inside_one_run_from_contract_caller(self):
        source = prove._fuzz_codegen([{
            "name": "claim",
            "signature": "claim(address)",
            "types": ["address"],
            "args": [prove._ATTACKER],
            "value": 0,
        }], {})
        self.assertIn("function run(address t) external payable", source)
        self.assertIn("t.call", source)
        self.assertIn("address(this)", source)
        self.assertIn('claim(address)', source)
        self.assertNotIn("interface I", source)

    def test_overloaded_functions_keep_distinct_signatures(self):
        functions = prove._fuzz_fns([
            {"type": "function", "name": "act", "stateMutability": "nonpayable",
             "inputs": [{"type": "uint256"}]},
            {"type": "function", "name": "act", "stateMutability": "nonpayable",
             "inputs": [{"type": "address"}]},
        ])
        self.assertEqual(
            {"act(uint256)", "act(address)"},
            {function["signature"] for function in functions},
        )

    def test_composite_abi_types_are_searchable(self):
        functions = prove._fuzz_fns([{
            "type": "function", "name": "act", "stateMutability": "nonpayable",
            "inputs": [
                {"type": "int8"}, {"type": "bytes4"}, {"type": "string"},
                {"type": "uint256[]"},
                {"type": "tuple", "components": [
                    {"type": "address"}, {"type": "bool"},
                ]},
            ],
        }])
        self.assertEqual(
            "act(int8,bytes4,string,uint256[],(address,bool))",
            functions[0]["signature"],
        )

    def test_multiblock_workflow_is_not_a_track_candidate(self):
        self.assertNotIn(
            "_multiblock_attempt",
            {provider.__name__ for provider in prove._track_synth_functions()},
        )


@unittest.skipUnless(_solc(), "solc 0.8.24 not installed")
class HarnessShapedFuzzing(unittest.TestCase):
    def test_contract_caller_candidate_is_discovered_and_reproduced(self):
        manifest = _manifest("CallerSensitive")
        feedback = []
        candidates = list(islice(prove._iter_fuzz_candidates(
            "CallerSensitive", CALLER_TARGET, CALLER_INVARIANTS, manifest, True,
            budget=40, depth=1, max_candidates=2, feedback_sink=feedback,
        ), 2))
        self.assertEqual(2, len(candidates))
        self.assertNotEqual(
            prove._fuzz_sequence_key(candidates[0][0]),
            prove._fuzz_sequence_key(candidates[1][0]),
        )
        self.assertTrue(candidates[0][2]["calls"][0]["success"])
        self.assertTrue(candidates[0][2]["predicate_before"]["allHold"])
        self.assertFalse(candidates[0][2]["predicate_after"]["allHold"])

        from verify import verify_full
        exploit = prove._fuzz_codegen(candidates[0][0], candidates[0][1])
        with patch.dict(os.environ, {"TRUST404_VERIFIER": "evm"}):
            result = verify_full(
                "CallerSensitive", CALLER_TARGET, CALLER_INVARIANTS,
                exploit, manifest, 42,
            )
        self.assertTrue(result.proven, result.detail)

    def test_symbolic_attacker_address_is_rebound_in_generated_calldata(self):
        manifest = _manifest("AddressArgument")
        sequence, payable_map, feedback = next(prove._iter_fuzz_candidates(
            "AddressArgument", ADDRESS_ARGUMENT_TARGET,
            ADDRESS_ARGUMENT_INVARIANTS, manifest, True,
            budget=30, depth=1, max_candidates=1,
        ))
        self.assertEqual("attacker", sequence[0]["address_patches"][0]["symbol"])
        exploit = prove._fuzz_codegen(sequence, payable_map)
        self.assertIn("assembly { mstore", exploit)
        self.assertIn("address()", exploit)

        from verify import verify_full
        with patch.dict(os.environ, {"TRUST404_VERIFIER": "evm"}):
            result = verify_full(
                "AddressArgument", ADDRESS_ARGUMENT_TARGET,
                ADDRESS_ARGUMENT_INVARIANTS, exploit, manifest, 42,
            )
        self.assertTrue(result.proven, result.detail)

    def test_manifest_setup_and_full_sources_define_fuzz_world(self):
        target = """
        // SPDX-License-Identifier: MIT
        pragma solidity 0.8.24;
        contract SetupTarget {
            uint256 public state;
            constructor(uint256 initial) { state = initial; }
            function corrupt() external { require(state == 7); state = 8; }
        }
        """
        setup = """
        // SPDX-License-Identifier: MIT
        pragma solidity 0.8.24;
        import {SetupTarget} from "./src/SetupTarget.sol";
        contract Setup {
            function run() external returns (address) {
                return address(new SetupTarget(7));
            }
        }
        """
        invariants = """
        // SPDX-License-Identifier: MIT
        pragma solidity 0.8.24;
        interface ISetupTarget { function state() external view returns (uint256); }
        contract Invariants {
            function checkAll(address target) external view returns (bool, string memory) {
                if (ISetupTarget(target).state() != 7) return (false, "healthy");
                return (true, "");
            }
        }
        """
        manifest = _manifest("SetupTarget", "Setup.s.sol")
        candidate = next(prove._iter_fuzz_candidates(
            "SetupTarget", target, invariants, manifest, True,
            budget=20, depth=1, max_candidates=1,
            extra_sources={"Setup.s.sol": setup},
        ))
        self.assertEqual("corrupt", candidate[0][0]["name"])

        from verify import verify_full
        exploit = prove._fuzz_codegen(candidate[0], candidate[1])
        with patch.dict(os.environ, {"TRUST404_VERIFIER": "evm"}):
            result = verify_full(
                "SetupTarget", target, invariants, exploit, manifest, 42,
                extra_sources={"Setup.s.sol": setup},
            )
        self.assertTrue(result.proven, result.detail)

    def test_dynamic_array_and_signed_inputs_reproduce_as_raw_calldata(self):
        manifest = _manifest("CompositeGate")
        candidate = next(prove._iter_fuzz_candidates(
            "CompositeGate", COMPOSITE_TARGET, COMPOSITE_INVARIANTS,
            manifest, True, budget=80, depth=1, pool_level=1,
            max_candidates=1,
        ))
        sequence, payable_map, feedback = candidate
        self.assertEqual("unlock", sequence[0]["name"])
        self.assertIn("encoded_data", sequence[0])
        self.assertEqual([], feedback["reproducer"][0]["arguments"][2])
        exploit = prove._fuzz_codegen(sequence, payable_map)
        self.assertIn("hex\"", exploit)

        from verify import verify_full
        with patch.dict(os.environ, {"TRUST404_VERIFIER": "evm"}):
            result = verify_full(
                "CompositeGate", COMPOSITE_TARGET, COMPOSITE_INVARIANTS,
                exploit, manifest, 42,
            )
        self.assertTrue(result.proven, result.detail)

    def test_state_only_two_call_path_is_found_and_one_minimal(self):
        manifest = _manifest("SequenceGate")
        candidate = next(prove._iter_fuzz_candidates(
            "SequenceGate", SEQUENCE_TARGET, SEQUENCE_INVARIANTS,
            manifest, True, budget=80, depth=2, max_candidates=1,
        ))
        sequence, payable_map, feedback = candidate
        self.assertEqual(["arm", "corrupt"], [call["name"] for call in sequence])
        self.assertEqual({
            "original_calls": 2,
            "final_calls": 2,
            "one_minimal": True,
        }, {
            key: feedback["minimization"][key]
            for key in ("original_calls", "final_calls", "one_minimal")
        })

        from verify import verify_full
        exploit = prove._fuzz_codegen(sequence, payable_map)
        with patch.dict(os.environ, {"TRUST404_VERIFIER": "evm"}):
            result = verify_full(
                "SequenceGate", SEQUENCE_TARGET, SEQUENCE_INVARIANTS,
                exploit, manifest, 42,
            )
        self.assertTrue(result.proven, result.detail)


if __name__ == "__main__":
    unittest.main()
