// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Harness, IInvariants} from "../harness/src/Harness.sol";
import {PredictableLottery} from "../targets/PredictableLottery/src/PredictableLottery.sol";
import {Invariants as LotteryInvariants} from "../targets/PredictableLottery/Invariants.sol";

contract DeterministicConstructor {
    uint256 public immutable deployedAt;

    constructor() {
        deployedAt = block.timestamp;
    }
}

interface IDeterministicConstructor {
    function deployedAt() external view returns (uint256);
}

contract Invariants {
    uint256 internal constant EXPECTED_TIMESTAMP = 1_735_689_600;

    function checkAll(address target) external view returns (bool, string memory) {
        if (IDeterministicConstructor(target).deployedAt() != EXPECTED_TIMESTAMP) {
            return (false, "constructorTimestampFrozen");
        }
        return (true, "");
    }
}

contract ManifestDeploymentTest is Harness {
    function test_direct_manifest_deployment_sends_value() public {
        vm.deal(address(this), 21 ether);
        string memory manifest = vm.readFile("targets/PredictableLottery/manifest.json");
        (address target, address invariants,,, uint256 valueWei) =
            _deployFromManifest(manifest, "targets/PredictableLottery");

        assertTrue(valueWei == 20 ether, "manifest value_wei parsed incorrectly");
        assertTrue(target.balance == 20 ether, "target constructor did not receive value_wei");
        (bool healthy,) = IInvariants(invariants).checkAll(target);
        assertTrue(healthy, "target must be healthy immediately after manifest deployment");
    }

    function test_manifest_determinism_is_applied_before_constructor() public {
        string memory manifest = string.concat(
            '{"target":{"name":"DeterministicConstructor",',
            '"src":"test/ManifestDeployment.t.sol"},',
            '"deploy":{"value_wei":"0","constructor_args":[]},',
            '"determinism":{"block_number":21000000,',
            '"block_timestamp":1735689600},',
            '"invariants":{"contract":"test/ManifestDeployment.t.sol"}}'
        );
        (address target, address invariants, uint256 blockNumber, uint256 blockTimestamp,) =
            _deployFromManifest(manifest, "");

        assertTrue(block.number == blockNumber, "block number was not frozen before deployment");
        assertTrue(block.timestamp == blockTimestamp, "timestamp was not frozen before deployment");
        assertTrue(
            IDeterministicConstructor(target).deployedAt() == blockTimestamp,
            "constructor observed a non-deterministic timestamp"
        );
        (bool healthy,) = IInvariants(invariants).checkAll(target);
        assertTrue(healthy, "constructor-derived initial invariant must hold");
    }
}
