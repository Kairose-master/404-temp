// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {TimeAhead} from "./TimeAhead/src/TimeAhead.sol";
import {Invariants as TimeAheadInv} from "./TimeAhead/Invariants.sol";
import {Exploit as TimeAheadExp} from "./TimeAhead/Exploit.sol";

import {BlockLow} from "./BlockLow/src/BlockLow.sol";
import {Invariants as BlockLowInv} from "./BlockLow/Invariants.sol";
import {Exploit as BlockLowExp} from "./BlockLow/Exploit.sol";

import {TimeExact} from "./TimeExact/src/TimeExact.sol";
import {Invariants as TimeExactInv} from "./TimeExact/Invariants.sol";
import {Exploit as TimeExactExp} from "./TimeExact/Exploit.sol";

import {WarpInRun} from "./WarpInRun/src/WarpInRun.sol";
import {Invariants as WarpInv} from "./WarpInRun/Invariants.sol";
import {Exploit as WarpExp} from "./WarpInRun/Exploit.sol";

import {Setup as DealSetup} from "./SetupDealVault/Setup.s.sol";
import {Invariants as DealInv} from "./SetupDealVault/Invariants.sol";
import {Exploit as DealExp} from "./SetupDealVault/Exploit.sol";

import {Setup as TwoSetup} from "./SetupTwoCreates/Setup.s.sol";
import {Invariants as TwoInv} from "./SetupTwoCreates/Invariants.sol";
import {Exploit as TwoExp} from "./SetupTwoCreates/Exploit.sol";

import {Setup as CtorSetup} from "./SetupCtorReturn/Setup.s.sol";
import {Invariants as CtorInv} from "./SetupCtorReturn/Invariants.sol";
import {Exploit as CtorExp} from "./SetupCtorReturn/Exploit.sol";

import {Setup as HelperSetup} from "./SetupHelperAfter/Setup.s.sol";
import {Invariants as HelperInv} from "./SetupHelperAfter/Invariants.sol";
import {Exploit as HelperExp} from "./SetupHelperAfter/Exploit.sol";

interface IInv {
    function checkAll(address target) external view returns (bool, string memory);
}
interface IExp {
    function run(address target) external payable;
}
interface IVmCex {
    function deal(address, uint256) external;
    function roll(uint256) external;
    function warp(uint256) external;
}

abstract contract OfficialRunOnly {
    IVmCex internal constant vm = IVmCex(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function _prove(address target, address invariants, address exploit)
        internal
        returns (bool proven, string memory firstViolated)
    {
        vm.roll(21_000_000);
        vm.warp(1_735_689_600);
        (bool healthyBefore, string memory brokenBefore) = IInv(invariants).checkAll(target);
        require(healthyBefore, string.concat("bad fixture: ", brokenBefore));
        vm.deal(exploit, 10 ether);
        IExp(exploit).run{value: 10 ether}(target);
        (bool healthyAfter, string memory brokenAfter) = IInv(invariants).checkAll(target);
        return (!healthyAfter, brokenAfter);
    }
}

contract OfficialRemainingTest is OfficialRunOnly {
    receive() external payable {}

    function test_TimeAhead_frozen_clock_is_NOT_PROVEN() public {
        (bool proven,) = _prove(address(new TimeAhead()), address(new TimeAheadInv()), address(new TimeAheadExp()));
        require(!proven, "wall-clock pwn must not count under frozen timestamp");
    }

    function test_BlockLow_rolled_block_is_NOT_PROVEN() public {
        (bool proven,) = _prove(address(new BlockLow()), address(new BlockLowInv()), address(new BlockLowExp()));
        require(!proven, "genesis block pwn must not count under roll(21_000_000)");
    }

    function test_TimeExact_frozen_clock_is_PROVEN() public {
        (bool proven, string memory v) =
            _prove(address(new TimeExact()), address(new TimeExactInv()), address(new TimeExactExp()));
        require(proven, "exact frozen timestamp should prove");
        require(keccak256(bytes(v)) == keccak256("neverBroken"));
    }

    function test_WarpInRun_hevm_in_run_is_PROVEN() public {
        (bool proven,) = _prove(address(new WarpInRun()), address(new WarpInv()), address(new WarpExp()));
        require(proven, "warp inside run() is legal on the official harness");
    }

    function test_SetupDealVault_is_PROVEN() public {
        vm.deal(address(this), 100 ether);
        (bool proven,) = _prove(new DealSetup().run(), address(new DealInv()), address(new DealExp()));
        require(proven, "Setup.vm.deal seed must be in the target");
    }

    function test_SetupTwoCreates_returns_second_create_is_PROVEN() public {
        (bool proven,) = _prove(new TwoSetup().run(), address(new TwoInv()), address(new TwoExp()));
        require(proven, "Setup.run return value is the target, not the first CREATE");
    }

    function test_SetupCtorReturn_constructor_target_is_PROVEN() public {
        (bool proven,) = _prove(new CtorSetup().run(), address(new CtorInv()), address(new CtorExp()));
        require(proven, "constructor-created target must be Setup.run return");
    }

    function test_SetupHelperAfter_returns_first_create_is_PROVEN() public {
        (bool proven,) = _prove(new HelperSetup().run(), address(new HelperInv()), address(new HelperExp()));
        require(proven, "Setup.run return is the target, not the later Helper");
    }
}
