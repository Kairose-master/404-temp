// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {SetupWarpOnce} from "./src/SetupWarpOnce.sol";
interface IVmW { function warp(uint256) external; }
contract Setup {
    IVmW constant vm = IVmW(address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D));
    function run() external returns (address target) {
        vm.warp(block.timestamp + 1 days);
        target = address(new SetupWarpOnce());
    }
}
