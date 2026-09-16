// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {SetupDealVault} from "./src/SetupDealVault.sol";
interface IVm { function deal(address, uint256) external; }
contract Setup {
    IVm constant vm = IVm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    function run() external returns (address target) {
        vm.deal(address(this), 10 ether);
        target = address(new SetupDealVault{value: 10 ether}());
    }
}
