// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ApprovalMirage} from "./src/ApprovalMirage.sol";

interface IVmAddress {
    function addr(uint256 privateKey) external returns (address);
}

contract Setup {
    IVmAddress private constant vm = IVmAddress(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    function makeAddr(string memory name) internal returns (address) {
        return vm.addr(uint256(keccak256(bytes(name))));
    }

    function run() external returns (address target) {
        // Merely naming the deterministic account must not create an approval.
        address alice = makeAddr("alice");
        ApprovalMirage deployed = new ApprovalMirage();
        require(alice == deployed.victim(), "address derivation mismatch");
        target = address(deployed);
    }
}

