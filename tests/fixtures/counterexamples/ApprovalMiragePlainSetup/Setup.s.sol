// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {ApprovalMirage} from "./src/ApprovalMirage.sol";

// Separate control, not a replacement for ApprovalMirage's HEVM Setup.
// The one fixture label has a fixed address, so no cheatcode is needed.
contract Setup {
    function makeAddr(string memory name) internal pure returns (address) {
        require(keccak256(bytes(name)) == keccak256(bytes("alice")), "unknown fixture label");
        return 0x328809Bc894f92807417D2dAD6b7C998c1aFdac6;
    }

    function run() external returns (address target) {
        address alice = makeAddr("alice");
        ApprovalMirage deployed = new ApprovalMirage();
        require(alice == deployed.victim(), "address derivation mismatch");
        require(deployed.token().allowance(alice, address(deployed)) == 0, "unexpected approval");
        target = address(deployed);
    }
}
