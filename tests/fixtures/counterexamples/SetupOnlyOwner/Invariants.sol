// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IOwnedTarget {
    function owner() external view returns (address);
}

contract Invariants {
    address internal constant EXPECTED_OWNER = address(0xA11CE);

    function ownerUnchanged(address target) public view returns (bool) {
        return IOwnedTarget(target).owner() == EXPECTED_OWNER;
    }

    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!ownerUnchanged(target)) return (false, "ownerUnchanged");
        return (true, "");
    }
}

