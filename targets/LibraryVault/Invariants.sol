// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IOwned { function owner() external view returns (address); }

contract Invariants {
    address constant INITIAL_OWNER = address(0xA11CE);
    function ownerUnchanged(address target) public view returns (bool) {
        return IOwned(target).owner() == INITIAL_OWNER;
    }
    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!ownerUnchanged(target)) return (false, "ownerUnchanged");
        return (true, "");
    }
}
