// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IOwnerView {
    function owner() external view returns (address);
}

contract Invariants {
    function ownerUnchanged(address target) public view returns (bool) {
        return IOwnerView(target).owner() == address(0xA11CE);
    }

    function checkAll(address target) external view returns (bool, string memory) {
        if (!ownerUnchanged(target)) return (false, "ownerUnchanged");
        return (true, "");
    }
}
