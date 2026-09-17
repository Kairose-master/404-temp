// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface I { function owner() external view returns (address); }
contract Invariants {
    function neverBroken(address t) public view returns (bool) {
        return I(t).owner() == address(0xA11CE);
    }
    function checkAll(address t) external view returns (bool ok, string memory v) {
        if (!neverBroken(t)) return (false, "neverBroken");
        return (true, "");
    }
}
