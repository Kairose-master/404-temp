// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Invariants {
    function neverBroken(address t) public view returns (bool) { return t.balance >= 10 ether; }
    function checkAll(address t) external view returns (bool ok, string memory v) {
        if (!neverBroken(t)) return (false, "neverBroken");
        return (true, "");
    }
}
