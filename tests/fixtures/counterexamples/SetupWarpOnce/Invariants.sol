// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface I { function stamped() external view returns (uint256); }
contract Invariants {
    uint256 constant ONCE = 1735689600 + 1 days;
    function stampedOnce(address t) public view returns (bool) {
        return I(t).stamped() == ONCE;
    }
    function checkAll(address t) external view returns (bool ok, string memory v) {
        if (!stampedOnce(t)) return (false, "stampedOnce");
        return (true, "");
    }
}
