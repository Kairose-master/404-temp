// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface I { function stamped() external view returns (uint256); }
contract Invariants {
    uint256 constant BASELINE = 1735689600;
    uint256 constant ONCE = 1735689600 + 1 days;
    function stampedOnce(address t) public view returns (bool) {
        // Setup may warp while building state, but Harness._prove restores the
        // manifest timestamp before checking the official initial state.
        return I(t).stamped() == ONCE && block.timestamp == BASELINE;
    }
    function checkAll(address t) external view returns (bool ok, string memory v) {
        if (!stampedOnce(t)) return (false, "stampedOnce");
        return (true, "");
    }
}
