// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IPhasedGhostView {
    function broken() external view returns (bool);
}

contract Invariants {
    function neverBroken(address target) public view returns (bool) {
        return !IPhasedGhostView(target).broken();
    }

    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!neverBroken(target)) return (false, "neverBroken");
        return (true, "");
    }
}

