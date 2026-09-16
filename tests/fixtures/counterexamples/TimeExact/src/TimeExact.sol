// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Dual of TimeAhead: only the frozen official timestamp works.
contract TimeExact {
    bool public broken;
    function pwn() external {
        require(block.timestamp == 1_735_689_600, "not frozen");
        broken = true;
    }
}
