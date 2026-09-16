// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Official harness rolls to 21_000_000. py-evm genesis is block 0.
contract BlockLow {
    bool public broken;
    function pwn() external {
        require(block.number < 100, "rolled");
        broken = true;
    }
}
