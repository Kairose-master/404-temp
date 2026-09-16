// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Official harness warps to 1735689600. py-evm uses wall-clock genesis.
contract TimeAhead {
    bool public broken;
    function pwn() external {
        require(block.timestamp > 1_740_000_000, "frozen");
        broken = true;
    }
}
