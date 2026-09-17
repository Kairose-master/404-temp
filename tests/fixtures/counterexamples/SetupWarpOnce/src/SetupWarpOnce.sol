// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract SetupWarpOnce {
    uint256 public stamped;
    constructor() { stamped = block.timestamp; }
    function bump() external { stamped = 0; }
}
