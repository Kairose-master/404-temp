// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract WarpInRun {
    uint256 public unlockAt;
    bool public broken;
    function arm() external { unlockAt = block.timestamp + 1 hours; }
    function finish() external {
        require(unlockAt != 0, "not armed");
        require(block.timestamp >= unlockAt, "too early");
        broken = true;
    }
}
