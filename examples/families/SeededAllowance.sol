// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: seeded_allowance_drain.
/// Bug: Setup already did `vm.prank(victim); token.approve(vault, max)`.
/// Exploit drain leftover allowance with transferFrom — no cheatcode.
/// Invariant: victimBalanceSafe.

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

contract PullVault {
    address public victim;
    IERC20 public token;

    constructor(address v, address t) {
        victim = v;
        token = IERC20(t);
    }

    /// Setup calls this as the victim (or world.txs from a second EOA).
    function seed() external {
        token.approve(address(this), type(uint256).max);
    }

    function pull() external {
        uint256 a = token.allowance(victim, address(this));
        uint256 b = token.balanceOf(victim);
        uint256 n = a < b ? a : b;
        require(token.transferFrom(victim, msg.sender, n));
    }
}
