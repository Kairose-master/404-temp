// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: victim_approve.
/// Bug: pull() transferFrom(victim) using an allowance the victim must
/// grant first. Forge path: vm.prank(victim). py-evm: world.txs.
/// Invariant: victimBalanceSafe — victim token balance does not fall
/// unless they signed the approve.

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

    function pull() external {
        uint256 a = token.allowance(victim, address(this));
        uint256 b = token.balanceOf(victim);
        uint256 n = a < b ? a : b;
        require(token.transferFrom(victim, msg.sender, n));
    }
}
