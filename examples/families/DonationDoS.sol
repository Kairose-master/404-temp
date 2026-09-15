// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: donation_accounting_dos (Unstoppable).
/// Bug: flashLoan asserts internal `poolBalance == token.balanceOf(this)`.
/// A direct token.transfer into the pool desyncs the books → DoS.
/// Invariant: flashLoanReachable — the assert must keep holding.

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract AccountedPool {
    IERC20 public token;
    uint256 public poolBalance;

    constructor(address t) { token = IERC20(t); }

    function deposit(uint256 n) external {
        poolBalance += n;
    }

    function flashLoan(uint256 amount) external {
        uint256 balanceBefore = token.balanceOf(address(this));
        assert(poolBalance == balanceBefore);
        require(token.transfer(msg.sender, amount));
        require(token.balanceOf(address(this)) >= balanceBefore);
    }
}
