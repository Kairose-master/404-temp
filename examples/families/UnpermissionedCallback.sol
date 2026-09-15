// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: unpermissioned_callback (Truster / AtomicQueue).
/// Bug: flashLoan forwards attacker-chosen `target.call(data)` with no
/// caller check. Attacker makes the pool approve them, then drain.
/// Invariant: poolTokenSolvent — token.balanceOf(pool) never decreases
/// unless a real loan is repaid.

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract FlashPool {
    IERC20 public token;

    constructor(address t) payable { token = IERC20(t); }

    function flashLoan(uint256 amount, address borrower, address target, bytes calldata data)
        external
    {
        uint256 before = token.balanceOf(address(this));
        require(token.transfer(borrower, amount), "xfer");
        (bool ok,) = target.call(data);
        require(ok, "callback");
        require(token.balanceOf(address(this)) >= before, "unpaid");
    }
}
