// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: governance_flashloan (Selfie).
/// Bug: snapshot() reads the caller's token balance in the same tx as a
/// flashLoan, so a borrower can queueAction with inflated votes.
/// Invariant: actionQueueHonest — no action queued by a flash borrower.

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
}

interface IFlashBorrower {
    function onFlashLoan(uint256 amount) external;
}

contract GovPool {
    IERC20 public token;
    uint256 public lastSnapshot;
    uint256 public queued;

    constructor(address t) { token = IERC20(t); }

    function flashLoan(uint256 amount) external {
        require(token.transfer(msg.sender, amount));
        IFlashBorrower(msg.sender).onFlashLoan(amount);
        require(token.transferFrom(msg.sender, address(this), amount));
    }

    function snapshot() external returns (uint256) {
        lastSnapshot = token.balanceOf(msg.sender);
        return lastSnapshot;
    }

    function queueAction(address, uint128, bytes calldata) external returns (uint256) {
        require(lastSnapshot * 2 > token.balanceOf(address(this)), "votes");
        queued += 1;
        return queued;
    }
}
