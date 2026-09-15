// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: cross_getter_drain.
/// Bug: Vault exposes public token()/pool()/oracle() pointing at sibling
/// contracts in the same unit. drain() pulls the sibling's tokens.
/// Invariant: oracleSolvent — sibling token balance covers vault debt.

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract Oracle {
    uint256 public px = 1e18;
    function price() external view returns (uint256) { return px; }
    function set(uint256 p) external { px = p; }
}

contract LendingDesk {
    IERC20 public immutable asset;
    Oracle public immutable feed;
    address public pool;
    uint256 public debt;

    constructor(address t, address o) payable {
        asset = IERC20(t);
        feed = Oracle(o);
        pool = address(this);
    }

    function token() external view returns (address) { return address(asset); }
    function oracle() external view returns (address) { return address(feed); }

    function borrow(uint256 n) external payable {
        require(msg.value * feed.price() >= n * 1e18, "col");
        debt += n;
        require(asset.transfer(msg.sender, n));
    }
}
