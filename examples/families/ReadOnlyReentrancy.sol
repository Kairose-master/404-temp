// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: readonly_reentrancy (Curve / Balancer).
/// Bug: price() is a view over address(this).balance. withdraw() sends ETH
/// then burns shares. During the callback, deposit() mints against the
/// stale (still-high) price.
/// Invariant: sharePriceMonotone — totalAssets / totalSupply does not jump
/// in the attacker's favour inside one tx.

contract CurveLike {
    uint256 public totalSupply;
    mapping(address => uint256) public shares;

    constructor() payable {
        totalSupply = 10 ether;
        shares[address(this)] = 10 ether;
    }

    function totalAssets() public view returns (uint256) {
        return address(this).balance;
    }

    function price() public view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return (totalAssets() * 1e18) / totalSupply;
    }

    function deposit() external payable {
        uint256 sh = (msg.value * 1e18) / price();
        shares[msg.sender] += sh;
        totalSupply += sh;
    }

    function withdraw() external {
        uint256 sh = shares[msg.sender];
        uint256 v = (sh * price()) / 1e18;
        (bool ok,) = msg.sender.call{value: v}("");
        require(ok);
        shares[msg.sender] = 0;
        totalSupply -= sh;
    }
}
