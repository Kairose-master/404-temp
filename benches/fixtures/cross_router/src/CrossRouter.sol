// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// CROSS-CONTRACT class — ReX's measured failure mode.
/// Drain requires two contracts in one unit: a Pair (spot) and a Router
/// that trusts the pair's reserves. A single-contract synth on Router
/// alone cannot see the donation surface; a world plan can.
contract ToyToken {
    mapping(address => uint256) public balanceOf;
    constructor() { balanceOf[msg.sender] = 1_000_000 ether; }
    function transfer(address to, uint256 n) external returns (bool) {
        require(balanceOf[msg.sender] >= n, "bal");
        balanceOf[msg.sender] -= n;
        balanceOf[to] += n;
        return true;
    }
}

contract ToyPair {
    ToyToken public token;
    uint256 public reserve;
    constructor(ToyToken t) { token = t; }
    function donate() external {
        reserve = token.balanceOf(address(this));
    }
    function getSpot() external view returns (uint256) {
        uint256 b = token.balanceOf(address(this));
        if (b == 0) return 0;
        return reserve * 1e18 / b;
    }
}

contract CrossRouter {
    ToyPair public pair;
    ToyToken public token;
    constructor(ToyPair p, ToyToken t) { pair = p; token = t; }
    function swap(uint256 amountIn) external {
        uint256 spot = pair.getSpot();
        uint256 out = amountIn * spot / 1e18;
        require(token.balanceOf(address(pair)) >= out, "liq");
        token.transfer(msg.sender, 0); // placeholder — real drain is world-planned
        amountIn; out;
    }
}
