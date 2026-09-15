// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPair {
    function reserve0() external view returns (uint256);
    function reserve1() external view returns (uint256);
}

contract Invariants {
    function checkAll(address t) external view returns (bool, string memory) {
        // Solvency: reserves fit in the contract. An arb swap preserves this.
        uint256 r = IPair(t).reserve0() + IPair(t).reserve1();
        if (t.balance < r) return (false, "reservesBacked");
        if (IPair(t).reserve0() == 0 || IPair(t).reserve1() == 0) return (false, "alive");
        return (true, "");
    }
}
