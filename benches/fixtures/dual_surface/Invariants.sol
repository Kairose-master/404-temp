// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IDual {
    function reserve0() external view returns (uint256);
    function reserve1() external view returns (uint256);
}

contract Invariants {
    uint256 constant SEED = 10 ether;

    function ammBacked(address t) public view returns (bool) {
        return t.balance >= IDual(t).reserve0() + IDual(t).reserve1();
    }

    function vaultSolvent(address t) public view returns (bool) {
        return t.balance >= SEED / 2;
    }

    function checkAll(address t) external view returns (bool, string memory) {
        if (!vaultSolvent(t)) return (false, "vaultSolvent");
        if (!ammBacked(t)) return (false, "ammBacked");
        return (true, "");
    }
}
