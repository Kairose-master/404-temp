// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault {
    function balances(address) external view returns (uint256);
}

contract Invariants {
    function checkAll(address t) external view returns (bool, string memory) {
        if (t.balance < 1) return (false, "vaultSolvent");
        return (true, "");
    }
}
