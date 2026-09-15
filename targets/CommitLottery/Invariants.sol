// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Invariants {
    uint256 constant SEED = 20 ether;
    function houseSolvent(address target) public view returns (bool) {
        return target.balance >= SEED;
    }
    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!houseSolvent(target)) return (false, "houseSolvent");
        return (true, "");
    }
}
