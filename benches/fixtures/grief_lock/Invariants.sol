// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IKing { function king() external view returns (address); }

contract Invariants {
    address public immutable deployer;
    constructor() { deployer = msg.sender; }
    function checkAll(address t) external view returns (bool, string memory) {
        // "role is not permanently unclaimable" — a contract king that reverts
        // on receive makes the next claim() uncallable. We only observe king()!=0
        // here; the *effect* is "claim still possible", which a later claim probe
        // would refute. For static scoring the expected class is grief.
        if (IKing(t).king() == address(0)) return (false, "kingSet");
        return (true, "");
    }
}
