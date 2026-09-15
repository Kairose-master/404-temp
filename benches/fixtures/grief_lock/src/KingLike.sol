// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// GRIEF class: push-refund king. Invariant breaks (role locked) but attacker
/// extracts no ETH — profit-only oracles miss this, effect oracles catch it.
contract KingLike {
    address public king;
    uint256 public prize;

    constructor() payable {
        king = msg.sender;
        prize = msg.value;
    }

    function claim() external payable {
        require(msg.value >= prize, "low");
        payable(king).transfer(prize);
        king = msg.sender;
        prize = msg.value;
    }
}
