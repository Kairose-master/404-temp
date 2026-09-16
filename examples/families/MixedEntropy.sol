// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: mixed_entropy.
/// Bug: coin flip is keccak(blockhash, nonce). Pure CoinFlip clone misses
/// the nonce. Exploit reads nonce() and mixes the same way.
/// Invariant: houseSolvent.

contract MixedFlip {
    uint256 public nonce;
    uint256 public wins;

    constructor() payable {}

    function play(bool guess) external payable {
        require(msg.value == 1 ether, "ante");
        uint256 v = uint256(keccak256(abi.encodePacked(blockhash(block.number - 1), nonce)));
        nonce += 1;
        bool side = v % 2 == 0;
        if (guess == side) {
            wins += 1;
            (bool ok,) = msg.sender.call{value: 2 ether}("");
            require(ok);
        }
    }
}
