// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: commit_reveal.
/// Bug: reveal() requires a later *block*, not a later call. One run() is
/// the same block unless HEVM roll / py-evm mine. Prize is paid on a
/// matching reveal.
/// Invariant: prizeUnclaimed until a legal reveal.

contract CommitReveal {
    mapping(address => bytes32) public commits;
    mapping(address => uint256) public commitBlock;
    uint256 public delay = 1;
    bool public paid;

    constructor() payable {}

    function commit(bytes32 h) external {
        commits[msg.sender] = h;
        commitBlock[msg.sender] = block.number;
    }

    function reveal(uint256 secret) external {
        require(block.number > commitBlock[msg.sender] + delay, "wait");
        require(commits[msg.sender] == keccak256(abi.encodePacked(secret, msg.sender)), "h");
        paid = true;
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        require(ok);
    }
}
