// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice SAFE counterpart to PredictableLottery. The winning condition is a
/// pre-committed secret hash, NOT any block field. A caller cannot derive the
/// secret from on-chain state within the transaction, so there is no
/// predictable-RNG edge to exploit (commit-reveal pattern).
contract CommitLottery {
    // Hash of the house's secret, fixed at deploy. Preimage is off-chain.
    bytes32 public constant COMMITMENT =
        0x9d3e2b1f4c7a86d05e21bb90f7c4c0a3d8e6f1b2c9a4d7e0f3b6c1a2d5e8f0b7;

    constructor() payable {}

    /// @dev No block.timestamp / prevrandao / blockhash anywhere: the payout
    /// gate is a hash preimage check, unpredictable on-chain.
    function claim(uint256 secret) external {
        require(keccak256(abi.encodePacked(secret)) == COMMITMENT, "wrong secret");
        (bool ok, ) = msg.sender.call{value: 5 ether}("");
        require(ok, "payout failed");
    }

    receive() external payable {}
}
