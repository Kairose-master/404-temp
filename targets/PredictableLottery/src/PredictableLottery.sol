// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice A lottery whose "random" winning number is derived entirely from
/// on-chain block fields readable by any caller in the SAME transaction.
/// An attacker computes the identical value and always wins. Modelled on
/// Ethernaut CoinFlip and Capture-the-Ether "Predict the Future".
contract PredictableLottery {
    constructor() payable {}

    /// @dev VULNERABLE: entropy source is block.timestamp/prevrandao/number,
    /// all known to the caller before they pick `guess`.
    function play(uint256 guess) external payable {
        require(msg.value == 1 ether, "ante is 1 ether");
        uint256 lucky = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.prevrandao, block.number))
        ) % 100;
        if (guess == lucky) {
            (bool ok, ) = msg.sender.call{value: 5 ether}("");
            require(ok, "payout failed");
        }
    }

    receive() external payable {}
}
