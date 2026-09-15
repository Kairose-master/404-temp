// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// INTENDED_PATH class — the unsolved frontier.
///
/// A constant-product pair that *anyone* can arb. Swapping is the protocol.
/// Attacker profit > 0, every invariant still holds. Profit-only agents
/// (Verite / SCONE / A1 revenue) report this as an exploit. It is not.
/// Distinguishing this from a true oracle-manipulation theft requires a
/// human (or retrieved) spec of *intended* extraction. See docs/FRONTIER.md §1.
contract SpotPair {
    uint256 public reserve0;
    uint256 public reserve1;

    constructor() payable {
        reserve0 = msg.value / 2;
        reserve1 = msg.value - reserve0;
    }

    function getPrice() public view returns (uint256) {
        return (reserve1 * 1e18) / reserve0;
    }

    function swap0to1() external payable {
        require(msg.value > 0, "zero");
        uint256 out = (msg.value * reserve1) / (reserve0 + msg.value);
        reserve0 += msg.value;
        reserve1 -= out;
        (bool ok, ) = msg.sender.call{value: out}("");
        require(ok, "pay");
    }
}
