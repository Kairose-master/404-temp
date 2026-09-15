// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: windowed_twap (Uniswap V3 Observation[]).
/// Bug: observations are a time window. Skew, warp 30 minutes, then borrow.
/// Invariant: protocolSolvent after a windowed borrow.

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract WindowTwapDesk {
    struct Observation {
        uint32 ts;
        uint224 c;
    }

    Observation[] public observations;
    uint32 public period = 30 minutes;
    IERC20 public token;
    uint256 public reserveEth;
    uint256 public debt;

    constructor(address t) payable {
        token = IERC20(t);
        reserveEth = msg.value;
        observations.push(Observation(uint32(block.timestamp), 0));
    }

    function pool() external view returns (address) { return address(this); }

    function observe(uint32[] calldata secondsAgos) external view returns (int56[] memory t) {
        t = new int56[](secondsAgos.length);
        if (observations.length > 0) {
            t[0] = int56(uint56(observations[observations.length - 1].c));
        }
    }

    function update() external {
        observations.push(Observation(uint32(block.timestamp), uint224(reserveEth)));
    }

    function swap() external payable { reserveEth += msg.value; }

    function borrow(uint256 n) external payable {
        require(observations.length > 1, "window");
        debt += n;
        require(token.transfer(msg.sender, n));
    }
}
