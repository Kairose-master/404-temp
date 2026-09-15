// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: twap_as_spot (Puppet v1).
/// Bug: consult()/twap() is the current reserve ratio. Skew the pool in
/// the same run(), then borrow against the fake price.
/// Invariant: protocolSolvent — collateral covers debt after a borrow.

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract SpotTwapDesk {
    IERC20 public token;
    uint256 public reserveEth;
    uint256 public reserveTok;
    uint256 public debt;

    constructor(address t) payable {
        token = IERC20(t);
        reserveEth = msg.value;
        reserveTok = 1000 ether;
    }

    function pool() external view returns (address) { return address(this); }
    function pair() external view returns (address) { return address(this); }

    function consult() public view returns (uint256) {
        if (reserveTok == 0) return 0;
        return (reserveEth * 1e18) / reserveTok;
    }

    function twap() external view returns (uint256) { return consult(); }

    function swap() external payable {
        reserveEth += msg.value;
    }

    function borrow(uint256 n) external payable {
        uint256 price = consult();
        require(msg.value * price >= n * 1e18, "col");
        debt += n;
        reserveTok -= n;
        require(token.transfer(msg.sender, n));
    }
}
