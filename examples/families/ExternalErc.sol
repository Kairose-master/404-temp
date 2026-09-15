// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: external_erc.
/// Bug: the AMM / token live at well-known addresses. This file only
/// holds IERC20 / IERC4626 / IUniswap — no source for the sibling.
/// Engine uses official ERC-20/2612/4626/3156/UniV2 selectors.
/// Invariant: deskSolvent.

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function permit(address, address, uint256, uint256, uint8, bytes32, bytes32) external;
}

interface IERC4626 {
    function asset() external view returns (address);
    function redeem(uint256, address, address) external returns (uint256);
}

contract ExternalDesk {
    IERC20 public token;
    // Canonical Uniswap V2 router — source not in this compilation unit.
    address public constant ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;

    constructor(address t) { token = IERC20(t); }

    function pool() external view returns (address) { return ROUTER; }

    function pull(address from, uint256 n) external {
        token.transferFrom(from, address(this), n);
    }
}
