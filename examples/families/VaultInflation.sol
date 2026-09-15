// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: vault_inflation (ERC4626 first depositor).
/// Bug: convertToShares uses totalAssets() = token.balanceOf(this). Donate
/// after minting 1 share → next depositor rounds to 0 shares.
/// Invariant: depositorGetsShares — assets in → shares out > 0.

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract InflatingVault {
    IERC20 public token;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    constructor(address t) { token = IERC20(t); }

    function totalAssets() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 s = totalSupply;
        uint256 a = totalAssets();
        if (s == 0 || a == 0) return assets;
        return (assets * s) / a;
    }

    function deposit(uint256 assets) external {
        uint256 sh = convertToShares(assets);
        require(token.transferFrom(msg.sender, address(this), assets));
        balanceOf[msg.sender] += sh;
        totalSupply += sh;
    }

    function redeem(uint256 sh) external {
        uint256 a = totalAssets();
        uint256 out = (sh * a) / totalSupply;
        balanceOf[msg.sender] -= sh;
        totalSupply -= sh;
        require(token.transfer(msg.sender, out));
    }
}
