// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: liquidate_other / no_key_path.
/// Handsel MiniVault shape: permissionless liquidate(user). The victim never
/// signs. Owner-fed price can crash HF (setPrice is onlyOwner — we do not
/// need it if the position is already underwater, or if we ARE the owner).
/// Invariant: healthyPositionsUntouched.

contract MiniVaultLike {
    address public owner;
    uint256 public price; // gUSD per ETH, 1e18
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    constructor(uint256 initialPrice) payable {
        owner = msg.sender;
        price = initialPrice;
        collateral[address(0xA11CE)] = 10 ether;
        debt[address(0xA11CE)] = 8 ether;
    }

    function setPrice(uint256 p) external {
        require(msg.sender == owner, "owner");
        price = p;
    }

    function healthFactor(address user) public view returns (uint256) {
        if (debt[user] == 0) return type(uint256).max;
        return (collateral[user] * price) / debt[user];
    }

    function liquidate(address user, uint256 repayAmount) external payable {
        require(healthFactor(user) < 1e18, "healthy");
        uint256 repaid = repayAmount > debt[user] ? debt[user] : repayAmount;
        debt[user] -= repaid;
        uint256 seize = (repaid * 11) / 10;
        if (seize > collateral[user]) seize = collateral[user];
        collateral[user] -= seize;
        (bool ok,) = msg.sender.call{value: seize}("");
        require(ok);
    }

    receive() external payable { collateral[msg.sender] += msg.value; }
}
