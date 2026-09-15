// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// THEFT class: CEI-broken vault. Invariant breaks AND attacker extracts ETH.
contract ProfitVault {
    mapping(address => uint256) public balances;

    constructor() payable {
        balances[msg.sender] += msg.value;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 b = balances[msg.sender];
        require(b > 0, "zero");
        (bool ok, ) = msg.sender.call{value: b}("");
        require(ok, "send");
        balances[msg.sender] = 0;
    }
}
