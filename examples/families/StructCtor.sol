// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: struct_ctor.
/// Bug: none required — this is the IR hole. constructor(Init memory)
/// used to fail JSON encoding. The vault is still drainable via open
/// withdraw so a hidden set with this ctor still gets a PoC.
/// Invariant: vaultSolvent.

contract ConfiguredVault {
    struct Init {
        address owner;
        uint256 cap;
        address[] tokens;
    }

    address public owner;
    uint256 public cap;
    mapping(address => uint256) public balances;

    constructor(Init memory cfg) payable {
        owner = cfg.owner;
        cap = cfg.cap;
        balances[cfg.owner] += msg.value;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 b = balances[msg.sender];
        require(b > 0);
        (bool ok,) = msg.sender.call{value: b}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
