// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice A "modular" vault that lets callers plug in behaviour by
/// delegatecalling an arbitrary module address they supply. Because the
/// module runs in THIS contract's storage context, a malicious module can
/// overwrite `owner` (storage slot 0). Modelled on Ethernaut Delegation /
/// Preservation and the Parity multisig delegatecall class.
contract DelegateVault {
    address public owner;      // slot 0
    uint256 public deposits;   // slot 1

    constructor() payable {
        owner = address(0xA11CE);
    }

    /// @dev VULNERABLE: module address is fully attacker-controlled and is
    /// invoked with delegatecall, so its code mutates DelegateVault storage.
    function execute(address module, bytes calldata data) external {
        (bool ok, ) = module.delegatecall(data);
        require(ok, "module call failed");
    }

    function deposit() external payable {
        deposits += msg.value;
    }

    receive() external payable {}
}
