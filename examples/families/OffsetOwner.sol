// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: owner_not_slot0.
/// Bug: deposits occupies slot 0; owner is slot 1. A module that writes
/// slot 0 misses. Pwn must pad one uint256 then write owner.
/// Invariant: ownerUnchanged.

contract OffsetVault {
    uint256 public deposits;   // slot 0
    address public owner;      // slot 1

    constructor() payable {
        owner = address(0xA11CE);
        deposits = msg.value;
    }

    function execute(address module, bytes calldata data) external {
        (bool ok,) = module.delegatecall(data);
        require(ok);
    }

    function sweep() external {
        require(msg.sender == owner, "owner");
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        require(ok);
    }
}
