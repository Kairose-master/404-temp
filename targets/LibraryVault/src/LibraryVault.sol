// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Fixed logic module. Its storage layout is deliberately aligned with
/// LibraryVault: slot 0 mirrors `owner` and is never written here, while the
/// counter lives at slot 1. A delegatecall into ping() therefore can only ever
/// touch slot 1, never the vault's owner slot.
contract Logic {
    address private _ownerSlot; // slot 0 — mirrors LibraryVault.owner; never written
    uint256 public pings;       // slot 1
    function ping() external { pings += 1; }
}

/// @notice SAFE counterpart to DelegateVault. It also uses delegatecall, but
/// only ever to an IMMUTABLE module fixed at construction whose storage layout
/// is aligned with this contract. Callers cannot point it at attacker code, and
/// the module never writes the owner slot, so ownership cannot be hijacked.
contract LibraryVault {
    address public owner;             // slot 0
    uint256 public pings;             // slot 1 — bumped by the module
    address public immutable module;  // immutable → not attacker-controlled, no slot

    constructor() payable {
        owner = address(0xA11CE);
        module = address(new Logic());
    }

    /// @dev delegatecall target is the fixed `module`, never a parameter, and
    /// the module only ever writes slot 1 (pings), never slot 0 (owner).
    function run(bytes calldata data) external {
        (bool ok, ) = module.delegatecall(data);
        require(ok, "module call failed");
    }

    receive() external payable {}
}
