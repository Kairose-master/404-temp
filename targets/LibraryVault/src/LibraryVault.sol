// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Fixed logic module — no function can write the vault's owner slot.
contract Logic {
    uint256 public pings; // slot 0 here, but only ever bumped, never owner
    function ping() external { pings += 1; }
}

/// @notice SAFE counterpart to DelegateVault. It also uses delegatecall, but
/// only ever to an IMMUTABLE module fixed at construction. Callers cannot
/// point it at attacker code, so ownership cannot be hijacked.
contract LibraryVault {
    address public owner;             // slot 0
    address public immutable module;  // immutable → not attacker-controlled

    constructor() payable {
        owner = address(0xA11CE);
        module = address(new Logic());
    }

    /// @dev delegatecall target is the fixed `module`, never a parameter.
    function run(bytes calldata data) external {
        (bool ok, ) = module.delegatecall(data);
        require(ok, "module call failed");
    }

    receive() external payable {}
}
