// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice A logic contract whose admin slot is left uninitialized at
/// construction and can be claimed by ANYONE via an unguarded initializer.
/// Modelled on Ethernaut Motorbike (uninitialized UUPS) and the broad class
/// of proxy contracts deployed without initialize() being locked.
contract OpenInitializer {
    address public admin;   // slot 0 — starts as address(0)

    constructor() payable {}

    /// @dev VULNERABLE: no `initialized` guard, no access control. The first
    /// caller becomes admin.
    function initialize() external {
        admin = msg.sender;
    }

    /// @dev Once admin, sweep the whole balance.
    function sweep(address payable to) external {
        require(msg.sender == admin, "not admin");
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
