// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Valid Track-04 target whose constructor arguments are supplied by Setup.s.sol.
contract SetupOnlyOwner {
    address public owner;

    constructor(address initialOwner) {
        require(initialOwner != address(0), "zero owner");
        owner = initialOwner;
    }

    /// @dev Deliberately vulnerable: anyone can replace the owner.
    function setOwner(address nextOwner) external {
        owner = nextOwner;
    }
}

