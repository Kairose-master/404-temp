// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice SAFE counterpart to OpenInitializer. The initializer is locked with
/// an `initialized` flag and is invoked in the constructor by the deployer, so
/// no later caller can re-run it to seize admin.
contract GuardedInitializer {
    address public admin;      // slot 0
    bool private initialized;  // slot 1

    constructor() payable {
        _init(address(0xA11CE));
    }

    function initialize(address who) external {
        _init(who);
    }

    function _init(address who) internal {
        require(!initialized, "already initialized");
        initialized = true;
        admin = who;
    }

    function sweep(address payable to) external {
        require(msg.sender == admin, "not admin");
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }

    receive() external payable {}
}
