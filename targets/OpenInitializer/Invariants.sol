// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IAdmin { function admin() external view returns (address); }

contract Invariants {
    /// @notice The admin slot must remain uninitialized until the legitimate
    /// deployer claims it. Any other address seizing it is a takeover.
    function adminUninitialized(address target) public view returns (bool) {
        return IAdmin(target).admin() == address(0);
    }
    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!adminUninitialized(target)) return (false, "adminUninitialized");
        return (true, "");
    }
}
