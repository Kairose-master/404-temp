// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IAdmin { function admin() external view returns (address); }

contract Invariants {
    address constant INITIAL_ADMIN = address(0xA11CE);
    function ownerUnchanged(address target) public view returns (bool) {
        return IAdmin(target).admin() == INITIAL_ADMIN;
    }
    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {
        if (!ownerUnchanged(target)) return (false, "ownerUnchanged");
        return (true, "");
    }
}
