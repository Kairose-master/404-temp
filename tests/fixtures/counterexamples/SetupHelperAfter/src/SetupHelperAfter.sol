// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Helper {
    function owner() external view returns (address) { return address(this); }
    function setOwner(address) external {}
}
contract SetupHelperAfter {
    address public owner;
    constructor() { owner = address(0xA11CE); }
    function setOwner(address n) external { owner = n; }
}
