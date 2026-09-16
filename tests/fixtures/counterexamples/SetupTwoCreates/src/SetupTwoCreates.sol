// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract Dummy {
    function owner() external pure returns (address) { return address(0xA11CE); }
    function setOwner(address) external {}
}
contract SetupTwoCreates {
    address public owner;
    constructor() { owner = address(0xA11CE); }
    function setOwner(address n) external { owner = n; }
}
