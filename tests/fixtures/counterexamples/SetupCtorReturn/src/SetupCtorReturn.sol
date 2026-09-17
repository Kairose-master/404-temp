// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract SetupCtorReturn {
    address public owner;
    constructor() { owner = address(0xA11CE); }
    function setOwner(address n) external { owner = n; }
}
