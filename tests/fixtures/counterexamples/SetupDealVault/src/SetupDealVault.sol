// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract SetupDealVault {
    constructor() payable {}
    function sweep() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
