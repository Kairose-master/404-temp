// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Reentrance {
    mapping(address => uint256) public balances;
    constructor() payable {}
    function donate(address to) public payable { balances[to] += msg.value; }
    function withdraw(uint256 amount) public {
        if (balances[msg.sender] >= amount) {
            (bool ok,) = msg.sender.call{value: amount}(""); require(ok);
            balances[msg.sender] -= amount;
        }
    }
    receive() external payable {}
}
