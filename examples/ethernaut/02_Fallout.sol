// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Fallout {
    mapping(address => uint256) allocations;
    address payable public owner;
    function Fal1out() public payable { owner = payable(msg.sender); allocations[owner] = msg.value; }
    function allocate() public payable { allocations[msg.sender] += msg.value; }
    function sendAllocation(address payable a) public { require(allocations[a] > 0); a.transfer(allocations[a]); }
    function collectAllocations() public { require(msg.sender == owner); payable(owner).transfer(address(this).balance); }
}
