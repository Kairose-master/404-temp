// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L1 · Fallback — become owner then drain
contract Fallback {
    mapping(address => uint256) public contributions;
    address public owner;
    constructor() payable { owner = msg.sender; contributions[msg.sender] = 1000 ether; }
    modifier onlyOwner { require(msg.sender == owner, "not owner"); _; }
    function contribute() public payable {
        require(msg.value < 0.001 ether);
        contributions[msg.sender] += msg.value;
        if (contributions[msg.sender] > contributions[owner]) owner = msg.sender;
    }
    function withdraw() public onlyOwner { (bool ok,)=payable(owner).call{value:address(this).balance}(""); require(ok); }
    receive() external payable { require(msg.value > 0 && contributions[msg.sender] > 0); owner = msg.sender; }
}
