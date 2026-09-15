// SPDX-License-Identifier: MIT
pragma solidity ^0.5.0;
// The Ethernaut L19 · Alien Codex — 동적배열 length 언더플로 → 임의 스토리지 쓰기 → owner 탈취
contract Ownable {
    address public owner;
    constructor() internal { owner = msg.sender; }
}
contract AlienCodex is Ownable {
    bool public contact;
    bytes32[] public codex;
    modifier contacted() { assert(contact); _; }
    function makeContact() public { contact = true; }
    function record(bytes32 _content) contacted public { codex.push(_content); }
    function retract() contacted public { codex.length--; }
    function revise(uint256 i, bytes32 _content) contacted public { codex[i] = _content; }
}
