// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L18 · Magic Number — 10바이트 이하 런타임으로 42 를 반환하는 solver 등록
contract MagicNum {
    address public solver;
    function setSolver(address _solver) public { solver = _solver; }
}
