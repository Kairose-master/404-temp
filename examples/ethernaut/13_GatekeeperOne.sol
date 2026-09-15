// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L13 · Gatekeeper One — gasleft()%8191==0 브루트포스 + tx.origin 키
contract GatekeeperOne {
    address public entrant;
    modifier gateOne() { require(msg.sender != tx.origin); _; }
    modifier gateTwo() { require(gasleft() % 8191 == 0); _; }
    modifier gateThree(bytes8 _gateKey) {
        require(uint32(uint64(_gateKey)) == uint16(uint64(_gateKey)), "flaw one");
        require(uint32(uint64(_gateKey)) != uint64(_gateKey), "flaw two");
        require(uint32(uint64(_gateKey)) == uint16(uint160(tx.origin)), "flaw three");
        _;
    }
    function enter(bytes8 _gateKey) public gateOne gateTwo gateThree(_gateKey) returns (bool) {
        entrant = tx.origin;
        return true;
    }
}
