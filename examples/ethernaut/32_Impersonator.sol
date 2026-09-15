// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L32 · Impersonator — ECDSA 서명 가변성(malleability): usedSignatures 가 정확한
// (v,r,s) 만 소모 처리해, 같은 서명자를 복구하는 대칭 서명(v^1, r, n-s)으로 controller 를 탈취.
contract ECLocker {
    uint256 public immutable lockId;
    bytes32 public immutable msgHash;
    address public controller;
    mapping(bytes32 => bool) public usedSignatures;

    error InvalidController();
    error SignatureAlreadyUsed();

    constructor(uint256 _lockId, bytes32 _msgHash, uint8 v, bytes32 r, bytes32 s) {
        lockId = _lockId;
        msgHash = _msgHash;
        controller = ecrecover(_msgHash, v, r, s);
    }
    modifier onlyController(uint8 v, bytes32 r, bytes32 s) {
        if (ecrecover(msgHash, v, r, s) != controller) revert InvalidController();
        bytes32 sigHash = keccak256(abi.encode(v, r, s));
        if (usedSignatures[sigHash]) revert SignatureAlreadyUsed();
        usedSignatures[sigHash] = true;
        _;
    }
    function changeController(uint8 v, bytes32 r, bytes32 s, address newController)
        external onlyController(v, r, s)
    {
        controller = newController;
    }
}
