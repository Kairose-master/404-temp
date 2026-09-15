// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: sig_replay.
/// Bug: claim() ecrecover's a stored digest with no nonce/deadline.
/// The same (v,r,s) pays every caller, every time.
/// Invariant: oneClaimPerSig.

contract ReplayDesk {
    address public signer;
    bytes32 public digest;
    bytes32 public r;
    bytes32 public s;
    uint8 public v;

    constructor() payable {
        signer = msg.sender;
        digest = keccak256("pay");
    }

    function setSig(uint8 vv, bytes32 rr, bytes32 ss) external {
        require(msg.sender == signer, "sig");
        v = vv;
        r = rr;
        s = ss;
    }

    function claim(bytes32 hash, uint8 vv, bytes32 rr, bytes32 ss) external {
        address who = ecrecover(hash, vv, rr, ss);
        require(who == signer && who != address(0), "bad");
        (bool ok,) = msg.sender.call{value: 1 ether}("");
        require(ok);
    }
}
