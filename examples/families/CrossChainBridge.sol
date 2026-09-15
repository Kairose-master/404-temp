// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: cross_chain_bridge.
/// Bug: lzReceive is unpermissioned — any caller is "the other chain".
/// Same-EVM mock of LayerZero / OP messenger. Not two real chains.
/// Invariant: tokenHeld — only a real messenger may mint/release.

interface IERC20 {
    function approve(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract MiniMessenger {
    IERC20 public token;
    address public trustedRemote;

    constructor(address t) { token = IERC20(t); }

    function lzReceive(uint16 srcChain, bytes memory src, uint64 nonce, bytes memory payload)
        external
    {
        srcChain;
        src;
        nonce;
        (bool ok,) = address(this).call(payload);
        require(ok, "payload");
    }

    function relayMessage(address target, bytes memory payload) external {
        (bool ok,) = target.call(payload);
        require(ok, "relay");
    }

    function approve(address s, uint256 n) external {
        token.approve(s, n);
    }
}
