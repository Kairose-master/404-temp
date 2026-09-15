// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: make_addr_victim.
/// Bug: Setup did `alice = makeAddr("alice")` then dealt her tokens and
/// never approved. Verifier derives keccak256("alice") as the Foundry
/// private key and sends a real approve — no vm.prank.
/// A random 0x EOA with no derivation is still impossible.
/// Invariant: aliceBalanceSafe.

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

contract PullVault {
    address public victim;
    IERC20 public token;

    constructor(address v, address t) {
        victim = v;
        token = IERC20(t);
    }

    function pull() external {
        uint256 b = token.balanceOf(victim);
        require(token.transferFrom(victim, msg.sender, b));
    }
}

/// Mirrors forge-std StdUtils.makeAddr used in Setup.s.sol.
contract SetupLike {
    function run() external pure returns (address alice) {
        alice = makeAddr("alice");
    }

    function makeAddr(string memory name) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(name)))));
    }
}
