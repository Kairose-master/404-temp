// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

// Minimal, vendored forge-std shim for TRUST404 Track04.
// The participant harness imports { Test, console2 } from "forge-std/Test.sol".
// Vendoring this small subset lets `forge test` compile and run WITHOUT downloading
// the full forge-std library (useful in network-restricted sandboxes). It declares
// only the cheatcodes the harness references; forge injects the real cheatcode
// implementations at the fixed VM address at test time.
interface Vm {
    function roll(uint256) external;
    function warp(uint256) external;
    function deal(address, uint256) external;
    function deployCode(string calldata) external returns (address);
    function deployCode(string calldata, uint256) external returns (address);
    function parseJsonString(string calldata, string calldata) external returns (string memory);
    function parseJsonUint(string calldata, string calldata) external returns (uint256);
    function keyExistsJson(string calldata, string calldata) external returns (bool);
    function expectRevert() external;
    function readFile(string calldata) external view returns (string memory);
}

library console2 {
    function log(string memory) internal pure {}
    function log(string memory, string memory) internal pure {}
    function log(string memory, uint256) internal pure {}
    function log(string memory, address) internal pure {}
}

abstract contract Test {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    // minimal assertion helpers (revert on failure -> forge marks test failed)
    function assertTrue(bool c) internal pure { require(c, "assertTrue"); }
    function assertTrue(bool c, string memory m) internal pure { require(c, m); }
    function assertFalse(bool c) internal pure { require(!c, "assertFalse"); }
    function assertFalse(bool c, string memory m) internal pure { require(!c, m); }
    function assertEq(string memory a, string memory b) internal pure {
        require(keccak256(bytes(a)) == keccak256(bytes(b)), "assertEq(string)");
    }
    function assertEq(string memory a, string memory b, string memory m) internal pure {
        require(keccak256(bytes(a)) == keccak256(bytes(b)), m);
    }

    // forge-std compatibility: logging is an event, not a same-named function.
    // Declaring both makes solc reject every harness compilation (error 2333).
    event log_named_string(string key, string val);
}
