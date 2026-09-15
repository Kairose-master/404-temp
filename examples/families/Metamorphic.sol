// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: metamorphic (CREATE2 + selfdestruct).
/// Bug: destroy() wipes runtime, deploy() plants new code at the same
/// address. One run() can replace a "safe" implementation.
/// Invariant: runtimeHashStable.

contract MetamorphicFactory {
    event Deployed(address);

    function deploy(bytes32 salt, bytes memory code) external payable returns (address a) {
        assembly {
            a := create2(callvalue(), add(code, 0x20), mload(code), salt)
        }
        require(a != address(0), "create2");
        emit Deployed(a);
    }

    function destroy() external {
        selfdestruct(payable(msg.sender));
    }
}
