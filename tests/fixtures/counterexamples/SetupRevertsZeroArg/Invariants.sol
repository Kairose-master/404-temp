// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
interface ITarget { function broken() external view returns (bool); }

contract Invariants {
    function checkAll(address target) external view returns (bool, string memory) {
        if (ITarget(target).broken()) return (false, "unbroken");
        return (true, "");
    }
}
