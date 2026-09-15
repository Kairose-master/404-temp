// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: execute_before_schedule (Climber).
/// Bug: execute() runs the batch first, then checks that schedule() was
/// called. A batch that calls schedule() on itself at the end is valid.
/// Invariant: delayHonored — no batch runs before the delay.

contract Timelock {
    uint64 public delay = 1 days;
    mapping(bytes32 => bool) public operations;
    address public owner;

    constructor() { owner = msg.sender; }

    function schedule(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata data,
        bytes32 salt
    ) external {
        operations[keccak256(abi.encode(targets, values, data, salt))] = true;
    }

    function execute(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata data,
        bytes32 salt
    ) external payable {
        bytes32 id = keccak256(abi.encode(targets, values, data, salt));
        for (uint256 i = 0; i < targets.length; i++) {
            (bool ok,) = targets[i].call{value: values[i]}(data[i]);
            require(ok, "call");
        }
        require(operations[id], "not scheduled");
    }

    function updateDelay(uint64 d) external {
        require(msg.sender == address(this), "self");
        delay = d;
    }
}
