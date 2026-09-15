// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface Building { function isLastFloor(uint256) external returns (bool); }
contract Elevator {
    bool public top; uint256 public floor;
    function goTo(uint256 _floor) public {
        Building b = Building(msg.sender);
        if (!b.isLastFloor(_floor)) { floor = _floor; top = b.isLastFloor(floor); }
    }
}
