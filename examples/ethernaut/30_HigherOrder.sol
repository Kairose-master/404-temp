// SPDX-License-Identifier: MIT
pragma solidity 0.6.12;
// The Ethernaut L30 · HigherOrder — uint8 파라미터지만 assembly 가 calldata 32바이트 전체를 읽음
contract HigherOrder {
    address public commander;
    uint256 public treasury;
    function registerTreasury(uint8) public {
        assembly { sstore(treasury_slot, calldataload(4)) }
    }
    function claimLeadership() public {
        if (treasury > 255) commander = msg.sender;
        else revert("Only members of the Higher Order can become Commander");
    }
}
