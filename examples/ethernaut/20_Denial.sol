// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L20 · Denial — 파트너에게 가스 무제한 call → 가스 소진 그리핑으로 owner 인출 DoS
contract Denial {
    address public partner;
    address public constant owner = address(0xA9E);
    uint256 timeLastWithdrawn;
    mapping(address => uint256) withdrawPartnerBalances;
    function setWithdrawPartner(address _partner) public { partner = _partner; }
    function withdraw() public {
        uint256 amountToSend = address(this).balance / 100;
        (bool ok, ) = partner.call{value: amountToSend}("");   // 가스 전량 전달(취약)
        ok;
        payable(owner).transfer(amountToSend);
        timeLastWithdrawn = block.timestamp;
        withdrawPartnerBalances[partner] += amountToSend;
    }
    receive() external payable {}
}
