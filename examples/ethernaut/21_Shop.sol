// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L21 · Shop — price() 를 두 번 호출하고 그 반환을 신뢰(콜백 불일치)
interface Buyer { function price() external view returns (uint256); }
contract Shop {
    uint256 public price = 100;
    bool public isSold;
    function buy() public {
        Buyer _buyer = Buyer(msg.sender);
        if (_buyer.price() >= price && !isSold) {
            isSold = true;
            price = _buyer.price();
        }
    }
}
