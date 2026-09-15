// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L25 · Motorbike — 구현(Engine) 자체가 초기화되지 않아 누구나 initialize() 로
// upgrader 를 선점(그 뒤 upgradeToAndCall 로 임의 코드/파괴). 초기화 탈취를 증명한다.
contract Engine {
    address public upgrader;
    uint256 public horsePower;
    bool private initialized;   // 구현 컨트랙트에서는 절대 세팅되지 않는다(프록시만 초기화)
    function initialize() external {
        require(!initialized, "already initialized");
        initialized = true;
        horsePower = 1000;
        upgrader = msg.sender;
    }
    function upgradeToAndCall(address newImplementation, bytes calldata data) external {
        require(msg.sender == upgrader, "not upgrader");
        (bool ok, ) = newImplementation.delegatecall(data);
        require(ok, "upgrade failed");
    }
}
