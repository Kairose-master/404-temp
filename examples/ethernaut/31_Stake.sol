// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L31 · Stake — WETH 이전 실패해도 UserStake 를 올려주는 회계 버그 → 실 ETH 인출
contract Stake {
    uint256 public totalStaked;
    mapping(address => uint256) public UserStake;
    mapping(address => bool) public Stakers;
    address public WETH;

    constructor(address _weth) payable {
        totalStaked = msg.value;
        WETH = _weth;
    }
    function StakeETH() public payable {
        require(msg.value > 0.001 ether, "Don't be cheap");
        totalStaked += msg.value;
        UserStake[msg.sender] += msg.value;
        Stakers[msg.sender] = true;
    }
    function StakeWETH(uint256 amount) public returns (bool) {
        require(amount > 0.001 ether, "Don't be cheap");
        (, bytes memory allowance) = WETH.call(abi.encodeWithSelector(0xdd62ed3e, msg.sender, address(this)));
        require(bytesToUint(allowance) >= amount, "How am I moving the funds honey?");
        (bool transfered, ) = WETH.call(abi.encodeWithSelector(0x23b872dd, msg.sender, address(this), amount));
        UserStake[msg.sender] += amount;          // BUG: increments regardless of transfer success
        if (transfered) Stakers[msg.sender] = true;
        totalStaked += amount;
        return transfered;
    }
    function Unstake(uint256 amount) public returns (bool) {
        require(UserStake[msg.sender] >= amount, "Don't be greedy");
        UserStake[msg.sender] -= amount;
        totalStaked -= amount;
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "Failed Sending Money Boss");
        return success;
    }
    function bytesToUint(bytes memory data) internal pure returns (uint256) {
        require(data.length >= 32, "Data length must be at least 32 bytes");
        uint256 result;
        assembly { result := mload(add(data, 0x20)) }
        return result;
    }
    receive() external payable {}
}
