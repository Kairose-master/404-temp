// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L27 · Good Samaritan — 커스텀 에러(NotEnoughBalance)로 전액 인출 유도
interface INotifyable { function notify(uint256 amount) external; }
contract Wallet {
    address public owner;
    Coin public coin;
    error OnlyOwner();
    error NotEnoughBalance();
    modifier onlyOwner() { if (msg.sender != owner) revert OnlyOwner(); _; }
    constructor() { owner = msg.sender; }
    function setCoin(Coin coin_) external onlyOwner { coin = coin_; }
    function donate10(address dest_) external onlyOwner {
        if (coin.balances(address(this)) < 10) { revert NotEnoughBalance(); }
        else { coin.transfer(dest_, 10); }
    }
    function transferRemainder(address dest_) external onlyOwner {
        coin.transfer(dest_, coin.balances(address(this)));
    }
}
contract Coin {
    mapping(address => uint256) public balances;
    error InsufficientBalance(uint256 current, uint256 required);
    constructor(address wallet_) { balances[wallet_] = 10 ** 6; }
    function transfer(address dest_, uint256 amount_) external {
        uint256 currentBalance = balances[msg.sender];
        if (amount_ <= currentBalance) {
            balances[msg.sender] -= amount_;
            balances[dest_] += amount_;
            if (dest_.code.length > 0) { INotifyable(dest_).notify(amount_); }
        } else {
            revert InsufficientBalance(currentBalance, amount_);
        }
    }
}
contract GoodSamaritan {
    Wallet public wallet;
    Coin public coin;
    constructor() {
        wallet = new Wallet();
        coin = new Coin(address(wallet));
        wallet.setCoin(coin);
    }
    function requestDonation() external returns (bool enoughBalance) {
        try wallet.donate10(msg.sender) {
            return true;
        } catch (bytes memory err) {
            if (keccak256(abi.encodeWithSignature("NotEnoughBalance()")) == keccak256(err)) {
                wallet.transferRemainder(msg.sender);
                return false;
            }
        }
    }
}
