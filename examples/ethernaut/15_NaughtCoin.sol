// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L15 · Naught Coin — transfer 는 10년 락업이지만 transferFrom 은 무방비
contract NaughtCoin {
    string public name = "NaughtCoin";
    string public symbol = "0x0";
    uint8 public constant decimals = 18;
    uint256 public constant INITIAL_SUPPLY = 1_000_000 * (10 ** 18);
    address public player;
    uint256 public timeLock = block.timestamp + 10 * 365 days;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address _player) {
        player = _player;
        totalSupply = INITIAL_SUPPLY;
        balanceOf[_player] = INITIAL_SUPPLY;
    }
    modifier lockTokens() {
        if (msg.sender == player) {
            require(block.timestamp > timeLock, "tokens locked for 10 years");
        }
        _;
    }
    function transfer(address to, uint256 value) public lockTokens returns (bool) {
        require(balanceOf[msg.sender] >= value, "insufficient");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        return true;
    }
    function approve(address spender, uint256 value) public returns (bool) {
        allowance[msg.sender][spender] = value;
        return true;
    }
    // VULNERABLE: no lockTokens modifier — player can move tokens via approve+transferFrom
    function transferFrom(address from, address to, uint256 value) public returns (bool) {
        require(allowance[from][msg.sender] >= value, "allowance");
        require(balanceOf[from] >= value, "insufficient");
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        return true;
    }
}
