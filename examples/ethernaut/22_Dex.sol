// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L22 · Dex — 반올림/스팟가격 스왑 반복으로 한 토큰을 전량 소진
interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}
contract Token is IERC20 {
    mapping(address => uint256) public bal;
    mapping(address => mapping(address => uint256)) public allow;
    uint256 public total;
    constructor(uint256 s) { total = s; bal[msg.sender] = s; }
    function transfer(address to, uint256 a) external returns (bool) { bal[msg.sender]-=a; bal[to]+=a; return true; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        if (allow[f][msg.sender] != type(uint256).max) allow[f][msg.sender]-=a;
        bal[f]-=a; bal[to]+=a; return true;
    }
    function approve(address s, uint256 a) external returns (bool) { allow[msg.sender][s]=a; return true; }
    function balanceOf(address who) external view returns (uint256) { return bal[who]; }
}
contract Dex {
    address public token1;
    address public token2;
    constructor() {
        token1 = address(new Token(110));   // dex holds 110, gives 10 to player → 100 each
        token2 = address(new Token(110));
    }
    function setup(address player) external {
        // seed: dex keeps 100/100, player gets 10/10
        Token(token1).transfer(player, 10);
        Token(token2).transfer(player, 10);
    }
    function swap(address from, address to, uint256 amount) external {
        require((from == token1 && to == token2) || (from == token2 && to == token1), "Invalid tokens");
        require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
        uint256 swapAmount = getSwapPrice(from, to, amount);
        IERC20(from).transferFrom(msg.sender, address(this), amount);
        IERC20(to).approve(address(this), swapAmount);
        IERC20(to).transferFrom(address(this), msg.sender, swapAmount);
    }
    function getSwapPrice(address from, address to, uint256 amount) public view returns (uint256) {
        return (amount * IERC20(to).balanceOf(address(this))) / IERC20(from).balanceOf(address(this));
    }
}
