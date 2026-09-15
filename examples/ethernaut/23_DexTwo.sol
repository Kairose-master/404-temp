// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L23 · Dex Two — swap 가 token1/token2 를 강제하지 않아 가짜 토큰으로 드레인
interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}
contract Token is IERC20 {
    mapping(address => uint256) public bal;
    mapping(address => mapping(address => uint256)) public allow;
    constructor(uint256 s) { bal[msg.sender] = s; }
    function transfer(address to, uint256 a) external returns (bool) { bal[msg.sender]-=a; bal[to]+=a; return true; }
    function transferFrom(address f, address to, uint256 a) external returns (bool) {
        if (allow[f][msg.sender] != type(uint256).max) allow[f][msg.sender]-=a;
        bal[f]-=a; bal[to]+=a; return true;
    }
    function approve(address s, uint256 a) external returns (bool) { allow[msg.sender][s]=a; return true; }
    function balanceOf(address who) external view returns (uint256) { return bal[who]; }
}
contract DexTwo {
    address public token1;
    address public token2;
    constructor() { token1 = address(new Token(110)); token2 = address(new Token(110)); }
    function setup(address player) external {
        Token(token1).transfer(player, 10);
        Token(token2).transfer(player, 10);
    }
    // VULNERABLE: no require that from/to are token1/token2
    function swap(address from, address to, uint256 amount) external {
        require(IERC20(from).balanceOf(msg.sender) >= amount, "Not enough to swap");
        uint256 swapAmount = getSwapAmount(from, to, amount);
        IERC20(from).transferFrom(msg.sender, address(this), amount);
        IERC20(to).approve(address(this), swapAmount);
        IERC20(to).transferFrom(address(this), msg.sender, swapAmount);
    }
    function getSwapAmount(address from, address to, uint256 amount) public view returns (uint256) {
        return (amount * IERC20(to).balanceOf(address(this))) / IERC20(from).balanceOf(address(this));
    }
}
