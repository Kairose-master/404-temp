// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract MirageToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor(address holder, uint256 amount) {
        balanceOf[holder] = amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        require(allowed >= amount, "not approved");
        require(balanceOf[from] >= amount, "insufficient balance");

        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @notice The victim owns tokens but never approves this target.
contract ApprovalMirage {
    address public constant victim = 0x328809Bc894f92807417D2dAD6b7C998c1aFdac6;
    uint256 public constant INITIAL_BALANCE = 100 ether;

    MirageToken public immutable token;

    constructor() {
        token = new MirageToken(victim, INITIAL_BALANCE);
    }

    function drain(address to) external {
        token.transferFrom(victim, to, token.balanceOf(victim));
    }
}

