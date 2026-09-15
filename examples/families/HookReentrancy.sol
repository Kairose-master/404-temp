// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Family: hook_reentrancy (ERC777 tokensReceived / ERC721 onReceived).
/// Bug: withdraw transfers then zeros. The token notifies the receiver
/// before the zero, so the hook re-enters withdraw.
/// Invariant: vaultSolvent.

interface IERC777Recipient {
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external;
}

contract HookToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 n) external { balanceOf[to] += n; }

    function transfer(address to, uint256 n) external returns (bool) {
        balanceOf[msg.sender] -= n;
        balanceOf[to] += n;
        if (to.code.length > 0) {
            IERC777Recipient(to).tokensReceived(msg.sender, msg.sender, to, n, "", "");
        }
        return true;
    }
}

contract HookVault {
    HookToken public token;
    mapping(address => uint256) public deposits;

    constructor(address t) { token = HookToken(t); }

    function deposit(uint256 n) external {
        deposits[msg.sender] += n;
    }

    function withdraw() external {
        uint256 b = deposits[msg.sender];
        token.transfer(msg.sender, b);
        deposits[msg.sender] = 0;
    }
}
