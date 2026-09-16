// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// HostileDesk — one protocol, hostile layout, two real bugs.
///
/// DualSurface was labels. This one is *shape*.
///
/// Slot 0 is not owner. A Pwn that writes slot 0 hits `totalDeposits`
/// and the treasury stays. The lottery is keccak(blockhash, nonce, salt);
/// a CoinFlip clone that only copies blockhash always loses.
///
///   execute(module, data)   THEFT   unguarded delegatecall. Pwn must
///                                   pad two uint256 then write owner.
///   play(guess)             THEFT   mixed entropy. Read nonce() and
///                                   salt() in the same tx, then guess.
///   deposit / withdraw      safe    CEI respected. Not the bug.
///
/// Invariants:
///   ownerUnchanged    owner == admin (immutable, not a slot)
///   houseAlive        seed float still there
///
/// Seed: constructor msg.value (default 10 ether) is the house.

contract HostileDesk {
    uint256 public totalDeposits; // slot 0
    uint256 public salt;          // slot 1
    address public owner;         // slot 2
    uint256 public nonce;         // slot 3
    address public immutable admin;
    mapping(address => uint256) public deposits;

    constructor() payable {
        require(msg.value >= 2 ether, "seed");
        owner = msg.sender;
        admin = msg.sender;
        salt = uint256(keccak256(abi.encodePacked(block.timestamp, address(this))));
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw() external {
        uint256 b = deposits[msg.sender];
        require(b > 0, "empty");
        deposits[msg.sender] = 0;
        totalDeposits -= b;
        (bool ok,) = msg.sender.call{value: b}("");
        require(ok);
    }

    /// @notice "Upgrade helper". No onlyOwner. The layout bug.
    function execute(address module, bytes calldata data) external {
        (bool ok,) = module.delegatecall(data);
        require(ok);
    }

    function sweep() external {
        require(msg.sender == owner, "owner");
        (bool ok,) = msg.sender.call{value: address(this).balance}("");
        require(ok);
    }

    /// @notice Looks like a fair coin. It is not.
    function play(bool guess) external payable {
        require(msg.value == 1 ether, "ante");
        uint256 v = uint256(keccak256(abi.encodePacked(
            blockhash(block.number - 1), nonce, salt
        )));
        nonce += 1;
        if (guess == (v % 2 == 0)) {
            (bool ok,) = msg.sender.call{value: 2 ether}("");
            require(ok);
        }
    }
}
