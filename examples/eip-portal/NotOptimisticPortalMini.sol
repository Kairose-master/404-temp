// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
// Self-contained repro of the NotOptimisticPortal off-by-one commitment bug.
// RLP/Merkle proof verification is stubbed to "the slot was legitimately sent"
// (sentMessages), and ERC20 is inlined — so the packing/proof plumbing is out of
// the way and the ACTUAL bug is exploitable in-sandbox:
//   _computeMessageSlot loops `i < receivers.length - 1`, so the LAST (receiver,
//   data) pair (and for length-1, everything) is never bound to the message slot,
//   while executeMessage executes ALL of them. Two distinct message sets collide
//   to one slot, so an attacker executes operations the sender never committed.
contract NotOptimisticPortalMini {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    mapping(bytes32 => bool) public sentMessages;      // L2 commitments (sendMessage)
    mapping(bytes32 => bool) public executedMessages;  // replay protection (executeMessage)
    bytes4 constant SEL = 0x3a69197e;                  // onMessageReceived(bytes)

    function _mint(address to, uint256 a) internal { balanceOf[to] += a; totalSupply += a; }
    function _burn(address from, uint256 a) internal { require(balanceOf[from] >= a, "bal"); balanceOf[from] -= a; totalSupply -= a; }

    // BUG: loop stops at length-1 → last element never hashed (length-1 arrays bind nothing)
    function computeMessageSlot(
        address _tokenReceiver, uint256 _amount,
        address[] calldata _messageReceivers, bytes[] calldata _messageDatas, uint256 _salt
    ) public pure returns (bytes32) {
        bytes32 rh; bytes32 dh;
        if (_messageReceivers.length != 0) {
            for (uint i; i < _messageReceivers.length - 1; i++) {
                rh = keccak256(abi.encode(rh, _messageReceivers[i]));
                dh = keccak256(abi.encode(dh, _messageDatas[i]));
            }
        }
        return keccak256(abi.encode(_tokenReceiver, _amount, rh, dh, _salt));
    }

    function sendMessage(uint256 _amount, address[] calldata recv, bytes[] calldata data, uint256 salt) external {
        require(recv.length == data.length, "len");
        for (uint i; i < data.length; i++) require(bytes4(data[i][0:4]) == SEL, "sel");
        bytes32 s = computeMessageSlot(msg.sender, _amount, recv, data, salt);
        require(!sentMessages[s], "sent");
        sentMessages[s] = true;
        _burn(msg.sender, _amount);
    }

    function executeMessage(
        address to, uint256 _amount, address[] calldata recv, bytes[] calldata data, uint256 salt
    ) external {
        bytes32 h = computeMessageSlot(to, _amount, recv, data, salt);
        require(!executedMessages[h], "executed");
        require(recv.length == data.length, "len");
        for (uint i; i < data.length; i++) {
            require(bytes4(data[i][0:4]) == SEL, "entrypoint");
            (bool ok, ) = recv[i].call(data[i]);
            require(ok, "op");
        }
        require(sentMessages[h], "invalid proof");   // STUB: a valid L2 proof == the committed slot
        executedMessages[h] = true;
        if (_amount != 0) _mint(to, _amount);
    }
}
