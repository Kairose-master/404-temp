// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
// Self-contained repro of the EIP-7702 receiver-callback reentrancy (Pectra).
// The free EOA mint path is guarded only by tx.origin == msg.sender and runs an
// ERC721 receiver callback BEFORE committing state, with no reentrancy guard.
// Pre-7702 an EOA has no code so the callback is inert; under EIP-7702 a
// code-bearing EOA satisfies the gate AND runs code, re-entering the mint while
// balanceOf is still 0 — minting past the "one per address" limit.
//
// TRUST404 proves this DYNAMICALLY: it signs an EIP-7702 authorization and sends
// a type-4 SetCode transaction on the py-evm prague fork, then observes
// balanceOf(EOA) > 1.  (See agent/audit.py — strategy eip7702-reentrancy.)
contract UniqueNFT7702 {
    mapping(address => uint256) public balanceOf;
    uint256 public tokenId;

    function mintNFTEOA() external {
        require(tx.origin == msg.sender, "not an EOA");   // 7702 로 무력화되는 게이트
        require(balanceOf[msg.sender] == 0, "only one unique NFT allowed");
        uint256 id = tokenId++;
        // receiver callback BEFORE the state commit (checks-effects-interactions 위반)
        if (msg.sender.code.length > 0) {
            (bool ok, bytes memory ret) = msg.sender.call(
                abi.encodeWithSignature("onERC721Received(address,address,uint256,bytes)",
                    address(0), address(0), id, "")
            );
            require(ok && abi.decode(ret, (bytes4)) == 0x150b7a02, "receiver");
        }
        balanceOf[msg.sender] += 1;                       // effect after interaction
    }
}
