// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L17 · Recovery — 무방비 selfdestruct(destroy) 로 잃어버린 컨트랙트 자금 회수/탈취
contract Recovery {
    function generateToken(string memory _name, uint256 _initialSupply) public {
        new SimpleToken(_name, msg.sender, _initialSupply);
    }
}
contract SimpleToken {
    string public name;
    mapping(address => uint256) public balances;
    constructor(string memory _name, address _creator, uint256 _initialSupply) {
        name = _name;
        balances[_creator] = _initialSupply;
    }
    receive() external payable { balances[msg.sender] = msg.value * 10; }
    function transfer(address _to, uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "insufficient");
        balances[msg.sender] -= _amount;
        balances[_to] += _amount;
    }
    // VULNERABLE: no access control on selfdestruct
    function destroy(address payable _to) public { selfdestruct(_to); }
}
