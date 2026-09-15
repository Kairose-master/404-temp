// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
// The Ethernaut L24 · Puzzle Wallet — 프록시/월렛 스토리지 충돌 + multicall 예치 중복 → admin 탈취
contract PuzzleProxy {
    address public pendingAdmin;   // slot 0  (collides with PuzzleWallet.owner)
    address public admin;          // slot 1  (collides with PuzzleWallet.maxBalance)
    address public implementation; // slot 2
    constructor(address _admin, address _implementation, bytes memory _initData) {
        implementation = _implementation;
        // init() runs FIRST (slot1 still 0 so require(maxBalance==0) passes), then admin is set
        (bool ok, ) = _implementation.delegatecall(_initData);
        require(ok, "init failed");
        admin = _admin;
    }
    modifier onlyAdmin() { require(msg.sender == admin, "Caller is not the admin"); _; }
    function proposeNewAdmin(address _newAdmin) external { pendingAdmin = _newAdmin; }
    function approveNewAdmin(address _expectedAdmin) external onlyAdmin {
        require(pendingAdmin == _expectedAdmin, "pending mismatch");
        admin = pendingAdmin;
    }
    function upgradeTo(address _newImplementation) external onlyAdmin { implementation = _newImplementation; }
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result case 0 { revert(0, returndatasize()) } default { return(0, returndatasize()) }
        }
    }
    receive() external payable {}
}
contract PuzzleWallet {
    address public owner;      // slot 0
    uint256 public maxBalance; // slot 1
    mapping(address => bool) public whitelisted;
    mapping(address => uint256) public balances;
    function init(uint256 _maxBalance) public { require(maxBalance == 0, "Already initialized"); maxBalance = _maxBalance; owner = msg.sender; }
    modifier onlyWhitelisted() { require(whitelisted[msg.sender], "Not whitelisted"); _; }
    function setMaxBalance(uint256 _maxBalance) external onlyWhitelisted {
        require(address(this).balance == 0, "Contract balance is not 0");
        maxBalance = _maxBalance;
    }
    function addToWhitelist(address addr) external { require(msg.sender == owner, "Not the owner"); whitelisted[addr] = true; }
    function deposit() external payable onlyWhitelisted {
        require(address(this).balance <= maxBalance, "Max balance reached");
        balances[msg.sender] += msg.value;
    }
    function execute(address to, uint256 value, bytes calldata data) external onlyWhitelisted {
        require(balances[msg.sender] >= value, "Insufficient balance");
        balances[msg.sender] -= value;
        (bool success, ) = to.call{value: value}(data);
        require(success, "Execution failed");
    }
    function multicall(bytes[] calldata data) external payable onlyWhitelisted {
        bool depositCalled = false;
        for (uint256 i = 0; i < data.length; i++) {
            bytes memory _data = data[i];
            bytes4 selector;
            assembly { selector := mload(add(_data, 32)) }
            if (selector == this.deposit.selector) {
                require(!depositCalled, "Deposit can only be called once");
                depositCalled = true;
            }
            (bool ok, ) = address(this).delegatecall(data[i]);
            require(ok, "Error while delegating call");
        }
    }
}
