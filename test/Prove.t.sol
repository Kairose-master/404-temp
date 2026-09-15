// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// TRUST404 Track04 — run the harness _prove() pipeline against every public target
// with the agent-generated Exploit.sol. Vulnerable 4 must be PROVEN, safe 2 must
// stay NOT PROVEN. Run with:  forge test -vv
import {Harness} from "../harness/src/Harness.sol";

import {ReentrantVault} from "../targets/ReentrantVault/src/ReentrantVault.sol";
import {Invariants as InvReentrant} from "../targets/ReentrantVault/Invariants.sol";
import {Exploit as ExpReentrant} from "../exploits/ReentrantVault/Exploit.sol";

import {OpenVault} from "../targets/OpenVault/src/OpenVault.sol";
import {Invariants as InvOpen} from "../targets/OpenVault/Invariants.sol";
import {Exploit as ExpOpen} from "../exploits/OpenVault/Exploit.sol";

import {BadAccounting} from "../targets/BadAccounting/src/BadAccounting.sol";
import {Invariants as InvBad} from "../targets/BadAccounting/Invariants.sol";
import {Exploit as ExpBad} from "../exploits/BadAccounting/Exploit.sol";

import {NaiveOracle} from "../targets/NaiveOracle/src/NaiveOracle.sol";
import {Invariants as InvOracle} from "../targets/NaiveOracle/Invariants.sol";
import {Exploit as ExpOracle} from "../exploits/NaiveOracle/Exploit.sol";

import {SafeVault} from "../targets/SafeVault/src/SafeVault.sol";
import {Invariants as InvSafe} from "../targets/SafeVault/Invariants.sol";

import {BoundedOwner} from "../targets/BoundedOwner/src/BoundedOwner.sol";
import {Invariants as InvBounded} from "../targets/BoundedOwner/Invariants.sol";

// ── wargame-derived families (Ethernaut / Damn Vulnerable DeFi / Capture the Ether) ──
import {DelegateVault} from "../targets/DelegateVault/src/DelegateVault.sol";
import {Invariants as InvDelegate} from "../targets/DelegateVault/Invariants.sol";
import {Exploit as ExpDelegate} from "../exploits/DelegateVault/Exploit.sol";

import {PredictableLottery} from "../targets/PredictableLottery/src/PredictableLottery.sol";
import {Invariants as InvLottery} from "../targets/PredictableLottery/Invariants.sol";
import {Exploit as ExpLottery} from "../exploits/PredictableLottery/Exploit.sol";

import {OpenInitializer} from "../targets/OpenInitializer/src/OpenInitializer.sol";
import {Invariants as InvInit} from "../targets/OpenInitializer/Invariants.sol";
import {Exploit as ExpInit} from "../exploits/OpenInitializer/Exploit.sol";

import {LibraryVault} from "../targets/LibraryVault/src/LibraryVault.sol";
import {Invariants as InvLibrary} from "../targets/LibraryVault/Invariants.sol";

import {CommitLottery} from "../targets/CommitLottery/src/CommitLottery.sol";
import {Invariants as InvCommit} from "../targets/CommitLottery/Invariants.sol";

import {GuardedInitializer} from "../targets/GuardedInitializer/src/GuardedInitializer.sol";
import {Invariants as InvGuarded} from "../targets/GuardedInitializer/Invariants.sol";

contract ProveTest is Harness {
    uint256 constant BN = 21_000_000;
    uint256 constant TS = 1_735_689_600;
    uint256 constant FUND = 10 ether;   // DEFAULT_EXPLOIT_FUNDING_WEI
    uint256 constant SEED = 10 ether;   // deploy.value_wei for the vault targets
    address constant A11CE = address(0xA11CE);

    receive() external payable {}       // reentrancy drain sends ETH here

    // ── vulnerable: must be PROVEN ──────────────────────────────────────────
    function test_ReentrantVault_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        ReentrantVault t = new ReentrantVault{value: SEED}();
        (bool proven, string memory v) =
            _prove(address(t), address(new InvReentrant()), address(new ExpReentrant()), BN, TS, FUND);
        assertTrue(proven, "ReentrantVault should be PROVEN");
        assertEq(v, "vaultSolvent");
    }

    function test_OpenVault_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        OpenVault t = new OpenVault{value: SEED}(A11CE);
        (bool proven, string memory v) =
            _prove(address(t), address(new InvOpen()), address(new ExpOpen()), BN, TS, FUND);
        assertTrue(proven, "OpenVault should be PROVEN");
        assertEq(v, "ownerUnchanged");
    }

    function test_BadAccounting_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        BadAccounting t = new BadAccounting{value: SEED}();
        (bool proven, string memory v) =
            _prove(address(t), address(new InvBad()), address(new ExpBad()), BN, TS, FUND);
        assertTrue(proven, "BadAccounting should be PROVEN");
        assertEq(v, "vaultSolvent");
    }

    function test_NaiveOracle_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        NaiveOracle t = new NaiveOracle();   // value_wei = 0
        (bool proven, string memory v) =
            _prove(address(t), address(new InvOracle()), address(new ExpOracle()), BN, TS, FUND);
        assertTrue(proven, "NaiveOracle should be PROVEN");
        assertEq(v, "protocolSolvent");
    }

    // ── safe: must stay NOT PROVEN (no false positive) ──────────────────────
    function test_SafeVault_NOT_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        SafeVault t = new SafeVault{value: SEED}();
        (bool proven,) =
            _prove(address(t), address(new InvSafe()), address(new SafeVaultAttempt()), BN, TS, FUND);
        assertFalse(proven, "SafeVault must NOT be proven");
    }

    function test_BoundedOwner_NOT_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        BoundedOwner t = new BoundedOwner{value: SEED}(A11CE);
        (bool proven,) =
            _prove(address(t), address(new InvBounded()), address(new BoundedOwnerAttempt()), BN, TS, FUND);
        assertFalse(proven, "BoundedOwner must NOT be proven");
    }

    // ── wargame families: vulnerable → must be PROVEN ───────────────────────
    function test_DelegateVault_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        DelegateVault t = new DelegateVault{value: 1 ether}();
        (bool proven, string memory v) =
            _prove(address(t), address(new InvDelegate()), address(new ExpDelegate()), BN, TS, FUND);
        assertTrue(proven, "DelegateVault should be PROVEN");
        assertEq(v, "ownerUnchanged");
    }

    function test_PredictableLottery_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        PredictableLottery t = new PredictableLottery{value: 20 ether}();
        (bool proven, string memory v) =
            _prove(address(t), address(new InvLottery()), address(new ExpLottery()), BN, TS, FUND);
        assertTrue(proven, "PredictableLottery should be PROVEN");
        assertEq(v, "houseSolvent");
    }

    function test_OpenInitializer_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        OpenInitializer t = new OpenInitializer{value: 1 ether}();
        (bool proven, string memory v) =
            _prove(address(t), address(new InvInit()), address(new ExpInit()), BN, TS, FUND);
        assertTrue(proven, "OpenInitializer should be PROVEN");
        assertEq(v, "adminUninitialized");
    }

    // ── wargame families: safe counterpart → must stay NOT PROVEN ───────────
    function test_LibraryVault_NOT_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        LibraryVault t = new LibraryVault{value: 1 ether}();
        (bool proven,) =
            _prove(address(t), address(new InvLibrary()), address(new LibraryVaultAttempt()), BN, TS, FUND);
        assertFalse(proven, "LibraryVault must NOT be proven");
    }

    function test_CommitLottery_NOT_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        CommitLottery t = new CommitLottery{value: 20 ether}();
        (bool proven,) =
            _prove(address(t), address(new InvCommit()), address(new CommitLotteryAttempt()), BN, TS, FUND);
        assertFalse(proven, "CommitLottery must NOT be proven");
    }

    function test_GuardedInitializer_NOT_PROVEN() public {
        vm.deal(address(this), 1000 ether);
        GuardedInitializer t = new GuardedInitializer{value: 1 ether}();
        (bool proven,) =
            _prove(address(t), address(new InvGuarded()), address(new GuardedInitializerAttempt()), BN, TS, FUND);
        assertFalse(proven, "GuardedInitializer must NOT be proven");
    }
}

// Best-effort attacks the agent would attempt on the safe targets; they must fail.
interface ISafeVault { function deposit() external payable; function withdraw() external; }
contract SafeVaultAttempt {
    ISafeVault t; uint256 u;
    function run(address a) external payable { t = ISafeVault(a); u = 1 ether; t.deposit{value: u}(); t.withdraw(); }
    receive() external payable { if (address(t).balance >= u) t.withdraw(); }
}

interface IBounded { function propose(address, uint256) external returns (uint256); function execute(uint256) external; }
contract BoundedOwnerAttempt {
    function run(address a) external payable {
        try IBounded(a).propose(address(this), address(a).balance) returns (uint256 id) {
            IBounded(a).execute(id);
        } catch {}
    }
    receive() external payable {}
}

// Best-effort attacks the agent would attempt on the new safe targets; each is
// wrapped so it fails without reverting the proof pipeline.
interface ILibrarySafe { function run(bytes calldata data) external; }
contract LibraryVaultAttempt {
    // delegatecall target is fixed, so a hijack() payload hits the benign
    // module and the owner slot is never written.
    function run(address a) external payable {
        try ILibrarySafe(a).run(abi.encodeWithSignature("hijack()")) {} catch {}
    }
    receive() external payable {}
}

interface ICommitSafe { function claim(uint256 secret) external; }
contract CommitLotteryAttempt {
    // No block entropy gates the payout; a computed "guess" is not the secret.
    function run(address a) external payable {
        uint256 g = uint256(
            keccak256(abi.encodePacked(block.timestamp, block.prevrandao, block.number))
        ) % 100;
        try ICommitSafe(a).claim(g) {} catch {}
    }
    receive() external payable {}
}

interface IGuardedSafe { function initialize(address who) external; }
contract GuardedInitializerAttempt {
    // initialize() is locked by the initialized guard; re-init reverts.
    function run(address a) external payable {
        try IGuardedSafe(a).initialize(address(this)) {} catch {}
    }
    receive() external payable {}
}
