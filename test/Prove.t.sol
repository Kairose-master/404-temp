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
