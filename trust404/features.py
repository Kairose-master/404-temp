"""Capability IR — generalize Ethernaut *level solvers* into family features.

Each former level-specific synth (`_synth_gatekeeper_one`, `_synth_puzzle_wallet`,
…) is a *family* that should fire on any contract matching these source
capabilities, not on a hardcoded name. `extract_features` is the cheap
pre-filter (regex/CFG-lite) that the provider registry uses so we do not
compile+deploy 20 solvers on every SafeVault.

Families map 1:1 onto the synths in api/prove.py; names are stable.
"""
from __future__ import annotations

import re
from typing import Iterable, Set

from .scan import _functions, _strip_comments, _contract_bodies


def extract_features(src: str, name: str | None = None) -> Set[str]:
    """Return the set of capability tags present in `src`.

    Empty set means "no family matched" — the registry then still runs the
    generic template/fuzz path, but skips expensive specialized synths.
    """
    raw = src or ""
    s = _strip_comments(raw)
    bodies = _contract_bodies(s)
    tb = bodies.get(name, s) if name else s
    fns = _functions(tb) or _functions(s)
    feats: Set[str] = set()

    def has(pat: str, text: str = s, flags=0) -> bool:
        return bool(re.search(pat, text, flags))

    # ── classic 4 + wargame 3 (scanner families) ──────────────────────────
    if has(r"\.call\s*\{\s*value\s*:"):
        feats.add("value_call")
    if has(r"nonReentrant|locked\s*==\s*1|_status"):
        feats.add("reentrancy_mutex")
    # CEI violation: value call with ledger clear AFTER the call
    for fn in fns:
        m = re.search(r"\.call\s*\{\s*value\s*:", fn["body"])
        if not m:
            continue
        before, after = fn["body"][: m.start()], fn["body"][m.start() :]
        cleared_before = re.search(r"\w+\[\s*msg\.sender\s*\]\s*(=\s*0|-=)", before)
        cleared_after = re.search(r"\w+\[\s*msg\.sender\s*\]\s*(=\s*0|-=)", after)
        if not cleared_before and (cleared_after or True):
            feats.add("cei_violation")
            break
    if has(r"\bowner\s*=") and not has(r"only\w*[Oo]wner"):
        feats.add("unguarded_owner_write")
    if has(r"unchecked\s*\{"):
        feats.add("unchecked_arithmetic")
    if has(r"spotPrice|getPrice|reserve[0-9A-Za-z]*") and has(r"\bborrow\b|\bswap"):
        feats.add("spot_price")
        feats.add("oracle")
    if has(r"\bswap\s*\(") or has(r"swap\w*For"):
        feats.add("swap")
    if has(r"flashLoan|flashloan|IFlashLoan"):
        feats.add("flashloan")

    # delegatecall: parameter vs stored library
    for fn in fns:
        m = re.search(r"(\w+)\s*\.\s*delegatecall\s*\(", fn["body"])
        if not m:
            continue
        recv = m.group(1)
        addr_params = [an for (t, an) in fn["args"] if t == "address"]
        if recv in addr_params:
            feats.add("delegatecall_param")
        else:
            feats.add("delegatecall_stored_lib")
    if has(r"fallback") and has(r"delegatecall"):
        feats.add("fallback_delegatecall")

    entropy = (
        "block.timestamp", "block.prevrandao", "block.difficulty",
        "block.number", "blockhash",
    )
    if any(tok in s for tok in entropy) and ("keccak256" in s or "%" in s):
        feats.add("block_entropy")

    init_name = re.compile(r"^(initialize|init|initializer|__init)\w*$", re.I)
    for fn in fns:
        if init_name.match(fn["name"]) or re.search(r"\b(owner|admin|upgrader)\b\s*=\s*msg\.sender", fn["body"]):
            guarded = bool(
                re.search(r"require\s*\(\s*!\s*\w*[Ii]nitialized", fn["body"])
                or re.search(r"require\s*\(\s*!\s*\w*[Ii]nitialized", s)
                or "initializer" in fn["head"]
                or "_disableInitializers" in s
            )
            if not guarded:
                feats.add("unguarded_initialize")

    # ── generalized former level-solvers ──────────────────────────────────
    # Gatekeeper One: gasleft()%N==0 + tx.origin key
    if has(r"gasleft\s*\(\s*\)\s*%\s*\d+"):
        feats.add("gasleft_modulo")
    if has(r"uint16\s*\(\s*uint160\s*\(\s*tx\.origin") or has(r"tx\.origin"):
        feats.add("tx_origin_mask")
        feats.add("tx_origin")

    # Gatekeeper Two: extcodesize(caller())==0 + XOR key
    if has(r"extcodesize") and has(r"==\s*0"):
        feats.add("extcodesize_zero")
    if has(r"type\s*\(\s*uint64\s*\)\s*\.max") and has(r"\^"):
        feats.add("xor_extcodehash_key")

    # Gatekeeper Three: typo'd constructor + send() gate
    if has(r"function\s+construct0r\b") or has(r"function\s+constructor\s*\("):
        feats.add("construct0r")
    if has(r"\.send\s*\(") and has(r"trick"):
        feats.add("send_gate")

    # HigherOrder: small ABI type, assembly calldataload/sstore of full word
    if has(r"calldataload") and has(r"sstore|assembly"):
        feats.add("calldata_fullword_sstore")
    if has(r"function\s+\w+\s*\(\s*uint8\b"):
        feats.add("narrow_abi_param")

    # Switch: selector compared at a fixed calldata offset
    if has(r"calldataload\s*\(\s*\d+\s*\)") and has(r"flipSwitch|selector"):
        feats.add("selector_offset_check")

    # Puzzle Wallet family: proxy admin + nested multicall + setMaxBalance
    if has(r"function\s+proposeNewAdmin") or has(r"pendingAdmin"):
        feats.add("proxy_admin")
    if has(r"function\s+multicall\s*\(\s*bytes"):
        feats.add("nested_multicall")
    if has(r"function\s+setMaxBalance"):
        feats.add("slot_alias_max_balance")

    # Magic Animal Carousel: packed nextId overflowing into name
    if has(r"nextId") and has(r"bytes32") and has(r"carousel|animal|packed"):
        feats.add("packed_id_overflow")
    # generic packed-storage write of a user-supplied bytes into a slot that
    # also holds an id/pointer — broader than the carousel level.
    if has(r"bytes32") and has(r"shl\s*\(\s*16") or has(r"uint16\(") and has(r"sstore"):
        feats.add("packed_storage_write")

    # Magic Number: solver with size constraint
    if has(r"extcodesize") and has(r"<=\s*10|<\s*11|solver"):
        feats.add("solver_size_gate")

    # Force: no receive/fallback but balance is observed
    if (not has(r"\breceive\s*\(") and not has(r"\bfallback\s*\(")
            and not has(r"payable")):
        feats.add("no_receive")

    # King / griefing: role assignment + push refund
    if has(r"\.transfer\s*\(") and has(r"king|prize|highest"):
        feats.add("push_refund_role")
    if has(r"payable\s*\(\s*\w+\s*\)\s*\.transfer"):
        feats.add("push_refund_role")

    # Elevator / Shop: view callback consulted twice
    if has(r"isLastFloor|price\s*\(") and has(r"msg\.sender"):
        feats.add("view_callback_twice")
    if has(r"function\s+price\s*\(") and has(r"view"):
        feats.add("view_price_callback")

    # Shop specifically: buy() reads price() twice
    for fn in fns:
        if fn["name"] in ("buy", "purchase") and fn["body"].count("price(") >= 2:
            feats.add("view_price_callback")
            feats.add("view_callback_twice")

    # Good Samaritan: custom error catch → remainder drain
    if has(r"error\s+\w+") and has(r"catch") and has(r"notify"):
        feats.add("custom_error_catch")
    if has(r"NotEnoughBalance|transferRemainder"):
        feats.add("custom_error_catch")

    # Stake: fake WETH accounting
    if has(r"StakeWETH|WETH") and has(r"balanceOf"):
        feats.add("fake_weth")
        feats.add("stake")

    # Dex / DexTwo
    if has(r"function\s+swap") and has(r"get_swap_price|getSwapPrice|balanceOf"):
        feats.add("dex_spot_swap")
    if has(r"function\s+swap") and not has(r"require\s*\([^)]*token"):
        feats.add("swap_unverified_token")

    # Alien Codex: array length underflow → slot 0
    if has(r"length\s*--") or has(r"codex\.length") or has(r"\.pop\s*\(\s*\)"):
        feats.add("array_length_unchecked")
    if has(r"function\s+revise") or has(r"retract"):
        feats.add("array_length_unchecked")

    # Naught Coin: lockup on transfer, approve+transferFrom open
    if has(r"transferFrom") and has(r"approve"):
        feats.add("approve_transferFrom")
    if has(r"lockup|timelock|timeLock|_time"):
        feats.add("lockup")

    # Denial: partner withdraw with unbounded gas
    if has(r"partner") and has(r"call\s*\{\s*value"):
        feats.add("withdraw_to_partner")
    if has(r"while\s*\(\s*true") or has(r"invalid\s*\(\s*\)"):
        feats.add("unbounded_loop")

    # ECDSA malleability
    if has(r"ecrecover"):
        feats.add("ecrecover")

    # Commitment / off-by-one hash
    if has(r"keccak256") and has(r"length\s*-\s*1"):
        feats.add("commit_hash_loop")

    # EIP-7702 / tx.origin EOA gate + receiver hook before mint
    if has(r"tx\.origin\s*==\s*msg\.sender|msg\.sender\s*==\s*tx\.origin"):
        feats.add("tx_origin_eoa_gate")
    if has(r"onERC721Received|onERC1155Received|tokensReceived"):
        feats.add("receiver_hook")
    if has(r"_safeMint|_mint") and has(r"onERC721Received|onERC1155Received"):
        feats.add("receiver_hook_before_mint")

    # Vault / Privacy: private password unlock
    if has(r"private") and has(r"unlock|locked|password"):
        feats.add("private_unlock")
        feats.add("bytes32_secret")

    # selfdestruct present (Recovery / Force / Motorbike engine)
    if has(r"selfdestruct|suicide"):
        feats.add("selfdestruct")

    # ── Damn Vulnerable DeFi / CTF / 2026-incident families (not level names)
    # Unstoppable: token.balanceOf(this) asserted against internal accounting
    if has(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)") and has(r"assert\s*\(|require\s*\("):
        feats.add("donation_accounting_dos")
    # Truster / AtomicQueue: unpermissioned target.call(data) or approve
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        if re.search(r"only\w*[Oo]wner", fn["head"] + b):
            continue
        if (re.search(r"\.call\s*\(|approve", b)
                and any(t.startswith("bytes") or t == "address" for t, _ in fn["args"])):
            feats.add("unpermissioned_callback")
            break
    # Selfie: flash loan + governance snapshot/queue
    if has(r"flashLoan|flashloan") and has(r"snapshot|queueAction|castVote|propose"):
        feats.add("governance_flashloan")
    # Climber: execute + schedule on a timelock
    if has(r"function\s+execute\s*\(") and has(r"function\s+schedule\s*\("):
        feats.add("execute_before_schedule")
    # CREATE2 address mining (WalletMining / Recovery)
    if has(r"CREATE2|create2") or has(r"keccak256\s*\(\s*abi\.encodePacked\s*\(\s*bytes1\s*\(\s*0xff"):
        feats.add("create2_predict")
    # Gnosis Safe factory callback (Backdoor)
    if has(r"GnosisSafe|setupModules|proxyCreated|IProxyCreationCallback"):
        feats.add("gnosis_factory_callback")
    # Naive receiver: flash loan charges a third party
    if has(r"flashLoan") and has(r"receiver") and not has(r"onlyOwner"):
        feats.add("unpermissioned_flashloan")
    # Short-address / calldata padding (软件学报 EVM layer)
    if has(r"calldataload") or has(r"msg\.data"):
        feats.add("raw_calldata")
    # 软件学报: exception-handling inconsistency (send vs call)
    if has(r"\.send\s*\(") or has(r"\.transfer\s*\("):
        feats.add("push_send")

    return feats


def any_match(needs: Iterable[str], feats: Set[str]) -> bool:
    """True if the provider should run: empty needs → always; else any overlap."""
    need = set(needs)
    if not need:
        return True
    return bool(need & feats)
