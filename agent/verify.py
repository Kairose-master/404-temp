# TRUST404 Track04 — candidate verifier.
# 하네스 harness/src/Harness.sol 의 _prove() 절차를 그대로 재현한다:
#   1. 결정론 시간 고정(내장 EVM은 배포 시점 고정 블록 사용)
#   2. 배포 직후 checkAll(target) == (true,"") (아니면 BAD TARGET DESIGN)
#   3. Exploit 에 10 ETH 지급 후 run{value: 10 ether}(target)
#   4. 재검사 — allHold==false 면 PROVEN
#   5. profit oracle: 펀딩 이후·run 이후 잔액 Δ. 펀딩 자체는 수익이 아님.
# 기본 검증기는 내장 EVM(solc 0.8.24 + eth-tester/py-evm)이라 forge 없이,
# 네트워크 없이 오프라인으로 동작한다. TRUST404_VERIFIER=forge 로 두면
# 참가 번들 하네스를 forge test 로 돌리는 경로를 쓴다(그 환경에 forge 필요).
from __future__ import annotations

import os
import warnings
from dataclasses import dataclass
from typing import List, Optional

warnings.filterwarnings("ignore")

DEFAULT_EXPLOIT_FUNDING_WEI = 10 * 10**18  # 하네스 규약 DEFAULT_EXPLOIT_FUNDING_WEI

try:
    from pathlib import Path as _P
    import sys as _s
    _r = _P(__file__).resolve().parent.parent
    if str(_r) not in _s.path:
        _s.path.insert(0, str(_r))
    from trust404.profit import ProfitReport, measure_evm, snapshot
except Exception:  # package optional
    ProfitReport = None
    measure_evm = None
    snapshot = None


@dataclass
class VerifyResult:
    proven: bool
    violated: str
    detail: str
    profit: object = None

    def tuple(self):
        return self.proven, self.violated, self.detail


class VerifyUnavailable(Exception):
    """검증 도구를 이 환경에서 사용할 수 없음."""


def verify_candidate(target_name, target_src, invariants_src, exploit_src, manifest, seed,
                     extra_sources=None):
    return verify_full(
        target_name, target_src, invariants_src, exploit_src, manifest, seed,
        extra_sources=extra_sources,
    ).tuple()


def verify_full(target_name, target_src, invariants_src, exploit_src, manifest, seed=0,
                extra_sources=None):
    mode = os.environ.get("TRUST404_VERIFIER", "evm").lower()
    if mode == "forge":
        proven, violated, detail = _verify_forge(
            target_name, target_src, invariants_src, exploit_src, manifest,
            extra_sources=extra_sources)
        return VerifyResult(proven, violated, detail, profit=None)
    return _verify_evm(target_name, target_src, invariants_src, exploit_src, manifest,
                       extra_sources=extra_sources)


# ── 내장 EVM 검증기 ──────────────────────────────────────────────────────────
def _verify_evm(target_name, target_src, invariants_src, exploit_src, manifest,
                extra_sources=None):
    try:
        import solcx
        from web3 import Web3
        from eth_tester import EthereumTester, PyEVMBackend
    except Exception as e:
        raise VerifyUnavailable(f"python EVM stack missing: {e}")

    solc_version = manifest["target"].get("solc", "0.8.24")
    evm_version = manifest["target"].get("evm_version", "cancun")
    try:
        solcx.set_solc_version(solc_version)
    except Exception:
        try:
            solcx.install_solc(solc_version)
            solcx.set_solc_version(solc_version)
        except Exception as e:
            raise VerifyUnavailable(f"solc {solc_version} unavailable: {e}")

    src_key = (manifest.get("target") or {}).get("src") or f"{target_name}.sol"
    inv_key = (manifest.get("invariants") or {}).get("contract") or "Invariants.sol"
    files = {
        src_key: target_src,
        f"{target_name}.sol": target_src,
        inv_key: invariants_src,
        "Invariants.sol": invariants_src,
        "Exploit.sol": exploit_src,
    }
    for k, v in (extra_sources or {}).items():
        if v:
            files[k] = v
    std_in = {
        "language": "Solidity",
        "sources": {fn: {"content": s} for fn, s in files.items()},
        "settings": {
            "evmVersion": evm_version,
            "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}},
        },
    }
    compiled = solcx.compile_standard(std_in, allow_empty=True)
    arts = {}
    for _fn, contracts in compiled.get("contracts", {}).items():
        for cname, c in contracts.items():
            arts[cname] = {"abi": c["abi"], "bin": c["evm"]["bytecode"]["object"]}

    for need in (target_name, "Invariants", "Exploit"):
        if need not in arts:
            raise RuntimeError(f"missing compiled artifact: {need}")

    backend = PyEVMBackend.from_mnemonic(
        "test test test test test test test test test test test junk",
        genesis_state_overrides={"balance": 10**24},
    )
    et = EthereumTester(backend=backend)
    w3 = Web3(Web3.EthereumTesterProvider(et))
    acct = w3.eth.accounts[0]

    def deploy(art, args=None, value=0):
        C = w3.eth.contract(abi=art["abi"], bytecode=art["bin"])
        tx = C.constructor(*(args or [])).transact({"from": acct, "value": value, "gas": 12_000_000})
        r = w3.eth.wait_for_transaction_receipt(tx)
        return w3.eth.contract(address=r.contractAddress, abi=art["abi"]), r.contractAddress

    dep = manifest.get("deploy", {})
    helpers_addr = {}
    for h in dep.get("helpers") or []:
        cname = h.get("contract")
        if not cname or cname not in arts:
            continue
        hargs = _coerce_args(h.get("args") or [], Web3)
        _hc, haddr = deploy(arts[cname], hargs, value=_parse_decimal(str(h.get("value_wei", "0"))))
        helpers_addr[cname] = haddr
    raw_cargs = dep.get("constructor_args", [])
    if isinstance(raw_cargs, dict):
        raw_cargs = [raw_cargs]
    try:
        from trust404.abi import resolve_placeholders, coerce_against_abi
        raw_cargs = resolve_placeholders(raw_cargs, helpers_addr)
        cargs = coerce_against_abi(raw_cargs, arts[target_name]["abi"], Web3)
    except Exception:
        cargs = _coerce_args(raw_cargs, Web3)
    seed_wei = _parse_decimal(str(dep.get("value_wei", "0")))

    target, taddr = deploy(arts[target_name], cargs, value=seed_wei)
    inv, iaddr = deploy(arts["Invariants"])

    try:
        _apply_world_txs(w3, arts, taddr, helpers_addr, manifest, acct)
    except Exception:
        pass
    try:
        _apply_derived_eoas(w3, et, taddr, target_src, extra_sources)
    except Exception:
        pass

    before = inv.functions.checkAll(taddr).call()
    if before[0] is not True:
        raise RuntimeError(f"BAD TARGET DESIGN: invariant already broken before exploit: {before[1]}")

    exp, eaddr = deploy(arts["Exploit"])
    w3.eth.send_transaction({"from": acct, "to": eaddr, "value": DEFAULT_EXPLOIT_FUNDING_WEI, "gas": 1_000_000})

    tokens: List[str] = list((manifest.get("profit") or {}).get("tokens") or [])
    before_att = snapshot(w3, eaddr, tokens) if snapshot else None
    before_tgt = snapshot(w3, taddr, tokens) if snapshot else None

    run_err = None
    try:
        tx = exp.functions.run(taddr).transact(
            {"from": acct, "value": DEFAULT_EXPLOIT_FUNDING_WEI, "gas": 12_000_000})
        w3.eth.wait_for_transaction_receipt(tx)
    except Exception as e:
        run_err = str(e)[:160]

    after = inv.functions.checkAll(taddr).call()
    proven = after[0] is False
    if not proven:
        try:
            p2, a2, e2 = _phased_retry(w3, et, exp, taddr, inv, exploit_src)
            if p2:
                proven, after = True, a2
                run_err = ((run_err or "") + f" phased=1 {e2}").strip()
        except Exception as e:
            run_err = ((run_err or "") + f" phase_err={str(e)[:80]}").strip()
    profit = None
    if measure_evm and before_att is not None:
        try:
            profit = measure_evm(
                w3, eaddr, taddr, tokens,
                before_attacker=before_att, before_target=before_tgt,
                invariant_broken=proven,
            )
        except Exception:
            profit = None
    cls = getattr(profit, "classification", "") if profit else ""
    wei = getattr(profit, "extractable_wei", "") if profit else ""
    detail = (
        f"allHold={after[0]}"
        + (f" run_err={run_err}" if run_err else "")
        + (f" profit={cls}:{wei}" if cls else "")
    )
    return VerifyResult(
        proven=proven,
        violated=(after[1] if proven else ""),
        detail=detail,
        profit=profit,
    )


def _coerce_args(args, Web3):
    try:
        from trust404.abi import coerce
        return coerce(args, Web3)
    except Exception:
        pass
    out = []
    for a in args or []:
        if isinstance(a, (list, tuple)):
            out.append(_coerce_args(a, Web3))
        elif isinstance(a, str):
            if a.startswith("0x") and len(a) == 42:
                out.append(Web3.to_checksum_address(a))
            elif a.startswith("0x") and len(a) > 2 and len(a) % 2 == 0:
                try:
                    out.append(bytes.fromhex(a[2:]))
                except ValueError:
                    out.append(a)
            elif a.isdigit():
                out.append(int(a))
            else:
                out.append(a)
        else:
            out.append(a)
    return out


def _parse_decimal(s):
    s = s.strip()
    if not s:
        return 0
    if not s.isdigit():
        raise ValueError(f"value_wei not decimal: {s!r}")
    return int(s)


def _phased_retry(w3, et, exp, taddr, inv, exploit_src):
    """prepare → time_travel → finish. py-evm stand-in for HEVM warp/prank.

    No-op if the exploit has no prepare(). Must not break the 12-target path.
    """
    fnames = {i.get("name") for i in (exp.abi or []) if i.get("type") == "function"}
    if "prepare" not in fnames:
        return False, None, "no-prepare"
    acct = w3.eth.accounts[0]
    tx = exp.functions.prepare(taddr).transact(
        {"from": acct, "value": DEFAULT_EXPLOIT_FUNDING_WEI, "gas": 12_000_000})
    w3.eth.wait_for_transaction_receipt(tx)
    window = 3600
    try:
        from trust404.hevm import window_seconds
        window = window_seconds(exploit_src)
    except Exception:
        pass
    try:
        latest = w3.eth.get_block("latest")
        et.time_travel(int(latest["timestamp"]) + max(int(window), 1))
    except Exception:
        try:
            et.time_travel(int(w3.eth.get_block("latest").timestamp) + max(int(window), 1))
        except Exception:
            pass
    for _ in range(3):
        try:
            et.mine_block()
        except Exception:
            break
    if "finish" in fnames:
        tx = exp.functions.finish(taddr).transact(
            {"from": acct, "value": DEFAULT_EXPLOIT_FUNDING_WEI, "gas": 12_000_000})
    else:
        tx = exp.functions.run(taddr).transact(
            {"from": acct, "value": DEFAULT_EXPLOIT_FUNDING_WEI, "gas": 12_000_000})
    w3.eth.wait_for_transaction_receipt(tx)
    after = inv.functions.checkAll(taddr).call()
    return after[0] is False, after, ""


def _apply_world_txs(w3, arts, taddr, helpers, manifest, acct0):
    """Send real txs from a second EOA (no cheatcodes).

    manifest.world.txs: [{from: "victim", to: "$token"| "$target", sig: "approve(address,uint256)", args: [...]}]
    `victim` is w3.eth.accounts[1]. $Name resolved from deploy.helpers.
    """
    txs = ((manifest.get("world") or {}).get("txs")) or []
    if not txs:
        return
    accounts = list(w3.eth.accounts)
    victim = accounts[1] if len(accounts) > 1 else accounts[0]
    try:
        w3.eth.send_transaction({"from": acct0, "to": victim, "value": 10**18, "gas": 21000})
    except Exception:
        pass

    def resolve_addr(x):
        if not isinstance(x, str):
            return x
        if x in ("$target", "target"):
            return taddr
        if x.startswith("$") and x[1:] in helpers:
            return helpers[x[1:]]
        if x.startswith("0x") and len(x) == 42:
            return w3.to_checksum_address(x)
        return x

    for step in txs:
        actor = (step.get("from") or step.get("actor") or "attacker")
        frm = victim if str(actor).lower() in ("victim", "user", "alice", "holder") else acct0
        to = resolve_addr(step.get("to") or "$target")
        sig = step.get("sig") or step.get("fn") or ""
        args = [resolve_addr(a) if isinstance(a, str) else a for a in (step.get("args") or [])]
        args = ["max" if a == "max" else a for a in args]
        args = [2**256 - 1 if a == "max" else a for a in args]
        if not sig or not to:
            continue
        name, _, rest = sig.partition("(")
        types = [t.strip() for t in rest.rstrip(")").split(",") if t.strip()]
        abi = [{
            "type": "function", "name": name,
            "inputs": [{"type": t, "name": f"a{i}"} for i, t in enumerate(types)],
            "outputs": [],
        }]
        c = w3.eth.contract(address=to, abi=abi)
        fn = getattr(c.functions, name)
        from trust404.abi import coerce
        coerced = coerce(args, w3)
        tx = fn(*coerced).transact({
            "from": frm,
            "value": int(step.get("value") or 0),
            "gas": 2_000_000,
        })
        w3.eth.wait_for_transaction_receipt(tx)


def _apply_derived_eoas(w3, et, taddr, target_src, extra_sources):
    """Register Foundry makeAddr keys and approve the target as those EOAs.

    No cheatcode: a real signed tx from keccak256(name). Only works when
    eth_account is installed (agent extras). Silent no-op in unit tests.
    """
    from trust404.eoa import derived_accounts, make_addr_names
    blobs = [target_src or ""] + list((extra_sources or {}).values())
    names = []
    for b in blobs:
        names.extend(make_addr_names(b))
    if not names:
        return
    accts = derived_accounts(*blobs)
    token_abi = [{
        "type": "function", "name": "approve",
        "inputs": [{"name": "s", "type": "address"}, {"name": "n", "type": "uint256"}],
        "outputs": [{"type": "bool"}],
    }, {
        "type": "function", "name": "token",
        "inputs": [], "outputs": [{"type": "address"}],
        "stateMutability": "view",
    }]
    tok = taddr
    try:
        t = w3.eth.contract(address=taddr, abi=token_abi)
        tok = t.functions.token().call()
    except Exception:
        tok = taddr
    for _name, addr, key in accts:
        try:
            et.add_account(key)
        except Exception:
            try:
                et.add_account(key[2:] if key.startswith("0x") else key)
            except Exception:
                continue
        try:
            w3.eth.send_transaction({
                "from": w3.eth.accounts[0], "to": addr, "value": 10**18, "gas": 21000,
            })
        except Exception:
            pass
        try:
            c = w3.eth.contract(address=tok, abi=token_abi)
            tx = c.functions.approve(taddr, 2**256 - 1).transact({
                "from": addr, "gas": 200_000,
            })
            w3.eth.wait_for_transaction_receipt(tx)
        except Exception:
            pass


# ── forge 검증기(선택) ───────────────────────────────────────────────────────
def _verify_forge(target_name, target_src, invariants_src, exploit_src, manifest,
                  extra_sources=None):
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    if shutil.which("forge") is None:
        raise VerifyUnavailable("forge not on PATH")
    harness_dir = os.environ.get("TRUST404_HARNESS_DIR")
    if not harness_dir or not Path(harness_dir).exists():
        raise VerifyUnavailable("TRUST404_HARNESS_DIR not set / missing")

    dep = manifest.get("deploy", {})
    seed_wei = _parse_decimal(str(dep.get("value_wei", "0")))
    block_number = manifest["determinism"]["block_number"]
    block_timestamp = manifest["determinism"]["block_timestamp"]

    work = Path(tempfile.mkdtemp(prefix="t404-forge-"))
    src = work / "src"
    test = work / "test"
    src.mkdir(parents=True)
    test.mkdir(parents=True)
    (src / f"{target_name}.sol").write_text(target_src)
    (src / "Invariants.sol").write_text(invariants_src)
    (src / "Exploit.sol").write_text(exploit_src)
    for rel, content in (extra_sources or {}).items():
        p = work / rel if "/" in rel or rel.endswith(".sol") else src / rel
        if not str(p).startswith(str(work)):
            p = src / Path(rel).name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    shutil.copytree(Path(harness_dir) / "src", work / "harness_src")
    (work / "foundry.toml").write_text(
        "[profile.default]\n"
        f"evm_version = \"{manifest['target'].get('evm_version','cancun')}\"\n"
        "src = 'src'\ntest = 'test'\n"
        "remappings = ['forge-std/=lib/forge-std/src/']\n"
    )
    cargs = dep.get("constructor_args", [])
    try:
        from trust404.abi import forge_ctor
        prelude, ctor = forge_ctor(cargs, src=target_src, name=target_name)
    except Exception:
        prelude, ctor = "", ""
        if len(cargs) == 1 and isinstance(cargs[0], str) and cargs[0].startswith("0x"):
            ctor = f"address({cargs[0]})"
    test_src = f"""// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
import {{Harness}} from "../harness_src/Harness.sol";
import {{{target_name}}} from "../src/{target_name}.sol";
import {{Invariants}} from "../src/Invariants.sol";
import {{Exploit}} from "../src/Exploit.sol";
contract Run is Harness {{
    function test_prove() public {{
        vm.deal(address(this), {seed_wei});
{prelude}
        {target_name} target = new {target_name}{{value: {seed_wei}}}({ctor});
        Invariants inv = new Invariants();
        Exploit exp = new Exploit();
        (bool proven, string memory v) = _prove(
            address(target), address(inv), address(exp),
            {block_number}, {block_timestamp}, {DEFAULT_EXPLOIT_FUNDING_WEI});
        if (proven) emit log_named_string("AGENT_RESULT", string.concat("PROVEN:", v));
        else emit log_named_string("AGENT_RESULT", "NOT_PROVEN");
    }}
}}
"""
    (test / "Run.t.sol").write_text(test_src)
    proc = subprocess.run(
        ["forge", "test", "--match-contract", "Run", "-vv"],
        cwd=work, capture_output=True, text=True, timeout=180)
    out = proc.stdout + proc.stderr
    if "AGENT_RESULT" not in out:
        raise RuntimeError(f"forge produced no result:\n{out[-800:]}")
    line = [l for l in out.splitlines() if "AGENT_RESULT" in l][-1]
    if "PROVEN:" in line and "NOT_PROVEN" not in line:
        violated = line.split("PROVEN:")[-1].strip().strip('"')
        return True, violated, "forge"
    return False, "", "forge NOT_PROVEN"
