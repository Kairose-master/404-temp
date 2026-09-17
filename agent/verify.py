# TRUST404 Track04 — candidate verifier.
# Official _prove() meaning only:
#   Setup.run() address if deploy.setup exists, else constructor + value_wei
#   checkAll healthy → exploit.run{value: 10 ether}(target) once → recheck
# Extra prepare/finish, makeAddr auto-approve, and world.txs are NOT part of
# the official run() and must not decide PROVEN.
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


class SetupDeploymentError(VerifyUnavailable):
    """The declared official initial state could not be established.

    Inherit VerifyUnavailable so the CLI emits INCONCLUSIVE / exit 2,
    rather than claiming a negative proof after silently changing targets.
    """


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

    det = manifest.get("determinism") or {}
    from trust404.hevm import make_backend
    backend, _box = make_backend(
        int(det.get("block_number") or 0),
        int(det.get("block_timestamp") or 0) or 1,
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
    target, taddr = _deploy_target(w3, compiled, arts, target_name, dep, acct, deploy, _box)
    inv, iaddr = deploy(arts["Invariants"])

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


def _deploy_target(w3, compiled, arts, target_name, dep, acct, deploy, hevm_box=None):
    """Setup presence selects a mandatory path, never a best-effort hint."""
    if "setup" in dep:
        setup_file = dep["setup"]
        if not isinstance(setup_file, str) or not setup_file.strip():
            raise SetupDeploymentError("deploy.setup must name a nonempty source path")
        # Do not use the last contract named Setup from a different source unit.
        artifact = compiled.get("contracts", {}).get(setup_file, {}).get("Setup")
        if artifact is None:
            raise SetupDeploymentError(f"missing declared Setup artifact: {setup_file}:Setup")
        try:
            setup_art = {"abi": artifact["abi"],
                         "bin": artifact["evm"]["bytecode"]["object"]}
            taddr = _deploy_via_setup(w3, setup_art, acct, hevm_box)
            if not taddr or not w3.eth.get_code(taddr):
                raise RuntimeError("Setup target has no deployed code")
            target = w3.eth.contract(address=taddr, abi=arts[target_name]["abi"])
            return target, taddr
        except Exception as e:
            raise SetupDeploymentError(
                "official Setup deployment failed; constructor fallback is forbidden: "
                f"{e}. Setups requiring Foundry cheatcodes need TRUST404_VERIFIER=forge."
            ) from e

    # No declared Setup: preserve the existing helper/constructor path.
    Web3 = type(w3)
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

    return deploy(arts[target_name], cargs, value=seed_wei)


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


def _ctor_inputs(abi):
    for e in abi or []:
        if e.get("type") == "constructor":
            return e.get("inputs") or []
    return []


def _evm_create_address(sender: str, nonce: int) -> str:
    import rlp
    from eth_utils import keccak, to_canonical_address, to_checksum_address
    return to_checksum_address(keccak(rlp.encode([to_canonical_address(sender), nonce]))[12:])


def _deploy_via_setup(w3, art, acct, hevm_box=None):
    """Deploy Setup and take ISetup.run() return value as the official target."""
    C = w3.eth.contract(abi=art["abi"], bytecode=art["bin"])
    tx = C.constructor().transact({"from": acct, "gas": 12_000_000})
    rec = w3.eth.wait_for_transaction_receipt(tx)
    saddr = rec.get("contractAddress")
    if rec.get("status") != 1 or not saddr or not w3.eth.get_code(saddr):
        raise RuntimeError("Setup constructor deployment failed")
    sc = w3.eth.contract(address=saddr, abi=art["abi"])
    # eth_call rolls back EVM state but not the Python HEVM box. Snapshot so
    # a relative vm.warp/roll inside Setup.run() is not applied twice.
    snap = dict(hevm_box) if hevm_box is not None else None
    try:
        taddr = sc.functions.run().call({"from": acct})
    except Exception as e:
        raise RuntimeError(f"Setup.run reverted: {e}") from e
    finally:
        if snap is not None:
            hevm_box.clear()
            hevm_box.update(snap)
    tx = sc.functions.run().transact({"from": acct, "gas": 12_000_000})
    rec = w3.eth.wait_for_transaction_receipt(tx)
    if rec.get("status") != 1:
        raise RuntimeError("Setup.run reverted")
    if not taddr or not w3.eth.get_code(taddr):
        raise RuntimeError("Setup.run returned an address with no code")
    return taddr


def _repo_root():
    from pathlib import Path
    return Path(__file__).resolve().parent.parent


def _harness_dir():
    from pathlib import Path
    env = os.environ.get("TRUST404_HARNESS_DIR")
    if env:
        p = Path(env)
        if p.exists():
            return p
    p = _repo_root() / "harness"
    if p.exists():
        return p
    raise VerifyUnavailable("TRUST404_HARNESS_DIR not set / missing")


def _forge_std_dir():
    from pathlib import Path
    env = os.environ.get("TRUST404_FORGE_STD")
    if env:
        p = Path(env)
        if (p / "src" / "Test.sol").exists():
            return p
    p = _repo_root() / "lib" / "forge-std"
    if (p / "src" / "Test.sol").exists():
        return p
    raise VerifyUnavailable("vendored forge-std missing (lib/forge-std)")


def _safe_write(root, rel, content):
    """Write rel under root. Reject path escape."""
    from pathlib import Path
    root = Path(root).resolve()
    p = (root / str(rel).lstrip("/")).resolve()
    if p != root and not str(p).startswith(str(root) + "/"):
        p = root / Path(rel).name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


def _parse_proof_result(out: str):
    """Read Harness ProofResult from forge -vvvv traces."""
    import re
    proven, violated = None, ""
    for line in out.splitlines():
        if "ProofResult" not in line:
            continue
        m = re.search(
            r"ProofResult\s*\(\s*(?:proven:\s*)?(true|false)\s*,\s*(?:firstViolated:\s*)?\"?([^\"\)]*)\"?\s*\)",
            line, re.I)
        if m:
            proven = m.group(1).lower() == "true"
            violated = (m.group(2) or "").strip().rstrip(",")
        elif "PROVEN" in line and "NOT PROVEN" not in line:
            proven = True
        elif "NOT PROVEN" in line or "NOT_PROVEN" in line:
            proven = False
    return proven, violated


def _forge_solc_arg(version: str) -> str:
    """Reuse the exact solcx binary offline, or let Forge use its own cache.

    Looking up an installed compiler must never download one. In the Docker
    image solcx owns /opt/solc; Forge's default ~/.svm cache is intentionally
    empty. Outside Docker, a Forge-only installation remains supported.
    """
    from pathlib import Path
    try:
        from solcx.install import get_executable
        from solcx.exceptions import SolcNotInstalled
    except ImportError:
        return version
    try:
        binary = Path(get_executable(version)).resolve()
    except SolcNotInstalled:
        return version
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise VerifyUnavailable(f"solc {version} is not executable: {binary}")
    return str(binary)


def _verify_forge(target_name, target_src, invariants_src, exploit_src, manifest,
                  extra_sources=None):
    import json
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    if shutil.which("forge") is None:
        raise VerifyUnavailable("forge not on PATH")
    harness_dir = _harness_dir()
    forge_std = _forge_std_dir()

    dep = manifest.get("deploy", {}) or {}
    seed_wei = _parse_decimal(str(dep.get("value_wei", "0")))
    funding = DEFAULT_EXPLOIT_FUNDING_WEI
    target_src_rel = (manifest.get("target") or {}).get("src") or f"src/{target_name}.sol"
    inv_rel = (manifest.get("invariants") or {}).get("contract") or "Invariants.sol"
    evm = (manifest.get("target") or {}).get("evm_version", "cancun")
    solc = (manifest.get("target") or {}).get("solc", "0.8.24")
    man_json = json.dumps(manifest)

    with tempfile.TemporaryDirectory(prefix="t404-forge-") as td:
        work = Path(td)
        (work / "src").mkdir(parents=True, exist_ok=True)
        (work / "test").mkdir(parents=True, exist_ok=True)
        shutil.copytree(Path(harness_dir) / "src", work / "harness_src")
        shutil.copytree(forge_std, work / "lib" / "forge-std")
        _safe_write(work, target_src_rel, target_src)
        _safe_write(work, inv_rel, invariants_src)
        _safe_write(work, "src/Exploit.sol", exploit_src)
        (work / "manifest.json").write_text(man_json, encoding="utf-8")
        for rel, content in (extra_sources or {}).items():
            if content:
                _safe_write(work, rel, content)
        (work / "foundry.toml").write_text(
            "[profile.default]\n"
            f"solc_version = \"{solc}\"\n"
            f"evm_version = \"{evm}\"\n"
            "src = '.'\n"
            "test = 'test'\n"
            "libs = ['lib']\n"
            "remappings = ['forge-std/=lib/forge-std/src/']\n"
            "fs_permissions = [{ access = \"read\", path = \"./\" }]\n"
            "offline = true\n"
        )
        # Caller keeps seed + exploit funding + gas headroom. _prove sends
        # run{value: funding} from this contract; seed is for the target ctor
        # / Setup, not for the caller remainder.
        deal_wei = seed_wei + funding + 10**18
        test_src = f"""// SPDX-License-Identifier: MIT
pragma solidity {solc};
import {{Harness}} from "../harness_src/Harness.sol";
import {{Exploit}} from "../src/Exploit.sol";
contract Run is Harness {{
    function test_prove() public {{
        vm.deal(address(this), {deal_wei});
        string memory man = vm.readFile("manifest.json");
        (address target, address inv, uint256 bn, uint256 ts,) = _deployFromManifest(man, "");
        Exploit exp = new Exploit();
        (bool proven, string memory v) = _prove(target, inv, address(exp), bn, ts, {funding});
        proven; v;
    }}
}}
"""
        (work / "test" / "Run.t.sol").write_text(test_src)
        try:
            proc = subprocess.run(
                ["forge", "test", "--match-contract", "Run", "-vvvv", "--offline",
                 "--use", _forge_solc_arg(solc), "--color", "never"],
                cwd=work, capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f"forge timed out: {e}")
        out = (proc.stdout or "") + (proc.stderr or "")
        # Failed execution traces may contain events from reverted calls.
        # Never accept those events as a successful official proof.
        if proc.returncode != 0:
            if ("Compiler run failed" in out or "not found" in out
                    or "failing tests" not in out.lower()):
                raise RuntimeError(f"forge verifier infrastructure failed:\n{out[-1200:]}")
            return False, "", "forge NOT_PROVEN (test reverted/failed)"
        proven, violated = _parse_proof_result(out)
        if proven is None:
            raise RuntimeError(f"forge succeeded without ProofResult:\n{out[-1200:]}")
        return bool(proven), violated if proven else "", "forge"
