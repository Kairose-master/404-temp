"""Constructor-arg coercion for the track verifier.

The official harness (Harness.sol) refuses to guess ABI from JSON and
delegates to Setup.s.sol. The py-evm path has to encode the same JSON
itself — METHOD used to admit only ``()`` or a single address, which is
how a hidden ``constructor(address[] memory, uint256)`` kills the agent.

This module is that encoder. It does not invent types: web3 uses the
compiled constructor ABI. We only coerce JSON values into Python objects
eth_abi will accept (checksum addresses, ints, bytes, nested lists).
"""
from __future__ import annotations

import re
from typing import Any, List, Optional, Sequence, Tuple


def coerce(args: Sequence[Any], web3=None) -> list:
    """Recursively coerce manifest constructor_args to Python values."""
    out = []
    for a in args or []:
        out.append(_one(a, web3))
    return out


def _one(a: Any, web3) -> Any:
    if isinstance(a, (list, tuple)):
        return [_one(x, web3) for x in a]
    if isinstance(a, bool):
        return a
    if isinstance(a, int):
        return a
    if not isinstance(a, str):
        return a
    s = a.strip()
    if s.startswith("$"):
        return s  # placeholder, resolved by helpers
    if s in ("true", "false"):
        return s == "true"
    if s.startswith("0x") and len(s) == 42:
        if web3 is not None:
            try:
                return web3.to_checksum_address(s)
            except Exception:
                return s
        return s
    if s.startswith("0x") and len(s) > 2 and len(s) % 2 == 0:
        try:
            return bytes.fromhex(s[2:])
        except ValueError:
            return s
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    return s


def parse_constructor_types(src: str, name: Optional[str] = None) -> List[str]:
    """Best-effort Solidity constructor types from source. Empty if none."""
    s = re.sub(r"//[^\n]*", "", src or "")
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.S)
    if name:
        m = re.search(rf"\bcontract\s+{re.escape(name)}\b", s)
        if m:
            s = s[m.start():]
    m = re.search(r"\bconstructor\s*\(([^)]*)\)", s)
    if not m:
        return []
    inner = m.group(1).strip()
    if not inner:
        return []
    types = []
    for part in _split_args(inner):
        part = part.strip()
        if not part:
            continue
        # drop argument name and data location
        part = re.sub(r"\b(memory|calldata|storage)\b", "", part)
        toks = part.split()
        types.append(toks[0] if toks else part)
    return types


def _split_args(inner: str) -> List[str]:
    parts, buf, depth = [], [], 0
    for ch in inner:
        if ch == "[":
            depth += 1
            buf.append(ch)
        elif ch == "]":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def forge_ctor(cargs: Sequence[Any]) -> Tuple[str, str]:
    """Return (prelude solidity, argument list) for `new Target{value}(args)`.

    Arrays become a local `memory` variable. Single address/uint/string
    inline. Empty args → ("", "").
    """
    if not cargs:
        return "", ""
    prelude: List[str] = []
    exprs: List[str] = []
    for i, a in enumerate(cargs):
        expr, extra = _forge_expr(a, f"_a{i}")
        prelude.extend(extra)
        exprs.append(expr)
    return "\n".join(prelude), ", ".join(exprs)


def _forge_expr(a: Any, ident: str) -> Tuple[str, List[str]]:
    if isinstance(a, list):
        n = len(a)
        kind = _infer_array_type(a)
        lines = [f"        {kind} memory {ident} = new {kind}({n});"]
        for j, el in enumerate(a):
            el_expr, el_extra = _forge_expr(el, f"{ident}_{j}")
            lines.extend(el_extra)
            lines.append(f"        {ident}[{j}] = {el_expr};")
        return ident, lines
    if isinstance(a, bool):
        return ("true" if a else "false"), []
    if isinstance(a, int):
        return f"uint256({a})", []
    if isinstance(a, (bytes, bytearray)):
        return f"hex\"{bytes(a).hex()}\"", []
    if isinstance(a, str):
        s = a.strip()
        if s.startswith("0x") and len(s) == 42:
            return f"address({s})", []
        if s.startswith("0x") and len(s) > 2:
            return f'hex"{s[2:]}"', []
        if re.fullmatch(r"-?\d+", s):
            return f"uint256({int(s)})", []
        esc = s.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{esc}"', []
    return str(a), []


def _infer_array_type(arr: list) -> str:
    if not arr:
        return "uint256[]"
    x = arr[0]
    if isinstance(x, list):
        return _infer_array_type(x) + "[]"
    if isinstance(x, bool):
        return "bool[]"
    if isinstance(x, int):
        return "uint256[]"
    if isinstance(x, str):
        s = x.strip()
        if s.startswith("0x") and len(s) == 42:
            return "address[]"
        if s.startswith("0x"):
            return "bytes[]"
        if re.fullmatch(r"-?\d+", s):
            return "uint256[]"
        return "string[]"
    return "uint256[]"


def resolve_placeholders(args: Sequence[Any], helpers: dict) -> list:
    """Replace \"$Token\" with deployed helper addresses."""
    out = []
    for a in args or []:
        if isinstance(a, str) and a.startswith("$"):
            key = a[1:]
            if key not in helpers:
                raise KeyError(f"unresolved constructor placeholder {a}")
            out.append(helpers[key])
        elif isinstance(a, list):
            out.append(resolve_placeholders(a, helpers))
        else:
            out.append(a)
    return out


def load_extra_sources(manifest_path, contract_path, manifest) -> dict:
    """Sibling .sol files + Setup.s.sol next to the manifest.

    Hidden-set targets with constructor arrays / multiple contracts use
    `deploy.setup` and extra sources in `src/`. The agent used to compile
    only `--contract`, which is how those die.
    """
    from pathlib import Path
    extras = {}
    man_dir = Path(manifest_path).parent
    setup = (manifest.get("deploy") or {}).get("setup")
    if setup:
        p = man_dir / setup
        if p.is_file():
            extras[setup] = p.read_text(encoding="utf-8")
    cpath = Path(contract_path)
    src_dir = cpath.parent
    if src_dir.is_dir():
        for p in sorted(src_dir.glob("*.sol")):
            if p.resolve() == cpath.resolve():
                continue
            extras[f"src/{p.name}"] = p.read_text(encoding="utf-8")
    return extras
