"""Foundry cheatcode snippets used inside IExploit.run(address).

The official harness is still one `run()` call. Foundry exposes the HEVM
address to *any* contract in the test (Setup.s.sol already uses
`vm.deal`). An exploit can therefore `warp` / `prank` mid-run on the
forge scoring path.

The py-evm verifier does not hook 0x7109, so it instead runs
`prepare → time_travel → finish` when those functions exist
(`agent/verify.py`).
"""
from __future__ import annotations

import re

HEVM = "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D"

IFACE = (
    "interface IVm {\n"
    "    function warp(uint256) external;\n"
    "    function roll(uint256) external;\n"
    "    function prank(address) external;\n"
    "    function deal(address,uint256) external;\n"
    "}\n"
)

DECL = f"    IVm constant vm = IVm(address({HEVM}));\n"


def window_seconds(src: str) -> int:
    """Parse a TWAP window from source. Default 1 hour."""
    s = src or ""
    m = re.search(r"(\d+)\s+(seconds|minutes|hours|days)\b", s)
    if m:
        n = int(m.group(1))
        return n * {"seconds": 1, "minutes": 60, "hours": 3600, "days": 86400}[m.group(2)]
    m = re.search(
        r"(?:TWAP_|PERIOD|WINDOW|SECONDS_AGO|timeWindow|window)\w*\s*=\s*(\d+)",
        s, re.I)
    if m:
        n = int(m.group(1))
        return n if n >= 60 else n  # already seconds, or small cardinality
    return 3600
