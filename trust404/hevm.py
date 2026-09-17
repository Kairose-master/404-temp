"""Foundry HEVM surface for py-evm.

Official _prove warps/rolls then calls run() once. py-evm freezes
NUMBER/TIMESTAMP to the manifest and honours warp/roll/deal/addr at 0x7109.
Solidity 0.8 needs extcodesize>0 there, so genesis plants stub code.
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

_SEL_WARP = bytes.fromhex("e5d6bf02")
_SEL_ROLL = bytes.fromhex("1f7b4f30")
_SEL_DEAL = bytes.fromhex("c88a5e6d")
_SEL_ADDR = bytes.fromhex("ffa18649")

MNEMONIC = "test test test test test test test test test test test junk"


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
        return n if n >= 60 else n
    return 3600


def _word(data: bytes, i: int) -> int:
    sl = data[4 + 32 * i:4 + 32 * (i + 1)]
    return int.from_bytes(sl.rjust(32, b"\x00"), "big")


def make_backend(block_number: int, timestamp: int):
    """eth-tester backend with frozen NUMBER/TIMESTAMP and HEVM precompile."""
    from eth.vm.forks.prague import PragueVM
    from eth.vm.forks.prague.state import PragueState
    from eth.vm.forks.prague.computation import PragueComputation
    from eth_tester.backends.pyevm.main import PyEVMBackend, get_default_genesis_params
    from eth_utils import to_canonical_address

    box = {"block_number": int(block_number), "timestamp": int(timestamp)}
    hevm_addr = to_canonical_address(HEVM)

    def hevm(computation):
        data = bytes(computation.msg.data)
        sel = data[:4]
        if sel == _SEL_WARP:
            box["timestamp"] = _word(data, 0)
        elif sel == _SEL_ROLL:
            box["block_number"] = _word(data, 0)
        elif sel == _SEL_DEAL:
            addr = _word(data, 0).to_bytes(32, "big")[-20:]
            computation.state.set_balance(addr, _word(data, 1))
        elif sel == _SEL_ADDR:
            pk = _word(data, 0).to_bytes(32, "big")
            try:
                from eth_keys import keys
                out = keys.PrivateKey(pk).public_key.to_canonical_address()
            except Exception:
                out = b"\x00" * 20
            computation.output = b"\x00" * 12 + out
        return computation

    class Comp(PragueComputation):
        _precompiles = {**PragueComputation.get_precompiles(), hevm_addr: hevm}

    class State(PragueState):
        computation_class = Comp

        @property
        def timestamp(self):
            return int(box["timestamp"])

        @property
        def block_number(self):
            return int(box["block_number"])

    class VM(PragueVM):
        _state_class = State

    gs = PyEVMBackend.generate_genesis_state(
        mnemonic=MNEMONIC, overrides={"balance": 10**24}, num_accounts=10)
    gs[hevm_addr] = {"balance": 0, "nonce": 0, "code": b"\x00", "storage": {}}
    gp = get_default_genesis_params(overrides={"timestamp": int(timestamp)})
    backend = PyEVMBackend(
        genesis_parameters=gp,
        genesis_state=gs,
        vm_configuration=((0, VM),),
        mnemonic=MNEMONIC,
    )
    return backend, box
