"""CTF victim EOAs whose *key is derivable* without cheatcodes.

Foundry `makeAddr(name)` / `makeAddrAndKey(name)` (forge-std StdUtils):

    privateKey = uint256(keccak256(abi.encodePacked(name)));
    addr       = vm.addr(privateKey);   // secp256k1

abi.encodePacked(string) is the raw UTF-8 bytes. So keccak256("alice")
is the private key. The official harness still only calls run(address)
as the Exploit — this module is for the *verifier* to send a real
signed tx (approve/permit) from that key before run(), which is what
Setup.s.sol already did if the hidden set used makeAddr.

A random 0x… EOA with no derivation remains impossible.
"""
from __future__ import annotations

import re
from typing import List, Tuple

MAKE_ADDR = re.compile(r"makeAddr(?:AndKey)?\s*\(\s*\"([^\"]+)\"\s*\)")


def make_addr_names(src: str) -> List[str]:
    return list(dict.fromkeys(MAKE_ADDR.findall(src or "")))


def private_key_bytes(name: str) -> bytes:
    """keccak256(name) as 32 bytes. Empty if no keccak lib."""
    data = (name or "").encode("utf-8")
    try:
        from eth_hash.auto import keccak
        return bytes(keccak(data))
    except Exception:
        pass
    try:
        from sha3 import keccak_256
        return keccak_256(data).digest()
    except Exception:
        pass
    try:
        from Crypto.Hash import keccak as kmod
        k = kmod.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except Exception:
        return b""


def account_from_name(name: str):
    """Return (address, key_hex) or None if crypto libs missing."""
    pk = private_key_bytes(name)
    if len(pk) != 32:
        return None
    try:
        from eth_account import Account
        acct = Account.from_key(pk)
        return acct.address, "0x" + pk.hex()
    except Exception:
        return None


def derived_accounts(*blobs: str) -> List[Tuple[str, str, str]]:
    """[(name, address, key_hex), ...] for every makeAddr in the blobs."""
    names: List[str] = []
    for b in blobs:
        names.extend(make_addr_names(b))
    out = []
    seen = set()
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        got = account_from_name(n)
        if got:
            out.append((n, got[0], got[1]))
    return out
