"""Official ERC surfaces the engine can call without target source.

Selectors are the 4-byte identifiers from the ERC specs (ethereum/ERCs):

    ERC-20    transfer/approve/transferFrom/balanceOf
    ERC-2612  permit(owner,spender,value,deadline,v,r,s)  — Permit typehash
    ERC-165   supportsInterface(bytes4)
    ERC-721   ownerOf / safeTransferFrom / onERC721Received
    ERC-777   tokensReceived
    ERC-1155  safeTransferFrom
    ERC-1271  isValidSignature(bytes32,bytes)
    ERC-4626  deposit/mint/withdraw/redeem/convertToShares/totalAssets/asset
    ERC-3156  flashLoan / onFlashLoan
    ERC-1967  implementation slot
    WETH      deposit() / withdraw(uint256)  (canonical wrapped-native)

Unknown bytecode is classified by PUSH4 selectors, then the matching
interface is what `run(address)` calls. Not a decompiler.
"""
from __future__ import annotations

import re
from typing import Dict, List, Set

# Well-known 4-byte selectors (keccak of the canonical signature, first 4 bytes).
SELECTORS: Dict[str, str] = {
    # ERC-20
    "70a08231": "balanceOf(address)",
    "a9059cbb": "transfer(address,uint256)",
    "095ea7b3": "approve(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "18160ddd": "totalSupply()",
    "dd62ed3e": "allowance(address,address)",
    # ERC-2612
    "d505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "7ecebe00": "nonces(address)",
    "3644e515": "DOMAIN_SEPARATOR()",
    # ERC-165
    "01ffc9a7": "supportsInterface(bytes4)",
    # ERC-721
    "6352211e": "ownerOf(uint256)",
    "42842e0e": "safeTransferFrom(address,address,uint256)",
    "150b7a02": "onERC721Received(address,address,uint256,bytes)",
    # ERC-1271
    "1626ba7e": "isValidSignature(bytes32,bytes)",
    # ERC-4626 (deposit(uint256,address) etc.)
    "38d52e0f": "asset()",
    "01e1d114": "totalAssets()",
    "c6e6f592": "convertToShares(uint256)",
    "07a2d13a": "convertToAssets(uint256)",
    "6e553f65": "deposit(uint256,address)",
    "94bf804d": "mint(uint256,address)",
    "b460af94": "withdraw(uint256,address,address)",
    "ba087652": "redeem(uint256,address,address)",
    # ERC-3156
    "5cffe9de": "flashLoan(address,address,uint256,bytes)",
    "23e30c8b": "onFlashLoan(address,address,uint256,uint256,bytes)",
    # WETH
    "d0e30db0": "deposit()",
    "2e1a7d4d": "withdraw(uint256)",
    # Uniswap V2 pair (de-facto, not an ERC)
    "022c0d9f": "swap(uint256,uint256,address,bytes)",
    "0902f1ac": "getReserves()",
    "0dfe1681": "token0()",
    "d21220a7": "token1()",
}

ERC20_NEED = {"a9059cbb", "70a08231", "095ea7b3"}
ERC4626_NEED = {"6e553f65", "c6e6f592", "01e1d114"}
FLASH_NEED = {"5cffe9de"}
UNIV2_NEED = {"022c0d9f", "0902f1ac"}
PERMIT_NEED = {"d505accf"}


def selectors_from_bytecode(code: bytes) -> Set[str]:
    """PUSH4 immediates. False positives exist; enough to pick an ERC family."""
    out: Set[str] = set()
    if not code:
        return out
    i = 0
    n = len(code)
    while i < n:
        op = code[i]
        if op == 0x63 and i + 4 < n:  # PUSH4
            out.add(code[i + 1:i + 5].hex())
            i += 5
            continue
        i += 1
    return out


def classify(selectors: Set[str]) -> List[str]:
    tags = []
    s = {x.lower() for x in selectors}
    if ERC20_NEED & s:
        tags.append("erc20")
    if PERMIT_NEED & s:
        tags.append("erc2612")
    if ERC4626_NEED & s:
        tags.append("erc4626")
    if FLASH_NEED & s:
        tags.append("erc3156")
    if UNIV2_NEED & s:
        tags.append("univ2")
    if "6352211e" in s:
        tags.append("erc721")
    if "1626ba7e" in s:
        tags.append("erc1271")
    return tags


def hardcoded_addresses(src: str) -> List[str]:
    skip = {
        "7109709ecfa91a80626ff3989d68f67f5b1dd12d",
        "0000000000000000000000000000000000000000",
        "ffffffffffffffffffffffffffffffffffffffff",
    }
    out = []
    for m in re.finditer(r"0x([a-fA-F0-9]{40})", src or ""):
        h = m.group(1).lower()
        if h not in skip and h not in out:
            out.append("0x" + h)
    return out


IFACE_ERC20 = (
    "interface IERC20 {\n"
    "    function balanceOf(address) external view returns (uint256);\n"
    "    function transfer(address,uint256) external returns (bool);\n"
    "    function approve(address,uint256) external returns (bool);\n"
    "    function transferFrom(address,address,uint256) external returns (bool);\n"
    "    function allowance(address,address) external view returns (uint256);\n"
    "    function permit(address,address,uint256,uint256,uint8,bytes32,bytes32) external;\n"
    "}\n"
)

IFACE_4626 = (
    "interface IERC4626 {\n"
    "    function asset() external view returns (address);\n"
    "    function totalAssets() external view returns (uint256);\n"
    "    function convertToShares(uint256) external view returns (uint256);\n"
    "    function deposit(uint256,address) external returns (uint256);\n"
    "    function redeem(uint256,address,address) external returns (uint256);\n"
    "}\n"
)

IFACE_3156 = (
    "interface IERC3156 {\n"
    "    function flashLoan(address,address,uint256,bytes calldata) external returns (bool);\n"
    "}\n"
)

IFACE_UNIV2 = (
    "interface IUniV2 {\n"
    "    function swap(uint256,uint256,address,bytes calldata) external;\n"
    "    function token0() external view returns (address);\n"
    "    function token1() external view returns (address);\n"
    "    function getReserves() external view returns (uint112,uint112,uint32);\n"
    "}\n"
)
