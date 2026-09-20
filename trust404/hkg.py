"""Hierarchical Knowledge Graph — protocol → cause → primitive.

EvoPoC (arXiv:2605.02868) argued exploit synthesis is not code generation
but structured reasoning over (protocol semantics, failure root cause,
exploit primitive). Our v0.2 registry was a flat OR of capability tags.
This graph is that registry lifted one level.

It does not claim EvoPoC's SMT+asset simulation. It *does* give the
engine a ranked path so `iter_engine_candidates` tries the primitive that
the protocol shape actually licenses, and so we can point at the unsolved
bit: the graph is still *intra-protocol*. Cross-protocol composition
(Euler, Kyberswap, Beanstalk-on-Aave) is docs/FRONTIER.md §2.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple


# ── L1 protocol semantics ──────────────────────────────────────────────────
PROTOCOLS: Dict[str, Set[str]] = {
    "amm": {"swap", "dex_spot_swap", "spot_price", "oracle", "swap_unverified_token"},
    "lending": {"flashloan", "unpermissioned_flashloan", "stake", "fake_weth"},
    "governance": {"governance_flashloan", "execute_before_schedule"},
    "vault": {"value_call", "cei_violation", "reentrancy_mutex", "private_unlock"},
    "proxy": {
        "fallback_delegatecall", "delegatecall_param", "delegatecall_stored_lib",
        "unguarded_initialize", "proxy_admin", "nested_multicall",
        "slot_alias_max_balance",
    },
    "token": {"approve_transferFrom", "lockup", "donation_accounting_dos"},
    "access": {"unguarded_owner_write", "construct0r", "send_gate", "tx_origin_eoa_gate"},
    "gate": {
        "gasleft_modulo", "tx_origin_mask", "extcodesize_zero", "xor_extcodehash_key",
        "solver_size_gate",
    },
    "callback": {
        "unpermissioned_callback", "view_callback_twice", "view_price_callback",
        "custom_error_catch", "receiver_hook", "receiver_hook_before_mint",
        "withdraw_to_partner",
    },
    "evm_quirk": {
        "calldata_fullword_sstore", "narrow_abi_param", "selector_offset_check",
        "array_length_unchecked", "packed_id_overflow", "packed_storage_write",
        "forced_ether", "selfdestruct", "no_receive", "ecrecover",
        "commit_hash_loop", "block_entropy", "raw_calldata", "create2_predict",
        "push_send", "push_refund_role",
    },
}

# ── L2 root causes ─────────────────────────────────────────────────────────
CAUSES: Dict[str, Set[str]] = {
    "cei": {"cei_violation", "value_call"},
    "missing_access": {
        "unguarded_owner_write", "unguarded_initialize", "unpermissioned_callback",
        "unpermissioned_flashloan", "construct0r",
    },
    "accounting_desync": {"donation_accounting_dos", "fake_weth", "stake"},
    "oracle_spot": {"spot_price", "oracle", "dex_spot_swap", "swap"},
    "delegate_confusion": {
        "delegatecall_param", "delegatecall_stored_lib", "fallback_delegatecall",
        "proxy_admin", "nested_multicall",
    },
    "trust_callback": {
        "view_callback_twice", "view_price_callback", "custom_error_catch",
        "receiver_hook_before_mint", "unpermissioned_callback",
    },
    "entropy_leak": {"block_entropy"},
    "abi_width": {
        "calldata_fullword_sstore", "narrow_abi_param", "selector_offset_check",
        "packed_id_overflow", "packed_storage_write", "raw_calldata",
    },
    "push_payment": {"push_refund_role", "push_send", "withdraw_to_partner"},
    "init_race": {"unguarded_initialize", "construct0r"},
    "sig_malleability": {"ecrecover"},
    "storage_alias": {"array_length_unchecked", "slot_alias_max_balance", "private_unlock"},
    "gas_gate": {"gasleft_modulo", "extcodesize_zero", "solver_size_gate"},
    "governance_flash": {"governance_flashloan", "execute_before_schedule", "flashloan"},
}

# ── L3 primitives → registry fn_name ───────────────────────────────────────
# (protocol, cause, primitive/fn_name, weight)
EDGES: List[Tuple[str, str, str, float]] = [
    ("vault", "cei", "_storage_attempt", 0.2),  # not really, keep low
    ("vault", "cei", "reentrancy", 1.0),
    ("vault", "storage_alias", "_storage_attempt", 0.9),
    ("proxy", "delegate_confusion", "_proxy_attempt", 1.0),
    ("proxy", "delegate_confusion", "_synth_storage_collision", 0.9),
    ("proxy", "delegate_confusion", "_synth_puzzle_wallet", 1.0),
    ("proxy", "init_race", "_synth_uninitialized", 1.0),
    ("access", "init_race", "_synth_uninitialized", 0.8),
    ("access", "missing_access", "_synth_gatekeeper_three", 0.6),
    ("gate", "gas_gate", "_synth_gatekeeper_one", 1.0),
    ("gate", "gas_gate", "_synth_gatekeeper_two", 0.9),
    ("gate", "gas_gate", "_synth_magicnumber", 0.7),
    ("callback", "trust_callback", "_synth_callback_inconsistency", 0.9),
    ("callback", "trust_callback", "_synth_shop", 0.8),
    ("callback", "trust_callback", "_synth_good_samaritan", 0.7),
    ("callback", "trust_callback", "_synth_eip7702_reentrancy", 0.7),
    ("callback", "missing_access", "unpermissioned_callback", 1.0),
    ("lending", "missing_access", "unpermissioned_callback", 0.9),
    ("lending", "accounting_desync", "_synth_stake_accounting", 0.8),
    ("token", "accounting_desync", "donation_accounting_dos", 1.0),
    ("token", "missing_access", "_synth_lockup_bypass", 0.8),
    ("amm", "oracle_spot", "_synth_dex_drain", 1.0),
    ("amm", "oracle_spot", "_synth_dex_two_drain", 0.9),
    ("governance", "governance_flash", "governance_flashloan", 1.0),
    ("governance", "governance_flash", "execute_before_schedule", 1.0),
    ("evm_quirk", "abi_width", "_synth_higher_order", 0.9),
    ("evm_quirk", "abi_width", "_synth_switch", 0.8),
    ("evm_quirk", "abi_width", "_synth_magic_carousel", 0.7),
    ("evm_quirk", "storage_alias", "_synth_array_underflow", 0.9),
    ("evm_quirk", "push_payment", "_synth_king_dos", 0.9),
    ("evm_quirk", "push_payment", "_synth_gas_griefing", 0.7),
    ("evm_quirk", "entropy_leak", "_multiblock_attempt", 1.0),
    ("evm_quirk", "sig_malleability", "_synth_ecdsa_malleability", 1.0),
    ("evm_quirk", "cei", "_synth_force", 0.4),
    ("vault", "push_payment", "_synth_force", 0.5),
]


@dataclass(frozen=True)
class Path:
    protocol: str
    cause: str
    primitive: str
    weight: float
    matched_features: Tuple[str, ...]


@dataclass
class HKGMatch:
    protocols: List[str]
    causes: List[str]
    paths: List[Path] = field(default_factory=list)
    ranked_primitives: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "protocols": self.protocols,
            "causes": self.causes,
            "paths": [
                {
                    "protocol": p.protocol,
                    "cause": p.cause,
                    "primitive": p.primitive,
                    "weight": p.weight,
                    "matched": list(p.matched_features),
                }
                for p in self.paths[:12]
            ],
            "ranked_primitives": self.ranked_primitives,
        }


def infer_protocols(features: Set[str]) -> List[str]:
    hits = []
    for proto, tags in PROTOCOLS.items():
        n = len(tags & features)
        if n:
            hits.append((n, proto))
    hits.sort(key=lambda x: (-x[0], x[1]))
    return [p for _, p in hits]


def infer_causes(features: Set[str]) -> List[str]:
    hits = []
    for cause, tags in CAUSES.items():
        n = len(tags & features)
        if n:
            hits.append((n, cause))
    hits.sort(key=lambda x: (-x[0], x[1]))
    return [c for _, c in hits]


def lift(features: Optional[Set[str]]) -> HKGMatch:
    """Lift a flat feature set onto the three-layer graph."""
    feats = set(features or [])
    protos = infer_protocols(feats)
    causes = infer_causes(feats)
    proto_set, cause_set = set(protos), set(causes)
    paths: List[Path] = []
    for proto, cause, prim, w in EDGES:
        if proto not in proto_set or cause not in cause_set:
            continue
        matched = tuple(sorted((PROTOCOLS[proto] | CAUSES[cause]) & feats))
        if not matched:
            continue
        # density bonus: more overlapping tags → more confident
        dens = len(matched) / max(1, len(CAUSES[cause]))
        paths.append(Path(proto, cause, prim, round(w * (0.5 + 0.5 * dens), 3), matched))
    paths.sort(key=lambda p: (-p.weight, p.primitive))
    ranked: List[str] = []
    seen = set()
    for p in paths:
        if p.primitive not in seen:
            seen.add(p.primitive)
            ranked.append(p.primitive)
    return HKGMatch(protocols=protos, causes=causes, paths=paths, ranked_primitives=ranked)


def should_run_hkg(fn_name: str, features: Optional[Set[str]]) -> bool:
    """Stricter than registry.should_run: require a graph path.

    Unknown primitives still run (forward-compat). Empty features skip
    specialized synths — same contract as the flat registry.
    """
    if features is None:
        return True
    from .registry import _BY_FN, should_run
    spec = _BY_FN.get(fn_name)
    if spec is None:
        return True
    if not should_run(fn_name, features):
        return False
    m = lift(features)
    if fn_name in m.ranked_primitives:
        return True
    # Fall back to the provider's precise any/all/none capability gate.
    return True


def order_by_hkg(fn_names: Sequence[str], features: Optional[Set[str]]) -> List[str]:
    """Stable reorder: HKG-ranked first, then the original tail."""
    if not features:
        return list(fn_names)
    rank = {n: i for i, n in enumerate(lift(features).ranked_primitives)}
    head = sorted((n for n in fn_names if n in rank), key=lambda n: rank[n])
    tail = [n for n in fn_names if n not in rank]
    return head + tail
