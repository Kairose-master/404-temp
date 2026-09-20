"""Stable candidate identities used to avoid redundant verification.

The scoring loop may receive equivalent Solidity from more than one provider.
Comments, formatting and pragma spelling are irrelevant to the execution, so
they must not consume another expensive Forge attempt.
"""
from __future__ import annotations

import hashlib
import random
import re
from typing import Iterable, Iterator, Sequence

from .scan import (
    FAM_ACCESS,
    FAM_DELEGATECALL,
    FAM_INIT,
    FAM_INTEGER,
    FAM_ORACLE,
    FAM_RANDOMNESS,
    FAM_REENTRANCY,
)


_FAMILY_EVIDENCE = {
    FAM_REENTRANCY: ("reentrancy_deposit", "reentrancy_withdraw"),
    FAM_ACCESS: ("access_drain", "access_setowner"),
    FAM_INTEGER: ("integer_transfer", "integer_redeem"),
    FAM_ORACLE: ("oracle_faucet", "oracle_swap", "oracle_deposit", "oracle_borrow"),
    FAM_DELEGATECALL: ("delegatecall_entry",),
    FAM_RANDOMNESS: ("randomness_fn",),
    FAM_INIT: ("init_fn",),
}

_FAMILY_EFFECTS = {
    FAM_REENTRANCY: {"native_balance"},
    FAM_ACCESS: {"native_balance", "privilege"},
    FAM_INTEGER: {"native_balance", "accounting"},
    FAM_ORACLE: {"debt", "collateral", "token_balance"},
    FAM_DELEGATECALL: {"privilege", "storage"},
    FAM_RANDOMNESS: {"native_balance"},
    FAM_INIT: {"privilege", "storage"},
}


def normalize_candidate(source: str) -> str:
    """Return a deterministic, formatting-insensitive Solidity form.

    This intentionally stays conservative: it removes comments, SPDX/pragma
    lines and whitespace, but does not rename identifiers or reorder calls.
    Distinct argument expressions therefore remain distinct candidates.
    """
    src = source or ""
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    src = re.sub(r"\bpragma\s+solidity\s+[^;]+;", "", src)
    src = re.sub(r"\s+", "", src)
    return src


def candidate_fingerprint(source: str) -> str:
    """Hash the executable candidate shape for cross-provider de-duplication."""
    return hashlib.sha256(normalize_candidate(source).encode("utf-8")).hexdigest()


def invariant_dependencies(source: str) -> set[str]:
    """Extract the state classes observed by the supplied invariants."""
    src = source or ""
    deps: set[str] = set()
    if re.search(r"\btarget\s*\.\s*balance\b|address\s*\([^)]*target[^)]*\)\s*\.balance", src):
        deps.add("native_balance")
    if re.search(r"\b(?:owner|admin|governor|guardian|operator)\s*\(", src, re.I):
        deps.add("privilege")
    if re.search(r"\btotalDebt\s*\(|\bdebt(?:Of)?\s*\(", src, re.I):
        deps.add("debt")
    if re.search(r"\btotalCollateral\s*\(|\bcollateral(?:Of)?\s*\(", src, re.I):
        deps.add("collateral")
    if re.search(r"\btotalSupply\s*\(", src):
        deps.add("supply")
    if re.search(r"\bbalanceOf\s*\(", src):
        deps.add("token_balance")
    return deps


def family_evidence(findings: dict, family: str) -> tuple[str, ...]:
    return tuple(key for key in _FAMILY_EVIDENCE.get(family, ()) if findings.get(key))


def candidate_effects(stage: str, label: str, findings: dict | None = None) -> set[str]:
    if label in _FAMILY_EFFECTS:
        effects = set(_FAMILY_EFFECTS[label])
        if label == FAM_ACCESS and findings:
            effects = set()
            if findings.get("access_drain"):
                effects.add("native_balance")
            if findings.get("access_setowner"):
                effects.add("privilege")
        return effects
    text = (label or "").lower()
    effects: set[str] = set()
    if any(word in text for word in ("reent", "drain", "withdraw", "lottery", "random")):
        effects.add("native_balance")
    if any(word in text for word in ("owner", "admin", "slot", "delegate", "init", "proxy")):
        effects.update({"privilege", "storage"})
    if any(word in text for word in ("oracle", "amm", "swap", "collateral", "borrow", "flash")):
        effects.update({"debt", "collateral", "token_balance"})
    if "supply" in text or "mint" in text:
        effects.add("supply")
    return effects


def candidate_profile(stage: str, label: str, findings: dict,
                      dependencies: set[str], features: Iterable[str] = ()) -> dict:
    """Return deterministic ranking/explanation metadata for one candidate."""
    evidence = list(family_evidence(findings, label))
    if not evidence and stage not in {"template", "llm"}:
        evidence = sorted(set(features))[:12]
    required = _FAMILY_EVIDENCE.get(label, ())
    completeness = (len(evidence) / len(required)) if required else (1.0 if evidence else 0.5)
    effects = candidate_effects(stage, label, findings)
    dependency_hits = sorted(effects & set(dependencies))
    base = {"template": 0.68, "synth": 0.58, "world": 0.52,
            "fuzz": 0.48, "llm": 0.45, "baseline": 1.0}.get(stage, 0.5)
    score = float((findings.get("scores") or {}).get(label, 0))
    confidence = min(0.99, base + min(score, 10.0) * 0.02
                     + completeness * 0.12 + (0.1 if dependency_hits else 0.0))
    cost = {"template": 1, "llm": 2, "synth": 3,
            "world": 4, "fuzz": 5, "baseline": 1}.get(stage, 3)
    return {
        "confidence": round(confidence, 3),
        "evidence": evidence,
        "estimated_effect": sorted(effects),
        "invariant_overlap": dependency_hits,
        "cost": cost,
    }


def rank_template_families(families: Sequence[str], findings: dict,
                           dependencies: set[str], seed: int) -> list[str]:
    """Rank complete, invariant-relevant evidence before seeded tie breaks."""
    rng = random.Random(seed)
    shuffled = sorted(families)
    rng.shuffle(shuffled)
    tie = {family: idx for idx, family in enumerate(shuffled)}

    def key(family: str):
        score = (findings.get("scores") or {}).get(family, 0)
        required = _FAMILY_EVIDENCE.get(family, ())
        evidence = family_evidence(findings, family)
        completeness = len(evidence) / len(required) if required else 0.0
        overlap = len(candidate_effects("template", family, findings) & dependencies)
        return (-score, -overlap, -completeness, tie[family], family)

    return sorted(families, key=key)


def schedule_candidates(candidates: Iterable[tuple], max_attempts: int,
                        metrics: dict | None = None) -> Iterator[tuple]:
    """Reserve validation slots for deeper stages, then reuse unused slots.

    Input order within each stage remains stable. Deferred candidates are only
    emitted after the raw stream reaches fuzz/exhaustion, so low-confidence
    templates cannot starve deeper search.
    """
    if max_attempts <= 0:
        return
    if max_attempts == 1:
        caps = {"template": 1, "synth": 0, "fuzz": 0}
    elif max_attempts == 2:
        caps = {"template": 1, "synth": 0, "fuzz": 1}
    else:
        caps = {"template": max_attempts - 2, "synth": 1, "fuzz": 1}
    used = {key: 0 for key in caps}
    deferred = []
    yielded = 0

    def bucket(stage: str) -> str:
        if stage in {"llm", "template"}:
            return "template"
        if stage in {"synth", "world"}:
            return "synth"
        return "fuzz" if stage == "fuzz" else "synth"

    for candidate in candidates:
        group = bucket(candidate[0])
        if used[group] < caps[group] and yielded < max_attempts:
            used[group] += 1
            yielded += 1
            yield candidate
        else:
            deferred.append(candidate)
            if metrics is not None:
                metrics["deferred"] = metrics.get("deferred", 0) + 1
    for candidate in deferred:
        if yielded >= max_attempts:
            return
        yielded += 1
        yield candidate
