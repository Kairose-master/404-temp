"""Self-validation loop critique — feed failures into the next candidate.

PoCo (ACM TOSEM, arXiv:2511.02780) and A1 (arXiv:2507.05558) both treat
compile/test stderr as the *search signal*, not just a log line. We keep
the track's deterministic template/synth/fuzz backbone and only use this
structure to (a) record richer result.json and (b) condition an optional
LLM retry.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Critique:
    stage: str
    label: str
    held: str = ""
    error: str = ""
    source_head: str = ""
    features: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


def format_for_llm(critiques: List[Critique], predicates: Optional[List[str]] = None) -> str:
    """Compact critique block to append to an LLM prompt (temperature=0)."""
    lines = [
        "Previous candidates FAILED to break invariants. Do not repeat them.",
        "Invariants still holding: " + ", ".join(predicates or []),
        "Failed attempts:",
    ]
    for i, c in enumerate(critiques[-6:], 1):
        lines.append(
            f"{i}. stage={c.stage} strategy={c.label} held={c.held[:180]} err={c.error[:120]}"
        )
        if c.source_head:
            lines.append("   exploit head: " + c.source_head.replace("\n", " ")[:240])
    lines.append(
        "Produce a DIFFERENT Exploit.sol that targets a still-held predicate. "
        "Keep `contract Exploit { function run(address target) external payable; }`."
    )
    return "\n".join(lines)
