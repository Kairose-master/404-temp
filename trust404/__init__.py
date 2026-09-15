"""TRUST404 exploit-prover engine package.

Layers:
  scan        — 7-family static scores (canonical)
  features    — capability IR extracted from source (generalized level-solvers)
  registry    — feature-gated synth providers
  targets     — load track fixtures from disk
  critique    — self-validation loop feedback for the next candidate
"""

from .scan import (  # noqa: F401
    FAM_ACCESS,
    FAM_DELEGATECALL,
    FAM_INIT,
    FAM_INTEGER,
    FAM_ORACLE,
    FAM_RANDOMNESS,
    FAM_REENTRANCY,
    STRATEGY_ORDER,
    scan_target,
)

__all__ = [
    "scan_target",
    "STRATEGY_ORDER",
    "FAM_REENTRANCY",
    "FAM_ACCESS",
    "FAM_INTEGER",
    "FAM_ORACLE",
    "FAM_DELEGATECALL",
    "FAM_RANDOMNESS",
    "FAM_INIT",
]