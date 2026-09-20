# Thin wrapper — canonical scanner lives in trust404.scan.
import sys
from pathlib import Path

_root = Path(__file__).resolve().parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from trust404.scan import (  # noqa: F401
    FAM_ACCESS,
    FAM_DELEGATECALL,
    FAM_INIT,
    FAM_INTEGER,
    FAM_ORACLE,
    FAM_RANDOMNESS,
    FAM_REENTRANCY,
    STRATEGY_ORDER,
    _ENTROPY_TOKENS,
    _contract_bodies,
    _extract_block,
    _functions,
    _has_privilege_guard,
    _has_owner_guard,
    _reentrancy_vulnerable,
    _strip_comments,
    scan_target,
)
