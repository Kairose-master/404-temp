"""Load track targets from disk so api/prove.py does not embed sources twice."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional

ROOT = Path(__file__).resolve().parent.parent
TARGETS_DIR = ROOT / "targets"


def load_target(name: str, root: Optional[Path] = None) -> Optional[dict]:
    base = (root or TARGETS_DIR) / name
    src_path = base / "src" / f"{name}.sol"
    inv_path = base / "Invariants.sol"
    man_path = base / "manifest.json"
    if not src_path.exists():
        return None
    out = {
        "src": src_path.read_text(encoding="utf-8"),
        "inv": inv_path.read_text(encoding="utf-8") if inv_path.exists() else "",
        "manifest": {},
    }
    if man_path.exists():
        out["manifest"] = json.loads(man_path.read_text(encoding="utf-8"))
    return out


def load_all(root: Optional[Path] = None) -> Dict[str, dict]:
    base = root or TARGETS_DIR
    if not base.is_dir():
        return {}
    found: Dict[str, dict] = {}
    for child in sorted(base.iterdir()):
        if not child.is_dir():
            continue
        t = load_target(child.name, base)
        if t:
            found[child.name] = t
    return found
