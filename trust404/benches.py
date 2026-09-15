"""Public-bench adapters — VERITE / SCONE / EVMbench / track-04 / frontier fixtures.

We do **not** vendor those datasets (licenses, fork-state size, contamination
risk). This module:

  * describes how to attach an upstream tree (env dirs)
  * always runs the *local* class fixtures under benches/fixtures/
    (profit vs grief vs intended_path vs cross-contract)
  * emits a score table the engine can grow into as datasets are attached

Honest default: `python -m trust404.benches` scores local fixtures only
and prints NOT_ATTACHED for upstream sets. Claiming VERITE 63% without
the tree would be a lie.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "benches" / "fixtures"
MANIFEST = ROOT / "benches" / "manifest.json"


@dataclass
class Dataset:
    id: str
    title: str
    paper: str
    metric: str
    n: int
    attach_env: str
    path: str = ""
    note: str = ""

    @property
    def attached(self) -> bool:
        if self.path:
            return Path(self.path).exists()
        env = os.environ.get(self.attach_env, "")
        return bool(env) and Path(env).exists()

    @property
    def root(self) -> Optional[Path]:
        if self.path and Path(self.path).exists():
            return Path(self.path)
        env = os.environ.get(self.attach_env, "")
        return Path(env) if env and Path(env).exists() else None


def load_manifest() -> dict:
    if MANIFEST.exists():
        return json.loads(MANIFEST.read_text(encoding="utf-8"))
    return {"datasets": []}


def datasets() -> List[Dataset]:
    raw = load_manifest().get("datasets", [])
    out = []
    for d in raw:
        out.append(Dataset(
            id=d["id"], title=d.get("title", d["id"]), paper=d.get("paper", ""),
            metric=d.get("metric", ""), n=int(d.get("n") or 0),
            attach_env=d.get("attach_env", ""),
            path=d.get("path", ""),
            note=d.get("note", ""),
        ))
    return out


def local_fixtures() -> List[Path]:
    if not FIXTURES.exists():
        return []
    return sorted(p for p in FIXTURES.iterdir() if p.is_dir() and (p / "manifest.json").exists())


def score_fixture(path: Path) -> dict:
    """Static score: lift HKG + classify expected label from manifest. No solc."""
    from .features import extract_features
    from .hkg import lift
    from .world import plan_world
    from .profit import THEFT, GRIEF, INTENDED_PATH, NONE

    man = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    name = man["target"]["name"]
    src_rel = man["target"]["src"]
    src = (path / src_rel).read_text(encoding="utf-8")
    feats = extract_features(src, name)
    hkg = lift(feats)
    world = plan_world(src, name, feats)
    expect = man.get("frontier", {}).get("expect", NONE)
    return {
        "id": path.name,
        "target": name,
        "expect": expect,
        "features": sorted(feats),
        "protocols": hkg.protocols,
        "causes": hkg.causes,
        "ranked": hkg.ranked_primitives[:6],
        "cross_contract": world.cross_contract,
        "world_reason": world.reason,
        "attached": True,
    }


def summary() -> dict:
    ds = []
    for d in datasets():
        rec = asdict(d)
        rec["attached"] = d.attached
        rec["status"] = "ATTACHED" if d.attached else "NOT_ATTACHED"
        ds.append(rec)
    fixtures = [score_fixture(p) for p in local_fixtures()]
    return {
        "datasets": ds,
        "local_fixtures": fixtures,
        "n_local": len(fixtures),
        "n_attached_upstream": sum(1 for d in datasets() if d.attached and d.id not in
                                   ("track04", "frontier-local")),
    }


def main(argv=None):
    import pprint
    s = summary()
    print(json.dumps(s, indent=2, ensure_ascii=False))
    print()
    print("# upstream datasets attached:", s["n_attached_upstream"], "/",
          sum(1 for d in s["datasets"] if d["id"] not in ("track04", "frontier-local")))
    print("# local frontier fixtures:", s["n_local"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
