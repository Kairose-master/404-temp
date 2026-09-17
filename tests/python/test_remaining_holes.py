#!/usr/bin/env python3
"""Official run-only results for the remaining-hole fixtures. Needs solc 0.8.24."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

FIX = ROOT / "tests" / "fixtures" / "counterexamples"

CLOSED = [
    ("TimeAhead", "NOT_PROVEN"),
    ("BlockLow", "NOT_PROVEN"),
    ("TimeExact", "PROVEN"),
    ("WarpInRun", "PROVEN"),
    ("SetupDealVault", "PROVEN"),
    ("SetupTwoCreates", "PROVEN"),
]


def _solc():
    try:
        import solcx
        solcx.set_solc_version("0.8.24")
        return True
    except Exception:
        try:
            import solcx
            solcx.install_solc("0.8.24")
            solcx.set_solc_version("0.8.24")
            return True
        except Exception:
            return False


def _run(name):
    base = FIX / name
    man = json.loads((base / "manifest.json").read_text())
    from trust404.abi import load_extra_sources
    extras = load_extra_sources(base / "manifest.json", base / man["target"]["src"], man)
    from verify import verify_full
    try:
        r = verify_full(
            man["target"]["name"],
            (base / man["target"]["src"]).read_text(),
            (base / man["invariants"]["contract"]).read_text(),
            (base / "Exploit.sol").read_text(),
            man, 42, extras or None,
        )
        return "PROVEN" if r.proven else "NOT_PROVEN", r
    except Exception as e:
        return "ERROR", e


@unittest.skipUnless(_solc(), "solc 0.8.24 not installed")
class ClosedHoles(unittest.TestCase):
    def test_pyevm_matches_official(self):
        for name, official in CLOSED:
            with self.subTest(name=name):
                got, detail = _run(name)
                self.assertEqual(got, official, detail)
