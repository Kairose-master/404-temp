#!/usr/bin/env python3
"""Open divergences vs official run-only _prove(). Needs solc 0.8.24.

Each row is a real counterexample: official harness result != py-evm.
When a row starts matching, drop it from OPEN and add it to OfficialRunOnly.
"""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

FIX = ROOT / "tests" / "fixtures" / "counterexamples"

# name, official, py-evm, kind
OPEN = [
    ("TimeAhead", "NOT_PROVEN", "PROVEN", "FP no warp, wall-clock"),
    ("BlockLow", "NOT_PROVEN", "PROVEN", "FP no roll, genesis block 0"),
    ("TimeExact", "PROVEN", "NOT_PROVEN", "FN frozen timestamp"),
    ("WarpInRun", "PROVEN", "NOT_PROVEN", "FN HEVM warp inside run()"),
    ("SetupDealVault", "PROVEN", "ERROR", "FN Setup vm.deal then empty ctor"),
    ("SetupTwoCreates", "PROVEN", "NOT_PROVEN", "FN CREATE nonce is Dummy"),
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
class RemainingHoles(unittest.TestCase):
    def test_each_open_hole_still_diverges(self):
        for name, official, ours, why in OPEN:
            with self.subTest(name=name):
                got, detail = _run(name)
                self.assertEqual(got, ours, f"{why}: {detail}")
                self.assertNotEqual(got, official, f"{name} unexpectedly matches official")
