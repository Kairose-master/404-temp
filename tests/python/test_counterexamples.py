#!/usr/bin/env python3
"""Official run-only counterexamples. Needs solc 0.8.24."""
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

FIX = ROOT / "tests" / "fixtures" / "counterexamples"


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


def _case(name):
    base = FIX / name
    man = json.loads((base / "manifest.json").read_text())
    from trust404.abi import load_extra_sources
    extras = load_extra_sources(base / "manifest.json", base / man["target"]["src"], man)
    from verify import verify_full
    return verify_full(
        target_name=man["target"]["name"],
        target_src=(base / man["target"]["src"]).read_text(),
        invariants_src=(base / man["invariants"]["contract"]).read_text(),
        exploit_src=(base / "Exploit.sol").read_text(),
        manifest=man,
        seed=42,
        extra_sources=extras or None,
    )


@unittest.skipUnless(_solc(), "solc 0.8.24 not installed")
class OfficialRunOnly(unittest.TestCase):
    def test_setup_only_owner_is_proven(self):
        r = _case("SetupOnlyOwner")
        self.assertTrue(r.proven, r.detail)
        self.assertEqual(r.violated, "ownerUnchanged")

    def test_phased_ghost_empty_run_is_not_proven(self):
        r = _case("PhasedGhost")
        self.assertFalse(r.proven, r.detail)

    def test_approval_mirage_hevm_setup_is_inconclusive(self):
        # Keep the original fixture: vm.addr is unsupported in py-evm.
        # Its old negative result relied on the constructor fallback.
        from verify import SetupDeploymentError
        with patch.dict(os.environ, {"TRUST404_VERIFIER": "evm"}):
            with self.assertRaisesRegex(SetupDeploymentError, "Setup.run reverted"):
                _case("ApprovalMirage")

    def test_approval_mirage_without_approval_is_not_proven(self):
        # Separate EVM-compatible Setup, identical target/token/exploit/invariant.
        # An exception does NOT count as a negative result for this control.
        r = _case("ApprovalMiragePlainSetup")
        self.assertFalse(r.proven, r.detail)
