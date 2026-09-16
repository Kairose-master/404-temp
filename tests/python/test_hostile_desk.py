#!/usr/bin/env python3
"""HostileDesk — owner is slot 2, lottery mixes nonce+salt. No solc."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.features import extract_features
from trust404.layout import privileged_slot, pwn_hijack
from trust404.registry import should_run
from trust404.synth_defi import iter_defi_families

SRC = (ROOT / "examples/frontier/hostile/HostileDesk.sol").read_text()
BASE = ROOT / "examples/frontier/hostile"


class HostileDesk(unittest.TestCase):
    def test_files(self):
        for n in ("HostileDesk.sol", "Invariants.sol", "ExploitSlot.sol",
                  "ExploitMix.sol", "manifest.json", "README.md"):
            self.assertTrue((BASE / n).is_file(), n)

    def test_layout_is_hostile(self):
        f = extract_features(SRC, "HostileDesk")
        self.assertIn("owner_not_slot0", f)
        self.assertIn("delegatecall_param", f)
        self.assertIn("mixed_entropy", f)
        self.assertEqual(privileged_slot(SRC), 2)
        self.assertIn("pad1", pwn_hijack(2))
        self.assertTrue(should_run("owner_slot_hijack", f))
        self.assertTrue(should_run("mixed_entropy", f))

    def test_slot_synth_pads_two(self):
        body = next(s for l, s in iter_defi_families(SRC, "HostileDesk")
                    if l.startswith("owner-slot"))
        self.assertIn("pad0", body)
        self.assertIn("pad1", body)
        self.assertIn("slot2", body)
        self.assertNotIn("slot0 = msg.sender", body)

    def test_mix_synth_reads_nonce_and_salt(self):
        body = next(s for l, s in iter_defi_families(SRC, "HostileDesk")
                    if l.startswith("mixed-entropy"))
        self.assertIn("nonce()", body)
        self.assertIn("salt()", body)

    def test_hand_exploits_match_the_holes(self):
        slot = (BASE / "ExploitSlot.sol").read_text()
        mix = (BASE / "ExploitMix.sol").read_text()
        self.assertIn("pad1", slot)
        self.assertIn("sweep()", slot)
        self.assertIn("nonce()", mix)
        self.assertIn("salt()", mix)
        self.assertNotIn("withdraw()", slot)
        self.assertNotIn("withdraw()", mix)

    def test_invariants_and_manifest(self):
        inv = (BASE / "Invariants.sol").read_text()
        self.assertIn("ownerUnchanged", inv)
        self.assertIn("houseAlive", inv)
        man = json.loads((BASE / "manifest.json").read_text())
        self.assertEqual(man["target"]["name"], "HostileDesk")
        self.assertEqual(man["frontier"]["expect"], "theft")
        self.assertEqual(man["frontier"]["class"], "hostile-layout")

    def test_honest_withdraw_is_cei(self):
        # debit before the call — not the DualSurface bug
        self.assertIn("totalDeposits -= b", SRC)
        withdraw = SRC.split("function withdraw")[1].split("function execute")[0]
        debit = withdraw.find("deposits[msg.sender] = 0")
        call = withdraw.find(".call{value")
        self.assertGreater(call, debit)
        self.assertGreater(debit, -1)
