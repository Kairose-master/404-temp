#!/usr/bin/env python3
"""Profit oracle — no solc. THEFT / GRIEF / INTENDED_PATH / NONE."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.profit import (
    BalanceSnap, INTENDED_PATH, GRIEF, NONE, THEFT,
    classify, report_from_snaps,
)


class ProfitOracle(unittest.TestCase):
    def test_theft(self):
        self.assertEqual(classify(True, 10**18), THEFT)

    def test_grief_no_extract(self):
        self.assertEqual(classify(True, 0), GRIEF)
        self.assertEqual(classify(True, -10), GRIEF)

    def test_intended_path_is_not_success(self):
        self.assertEqual(classify(False, 10**18), INTENDED_PATH)

    def test_none(self):
        self.assertEqual(classify(False, 0), NONE)

    def test_report_token_and_native(self):
        before = BalanceSnap(native_wei=10, tokens={"0xabc": 0})
        after = BalanceSnap(native_wei=15, tokens={"0xabc": 7})
        r = report_from_snaps(before, after, invariant_broken=True)
        self.assertEqual(r.classification, THEFT)
        self.assertEqual(r.extractable_wei, 5 + 7)
        d = r.as_dict()
        self.assertEqual(d["extractable_wei"], 12)

    def test_harness_funding_is_not_profit(self):
        before = BalanceSnap(native_wei=10 * 10**18)
        after = BalanceSnap(native_wei=20 * 10**18)
        r = report_from_snaps(
            before, after, invariant_broken=False,
            external_funding_wei=10 * 10**18,
        )
        self.assertEqual(r.attacker_native_delta, 0)
        self.assertEqual(r.extractable_wei, 0)
        self.assertEqual(r.classification, NONE)

    def test_only_value_above_harness_funding_is_profit(self):
        before = BalanceSnap(native_wei=10 * 10**18)
        after = BalanceSnap(native_wei=25 * 10**18)
        r = report_from_snaps(
            before, after, invariant_broken=True,
            external_funding_wei=10 * 10**18,
        )
        self.assertEqual(r.attacker_native_delta, 5 * 10**18)
        self.assertEqual(r.extractable_wei, 5 * 10**18)
        self.assertEqual(r.classification, THEFT)

    def test_intended_arb_fixture_expect(self):
        import json
        man = json.loads(
            (ROOT / "benches/fixtures/intended_arb/manifest.json").read_text()
        )
        self.assertEqual(man["frontier"]["expect"], "intended_path")
