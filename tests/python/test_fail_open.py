#!/usr/bin/env python3
"""Audit errors must not count as clean. Agent source must separate no-proof."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "agent"))

import audit


class FailOpen(unittest.TestCase):
    def test_verifier_error_is_inconclusive_not_clean(self):
        res = {"proven": False, "error": "verifier unavailable", "steps": [{"scores": {}}]}
        sev, evidence, is_finding = audit.severity_for(res)
        self.assertFalse(is_finding)
        self.assertIn("inconclusive", evidence)
        args = SimpleNamespace(seed=42)
        findings = [{
            "contract": "X", "file": "X.sol", "severity": sev, "evidence": evidence,
            "res": res, "cls": audit.CLASS["generic"], "poc_file": None,
            "drained_eth": None, "line": 1, "decl_line": 1,
        }]
        report = audit.build_report(findings, args)
        self.assertEqual(report["summary"]["clean"], 0)
        self.assertEqual(report["summary"]["inconclusive"], 1)
        md = audit.render_md(report)
        self.assertIn("INCONCLUSIVE", md)
        self.assertNotIn("| `X` | ⬜ INFO | clean |", md)

    def test_true_clean_has_no_error(self):
        res = {"proven": False, "steps": [{"scores": {}}]}
        sev, evidence, is_finding = audit.severity_for(res)
        self.assertEqual(sev, "INFO")
        self.assertFalse(is_finding)
        args = SimpleNamespace(seed=42)
        findings = [{
            "contract": "Safe", "file": "Safe.sol", "severity": sev, "evidence": evidence,
            "res": res, "cls": audit.CLASS["generic"], "poc_file": None,
            "drained_eth": None, "line": 1, "decl_line": 1,
        }]
        report = audit.build_report(findings, args)
        self.assertEqual(report["summary"]["clean"], 1)
        self.assertEqual(report["summary"]["inconclusive"], 0)

    def test_agent_no_completed_proof_is_exit_2(self):
        src = (ROOT / "agent" / "agent.py").read_text()
        self.assertIn("completed_proofs == 0", src)
        self.assertIn("no successful proof ran", src)
        self.assertIn("def _confirm_official", src)
