#!/usr/bin/env python3
"""Every examples/families/*.sol lights the catalogued feature + provider."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.features import extract_features
from trust404.registry import should_run

FAM = ROOT / "examples" / "families"
CATALOG = json.loads((FAM / "catalog.json").read_text(encoding="utf-8"))


class FamilyExamples(unittest.TestCase):
    def test_catalog_covers_sol_files(self):
        sols = {p.name for p in FAM.glob("*.sol")}
        listed = {row["file"] for row in CATALOG}
        self.assertEqual(sols, listed)

    def test_each_row_fires(self):
        for row in CATALOG:
            with self.subTest(row["file"]):
                src = (FAM / row["file"]).read_text(encoding="utf-8")
                feats = extract_features(src, row["contract"])
                self.assertIn(
                    row["feature"], feats,
                    f"{row['file']} missing {row['feature']}: {sorted(feats)}")
                if row.get("provider"):
                    self.assertTrue(
                        should_run(row["provider"], feats),
                        f"{row['file']} provider {row['provider']} skipped")

    def test_safevault_still_not_in_this_folder(self):
        names = {row["file"] for row in CATALOG}
        self.assertNotIn("SafeVault.sol", names)


if __name__ == "__main__":
    unittest.main()
