#!/usr/bin/env python3
"""Multi-file import flattening + zip intake for the auditor CLI.

Pure-Python: exercises agent/audit.py helpers without solc or the engine.
"""
import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Load agent/audit.py by path (its package dir is not importable as `agent`).
_spec = importlib.util.spec_from_file_location("t404audit", ROOT / "agent" / "audit.py")
audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(audit)


class _CtorEngine:
    @staticmethod
    def _strip_comments(src):
        return src

    @staticmethod
    def _contract_bodies(_src):
        return {
            "Pool": "constructor(Token _col, IToken _bor, Token[2] memory peers) {}",
        }


def _make_project(base: Path):
    (base / "src" / "base").mkdir(parents=True, exist_ok=True)
    (base / "lib" / "oz" / "contracts" / "utils").mkdir(parents=True, exist_ok=True)
    (base / "lib" / "oz" / "contracts" / "utils" / "Note.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        "abstract contract Note { function _n() internal {} }\n", encoding="utf-8")
    (base / "src" / "base" / "VaultBase.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        'import "@oz/contracts/utils/Note.sol";\n'
        "abstract contract VaultBase is Note { uint256 public x; }\n", encoding="utf-8")
    (base / "src" / "IVault.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
        "interface IVault { function f() external; }\n", encoding="utf-8")
    (base / "src" / "Vault.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n"
        'import {IVault} from "./IVault.sol";\n'
        'import "./base/VaultBase.sol";\n'
        "contract Vault is VaultBase, IVault { function f() external override {} }\n",
        encoding="utf-8")


class Flatten(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="t404-test-"))
        _make_project(self.tmp)
        self.index = audit.build_source_index(self.tmp)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_alias_import_resolves_by_suffix(self):
        note = self.tmp / "lib" / "oz" / "contracts" / "utils" / "Note.sol"
        got = audit.resolve_import(
            "@oz/contracts/utils/Note.sol",
            self.tmp / "src" / "base" / "VaultBase.sol", self.index)
        self.assertEqual(got, note.resolve())

    def test_relative_import_resolves(self):
        got = audit.resolve_import(
            "./IVault.sol", self.tmp / "src" / "Vault.sol", self.index)
        self.assertEqual(got, (self.tmp / "src" / "IVault.sol").resolve())

    def test_flatten_inlines_all_deps_once(self):
        flat = audit.flatten_sol(self.tmp / "src" / "Vault.sol", self.index)
        # Every dependency contract is present.
        for needle in ("interface IVault", "abstract contract Note",
                       "abstract contract VaultBase", "contract Vault"):
            self.assertIn(needle, flat)
        # No import lines survive.
        self.assertNotIn("import ", flat)
        # Exactly one SPDX and one pragma header.
        self.assertEqual(flat.count("SPDX-License-Identifier"), 1)
        self.assertEqual(flat.count("pragma solidity"), 1)
        # Dependencies come before the contract that needs them.
        self.assertLess(flat.index("abstract contract VaultBase"),
                        flat.index("contract Vault is VaultBase"))
        self.assertLess(flat.index("abstract contract Note"),
                        flat.index("contract Vault is VaultBase"))

    def test_flatten_preserves_symbol_and_namespace_aliases(self):
        alias = self.tmp / "src" / "AliasVault.sol"
        alias.write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\n"
            'import {VaultBase as LockedBase} from "./base/VaultBase.sol";\n'
            'import * as Types from "./IVault.sol";\n'
            "contract AliasVault is LockedBase, Types.IVault { "
            "function f() external override {} }\n", encoding="utf-8")
        flat = audit.flatten_sol(alias, audit.build_source_index(self.tmp))
        self.assertIn("contract AliasVault is VaultBase, IVault", flat)
        self.assertNotIn("LockedBase", flat)
        self.assertNotIn("Types.IVault", flat)

        try:
            import solcx
            solcx.set_solc_version("0.8.24")
        except Exception:
            self.skipTest("solc 0.8.24 unavailable")
        compiled = solcx.compile_source(flat, output_values=["abi"])
        self.assertTrue(any(name.endswith(":AliasVault") for name in compiled))

    def test_ambiguous_suffix_import_fails_closed(self):
        other = self.tmp / "vendor" / "contracts" / "utils"
        other.mkdir(parents=True)
        (other / "Note.sol").write_text(
            "pragma solidity ^0.8.0; contract Note {}\n", encoding="utf-8")
        index = audit.build_source_index(self.tmp)
        with self.assertRaisesRegex(ValueError, "ambiguous import"):
            audit.resolve_import("@alias/contracts/utils/Note.sol",
                                 self.tmp / "src" / "Vault.sol", index)

    def test_unresolved_relative_import_fails_closed(self):
        broken = self.tmp / "src" / "Broken.sol"
        broken.write_text(
            "pragma solidity 0.8.24;\n"
            'import {Missing} from "./Missing.sol";\n'
            "contract Broken is Missing {}\n", encoding="utf-8")
        with self.assertRaisesRegex(FileNotFoundError, "unresolved import"):
            audit.flatten_sol(broken, audit.build_source_index(self.tmp))

        out = self.tmp / "audit-output"
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            rc = audit.main([str(broken), "--out", str(out), "--quiet"])
        self.assertEqual(rc, audit.EXIT_ERROR)
        report = json.loads((out / "report.json").read_text())
        self.assertEqual(report["summary"]["analysis_errors"], 1)

    def test_constructor_contract_types_are_synthesized_as_addresses(self):
        src = """
        interface IToken {}
        library Types { }
        contract Token {}
        contract Pool {
            constructor(Token _col, IToken _bor, Token[2] memory peers) {}
        }
        """
        dummy = "0x000000000000000000000000000000000000dEaD"
        self.assertEqual(
            audit.synth_ctor_args(_CtorEngine(), src, "Pool"),
            [dummy, dummy, [dummy, dummy]],
        )

    def test_prepare_input_extracts_zip(self):
        zp = self.tmp.parent / (self.tmp.name + ".zip")
        with zipfile.ZipFile(zp, "w") as zf:
            for f in self.tmp.rglob("*.sol"):
                zf.write(f, Path(self.tmp.name) / f.relative_to(self.tmp))
        try:
            root, cleanup = audit.prepare_input(str(zp))
            try:
                sols = list(Path(root).rglob("*.sol"))
                self.assertTrue(any(s.name == "Vault.sol" for s in sols))
                # Single top-level folder is unwrapped to become the root.
                self.assertTrue((Path(root) / "src" / "Vault.sol").exists())
            finally:
                cleanup()
        finally:
            zp.unlink(missing_ok=True)

    def test_prepare_input_rejects_zip_slip(self):
        zp = self.tmp.parent / "evil.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("../evil.sol", "// pwned")
        try:
            with self.assertRaises(SystemExit):
                audit.prepare_input(str(zp))
        finally:
            zp.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
