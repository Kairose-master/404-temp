#!/usr/bin/env python3
"""Hidden-set IR: constructor arrays, cross-contract getters, TWAP-as-spot."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from trust404.abi import (
    coerce, coerce_against_abi, forge_ctor, parse_constructor_types,
    parse_structs, resolve_placeholders,
)
from trust404.features import extract_features
from trust404.hevm import window_seconds
from trust404.registry import should_run
from trust404.synth_defi import iter_defi_families
from trust404.world import plan_world


class ConstructorAbi(unittest.TestCase):
    def test_nested_address_array_and_uint(self):
        raw = [
            ["0x00000000000000000000000000000000000a11ce",
             "0x00000000000000000000000000000000000b0b00"],
            "2",
        ]
        out = coerce(raw, web3=None)
        self.assertEqual(len(out[0]), 2)
        self.assertEqual(out[1], 2)
        self.assertTrue(out[0][0].startswith("0x"))

    def test_bytes32_and_string(self):
        out = coerce(["0x" + "ab" * 32, "hello"], web3=None)
        self.assertEqual(out[0], bytes.fromhex("ab" * 32))
        self.assertEqual(out[1], "hello")

    def test_bool_and_placeholder(self):
        out = coerce(["true", "$Token"], web3=None)
        self.assertIs(out[0], True)
        self.assertEqual(out[1], "$Token")
        resolved = resolve_placeholders(["$Token"], {"Token": "0xabc"})
        self.assertEqual(resolved, ["0xabc"])

    def test_parse_array_ctor(self):
        src = """
        contract V {
            constructor(address[] memory owners, uint256 threshold) payable {}
        }
        """
        self.assertEqual(
            parse_constructor_types(src, "V"),
            ["address[]", "uint256"],
        )

    def test_forge_ctor_emits_memory_array(self):
        prelude, args = forge_ctor([
            ["0x00000000000000000000000000000000000a11ce"],
            1,
        ])
        self.assertIn("address[] memory _a0", prelude)
        self.assertIn("_a0, uint256(1)", args)


class TwapAsSpot(unittest.TestCase):
    SRC = """
    contract TwapDesk {
        uint256 public reserve0; uint256 public reserve1;
        function consult() public view returns (uint256) { return twap(); }
        function twap() public view returns (uint256) { return reserve1 * 1e18 / reserve0; }
        function borrow(uint256 n) external {}
        function token() external view returns (address) { return address(0); }
        function pool() external view returns (address) { return address(0); }
    }
    """
    WINDOWED = """
    contract UniTwap {
        struct Observation { uint32 ts; uint224 c; }
        Observation[] public observations;
        function observe(uint32[] calldata secondsAgos) external view returns (int56[] memory) {}
        function borrow(uint256 n) external {}
    }
    """

    def test_falls_to_spot(self):
        f = extract_features(self.SRC, "TwapDesk")
        self.assertIn("twap_oracle", f)
        self.assertIn("twap_falls_to_spot", f)
        self.assertIn("spot_price", f)

    def test_stored_window_is_not_spot(self):
        f = extract_features(self.WINDOWED, "UniTwap")
        self.assertIn("twap_oracle", f)
        self.assertNotIn("twap_falls_to_spot", f)

    def test_synth_fires(self):
        labels = [l for l, _ in iter_defi_families(self.SRC, "TwapDesk")]
        self.assertTrue(any(l.startswith("twap-as-spot") for l in labels))
        self.assertTrue(should_run("twap_as_spot", extract_features(self.SRC, "TwapDesk")))


class CrossContract(unittest.TestCase):
    SRC = """
    contract Token { function transfer(address,uint256) external returns (bool) { return true; } }
    contract Desk {
        address public token; address public pool;
        constructor(address t, address p) { token = t; pool = p; }
        function token() external view returns (address) { return token; }
        function pool() external view returns (address) { return pool; }
        function borrow(uint256 n) external {}
    }
    """

    def test_features(self):
        f = extract_features(self.SRC, "Desk")
        self.assertIn("multi_contract_unit", f)
        self.assertIn("sibling_getter", f)
        self.assertIn("address_ctor", f)

    def test_world_and_synth(self):
        f = extract_features(self.SRC, "Desk")
        wp = plan_world(self.SRC, "Desk", f)
        self.assertTrue(wp.cross_contract)
        self.assertIn("function pool()", wp.folded_exploit)
        labels = [l for l, _ in iter_defi_families(self.SRC, "Desk")]
        self.assertTrue(any(l.startswith("cross-getter") for l in labels))


class SafeVaultUnchanged(unittest.TestCase):
    def test_still_skips_twap_synth(self):
        src = (ROOT / "targets/SafeVault/src/SafeVault.sol").read_text()
        f = extract_features(src, "SafeVault")
        self.assertNotIn("twap_oracle", f)
        self.assertFalse(should_run("twap_as_spot", f))
        self.assertFalse(should_run("twap_window", f))
        self.assertFalse(should_run("victim_approve", f))
        self.assertFalse(should_run("_synth_gatekeeper_one", f))


class StructCtor(unittest.TestCase):
    SRC = """
    struct Init { address owner; uint256 cap; address[] tokens; }
    contract V {
        constructor(Init memory cfg) payable {}
    }
    """
    ABI = [{
        "type": "constructor",
        "inputs": [{
            "name": "cfg", "type": "tuple",
            "components": [
                {"name": "owner", "type": "address"},
                {"name": "cap", "type": "uint256"},
                {"name": "tokens", "type": "address[]"},
            ],
        }],
    }]

    def test_named_object(self):
        raw = [{
            "owner": "0x00000000000000000000000000000000000a11ce",
            "cap": "5",
            "tokens": ["0x00000000000000000000000000000000000b0b00"],
        }]
        out = coerce_against_abi(raw, self.ABI)
        self.assertIsInstance(out[0], tuple)
        self.assertEqual(out[0][1], 5)
        self.assertEqual(len(out[0][2]), 1)

    def test_positional(self):
        raw = [["0x00000000000000000000000000000000000a11ce", "5",
                ["0x00000000000000000000000000000000000b0b00"]]]
        out = coerce_against_abi(raw, self.ABI)
        self.assertEqual(out[0][1], 5)

    def test_parse_and_forge(self):
        self.assertIn("Init", parse_structs(self.SRC))
        self.assertEqual(parse_constructor_types(self.SRC, "V"), ["Init"])
        prelude, args = forge_ctor(
            [{"owner": "0x00000000000000000000000000000000000a11ce",
              "cap": 5,
              "tokens": ["0x00000000000000000000000000000000000b0b00"]}],
            src=self.SRC, name="V")
        self.assertIn("Init(", args)
        self.assertIn("address[] memory", prelude)

    def test_feature(self):
        self.assertIn("struct_ctor", extract_features(self.SRC, "V"))


class WindowedTwap(unittest.TestCase):
    SRC = """
    contract UniTwap {
        struct Observation { uint32 ts; uint224 c; }
        Observation[] public observations;
        uint32 public period = 30 minutes;
        function observe(uint32[] calldata secondsAgos) external view returns (int56[] memory) {}
        function borrow(uint256 n) external {}
        function update() external {}
        function token() external view returns (address) { return address(0); }
        function pool() external view returns (address) { return address(0); }
    }
    """

    def test_feature_and_window(self):
        f = extract_features(self.SRC, "UniTwap")
        self.assertIn("windowed_twap", f)
        self.assertNotIn("twap_falls_to_spot", f)
        self.assertEqual(window_seconds(self.SRC), 30 * 60)
        self.assertTrue(should_run("twap_window", f))

    def test_synth_has_warp_and_phases(self):
        srcs = dict(iter_defi_families(self.SRC, "UniTwap"))
        key = next(k for k in srcs if k.startswith("twap-window"))
        body = srcs[key]
        self.assertIn("vm.warp", body)
        self.assertIn("function prepare", body)
        self.assertIn("function finish", body)


class VictimApprove(unittest.TestCase):
    SRC = """
    contract Vault {
        address public victim;
        address public token;
        function pull() external {
            IERC20(token).transferFrom(victim, address(this), IERC20(token).allowance(victim, address(this)));
        }
    }
    interface IERC20 {
        function transferFrom(address,address,uint256) external returns (bool);
        function allowance(address,address) external view returns (uint256);
    }
    """

    def test_feature_and_synth(self):
        f = extract_features(self.SRC, "Vault")
        self.assertIn("victim_approve", f)
        self.assertIn("victim_getter", f)
        self.assertTrue(should_run("victim_approve", f))
        labels = [l for l, _ in iter_defi_families(self.SRC, "Vault")]
        self.assertTrue(any(l.startswith("victim-approve") for l in labels))
        body = dict(iter_defi_families(self.SRC, "Vault"))
        src = next(v for k, v in body.items() if k.startswith("victim-approve"))
        self.assertIn("vm.prank", src)


class IntentPath(unittest.TestCase):
    def test_swap_only_is_intended(self):
        from trust404.intent import decide, is_success, INTENDED_PATH, THEFT
        swap = "contract Exploit { function run(address t) external payable { I(t).swap0to1(); } }"
        self.assertEqual(decide({"swap"}, swap, False, "intended_path"), INTENDED_PATH)
        self.assertFalse(is_success(INTENDED_PATH))
        drain = "contract Exploit { function run(address t) { I(t).withdraw(); } }"
        self.assertEqual(decide({"cei_violation"}, drain, True, "theft"), THEFT)
        self.assertTrue(is_success(THEFT))

    def test_dual_surface_swap_poc_is_intended(self):
        from trust404.intent import decide, INTENDED_PATH
        swap = (ROOT / "examples/frontier/ExploitSwap.sol").read_text()
        self.assertEqual(decide({"swap"}, swap, False, None), INTENDED_PATH)


class SeededAllowance(unittest.TestCase):
    SRC = """
    contract Vault {
        address public victim;
        address public token;
        function pull() external {}
        function seed() external { Token(token).approve(address(this), 1); }
    }
    interface Token { function approve(address,uint256) external returns (bool); }
    """

    def test_no_prank_synth(self):
        f = extract_features(self.SRC, "Vault")
        self.assertIn("setup_seeded_allowance", f)
        labels = [l for l, _ in iter_defi_families(self.SRC, "Vault")]
        self.assertTrue(any(l.startswith("seeded-allowance") for l in labels))
        body = next(s for l, s in iter_defi_families(self.SRC, "Vault") if l.startswith("seeded-allowance"))
        self.assertNotIn("vm.prank", body)
        self.assertIn("transferFrom", body)


class CrossChain(unittest.TestCase):
    SRC = """
    contract Bridge {
        function lzReceive(uint16 srcChain, bytes memory src, uint64 nonce, bytes memory payload) external {}
        function token() external view returns (address) { return address(0); }
    }
    """

    def test_feature_and_synth(self):
        f = extract_features(self.SRC, "Bridge")
        self.assertIn("cross_chain_bridge", f)
        self.assertTrue(should_run("cross_chain_bridge", f))
        labels = [l for l, _ in iter_defi_families(self.SRC, "Bridge")]
        self.assertTrue(any(l.startswith("cross-chain") for l in labels))


class HandselNoKey(unittest.TestCase):
    def test_minivault_liquidate(self):
        src = (ROOT / "examples/families/LiquidateOther.sol").read_text()
        f = extract_features(src, "MiniVaultLike")
        self.assertIn("liquidate_other", f)
        self.assertIn("no_key_path", f)
        self.assertTrue(should_run("liquidate_other", f))
        labels = [l for l, _ in iter_defi_families(src, "MiniVaultLike")]
        self.assertTrue(any(l.startswith("liquidate-other") for l in labels))
        body = next(s for l, s in iter_defi_families(src, "MiniVaultLike") if l.startswith("liquidate-other"))
        self.assertNotIn("vm.prank", body)

    def test_imported_protocol(self):
        src = (ROOT / "examples/families/ImportedProtocol.sol").read_text()
        f = extract_features(src, "ProtocolDesk")
        self.assertIn("imported_lending", f)
        self.assertTrue(should_run("imported_protocol", f))

    def test_yul_skips_specialized_not_unknown(self):
        src = (ROOT / "examples/families/OpaqueYul.sol").read_text()
        f = extract_features(src, "OpaqueYul")
        self.assertIn("opaque_ir", f)
        self.assertFalse(should_run("liquidate_other", f))
        self.assertTrue(should_run("not_a_real_fn", f))


class HiddenSetDeep(unittest.TestCase):
    def _src(self, name):
        return (ROOT / "examples/families" / name).read_text(encoding="utf-8")

    def test_readonly(self):
        src = self._src("ReadOnlyReentrancy.sol")
        f = extract_features(src, "CurveLike")
        self.assertIn("readonly_reentrancy", f)
        self.assertTrue(should_run("readonly_reentrancy", f))
        labels = [l for l, _ in iter_defi_families(src, "CurveLike")]
        self.assertIn("readonly-reentrancy", labels)

    def test_inflation(self):
        src = self._src("VaultInflation.sol")
        f = extract_features(src, "InflatingVault")
        self.assertIn("vault_inflation", f)
        self.assertTrue(any(l == "vault-inflation" for l, _ in iter_defi_families(src, "InflatingVault")))

    def test_hook(self):
        src = self._src("HookReentrancy.sol")
        f = extract_features(src, "HookVault")
        self.assertIn("hook_reentrancy", f)

    def test_sig_replay(self):
        src = self._src("SigReplay.sol")
        f = extract_features(src, "ReplayDesk")
        self.assertIn("sig_replay", f)
        self.assertNotIn("opaque_ir", f)

    def test_metamorphic(self):
        src = self._src("Metamorphic.sol")
        f = extract_features(src, "MetamorphicFactory")
        self.assertIn("metamorphic", f)
        self.assertIn("selfdestruct", f)
        self.assertTrue(should_run("metamorphic", f))


class LastThree(unittest.TestCase):
    def test_commit_reveal(self):
        src = (ROOT / "examples/families/CommitReveal.sol").read_text()
        f = extract_features(src, "CommitReveal")
        self.assertIn("commit_reveal", f)
        self.assertTrue(should_run("commit_reveal", f))
        srcs = dict(iter_defi_families(src, "CommitReveal"))
        self.assertIn("commit-reveal", srcs)
        self.assertIn("prepare", srcs["commit-reveal"])
        self.assertIn("vm.roll", srcs["commit-reveal"])

    def test_external_erc(self):
        from trust404.erc import hardcoded_addresses, classify, SELECTORS
        src = (ROOT / "examples/families/ExternalErc.sol").read_text()
        f = extract_features(src, "ExternalDesk")
        self.assertIn("external_erc", f)
        addrs = hardcoded_addresses(src)
        self.assertTrue(any(a.lower().endswith("2488d") for a in addrs))
        self.assertIn("d505accf", SELECTORS)
        self.assertEqual(SELECTORS["a9059cbb"], "transfer(address,uint256)")
        self.assertIn("erc20", classify({"a9059cbb", "70a08231", "095ea7b3"}))

    def test_make_addr_parse(self):
        from trust404.eoa import make_addr_names
        src = (ROOT / "examples/families/MakeAddrVictim.sol").read_text()
        f = extract_features(src, "PullVault")
        self.assertIn("make_addr_victim", f)
        self.assertEqual(make_addr_names(src), ["alice"])

    def test_push4_selectors(self):
        from trust404.erc import selectors_from_bytecode, classify
        # PUSH4 a9059cbb  (transfer)
        code = bytes.fromhex("63a9059cbb")
        sel = selectors_from_bytecode(code)
        self.assertIn("a9059cbb", sel)
        self.assertIn("erc20", classify(sel | {"70a08231", "095ea7b3"}))



if __name__ == "__main__":
    unittest.main()
