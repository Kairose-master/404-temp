#!/usr/bin/env python3
"""Real offline checks against image code, with no skipped or mocked proofs."""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/work"))
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--backend", choices=("evm", "forge"), required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "agent"))
    os.environ["TRUST404_VERIFIER"] = args.backend

    # Missing tools are fatal; never install or skip at runtime.
    import solcx
    from solcx.install import get_executable
    solcx.set_solc_version("0.8.24")
    subprocess.run([str(get_executable("0.8.24")), "--version"], check=True, timeout=15)
    subprocess.run(["forge", "--version"], check=True, timeout=15)
    from trust404.abi import load_extra_sources
    from verify import verify_full, SetupDeploymentError

    checks = []

    def record(row):
        checks.append(row)
        print(json.dumps({"backend": args.backend, **row}), flush=True)

    def check(name, result, expected, violated=""):
        if result.proven is not expected or result.violated != violated:
            raise AssertionError(f"{args.backend}/{name}: unexpected proof result {result}")
        # A failed Forge runner is not an acceptable negative proof.
        if args.backend == "forge" and result.detail != "forge":
            raise AssertionError(f"{name}: did not reach ProofResult: {result.detail}")
        record({"case": name, "proven": result.proven, "violated": result.violated})

    def case_inputs(name):
        base = args.fixtures / name
        manifest_path = base / "manifest.json"
        man = json.loads(manifest_path.read_text())
        target_path = base / man["target"]["src"]
        return dict(
            target_name=man["target"]["name"], target_src=target_path.read_text(),
            invariants_src=(base / man["invariants"]["contract"]).read_text(),
            exploit_src=(base / "Exploit.sol").read_text(), manifest=man, seed=42,
            extra_sources=load_extra_sources(manifest_path, target_path, man) or None,
        )

    def check_setup_error(name, inputs):
        try:
            verify_full(**inputs)
        except SetupDeploymentError as exc:
            if "Setup.run reverted" not in str(exc):
                raise AssertionError(f"{name}: wrong deployment failure: {exc}") from exc
        else:
            raise AssertionError(f"{name}: failed Setup unexpectedly produced a proof result")
        record({"case": name, "status": "INCONCLUSIVE"})

    for name, expected, violated in (
        ("SetupOnlyOwner", True, "ownerUnchanged"),
        ("PhasedGhost", False, ""),
        ("ApprovalMirage", False, ""),
        ("ApprovalMiragePlainSetup", False, ""),
    ):
        inputs = case_inputs(name)
        if name == "ApprovalMirage" and args.backend == "evm":
            # Preserve the original vm.addr-using fixture. Unsupported Setup is
            # an explicit error, never a negative proof or constructor fallback.
            check_setup_error(name, inputs)
        else:
            check(name, verify_full(**inputs), expected, violated)

    target = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract SmokeTarget {
    bool public broken;
    function breakInvariant() external { broken = true; }
}
"""
    inv = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
interface ISmokeTarget { function broken() external view returns (bool); }
contract Invariants {
    function checkAll(address target) external view returns (bool, string memory) {
        if (ISmokeTarget(target).broken()) return (false, "unbroken");
        return (true, "");
    }
}
"""
    manifest = {
        "target": {"name": "SmokeTarget", "src": "src/SmokeTarget.sol",
                   "solc": "0.8.24", "evm_version": "cancun"},
        "deploy": {"constructor_args": [], "value_wei": "0"},
        "invariants": {"contract": "Invariants.sol", "predicates": ["unbroken"]},
        "determinism": {"block_number": 21000000, "block_timestamp": 1735689600},
    }
    for name, body, expected in (
        ("DirectConstructor", 'ISmokeTarget(target).breakInvariant();', True),
        ("HealthyNoop", 'target;', False),
    ):
        exploit = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
interface ISmokeTarget { function breakInvariant() external; }
contract Exploit {
    function run(address target) external payable { BODY }
    receive() external payable {}
}
""".replace("BODY", body)
        result = verify_full("SmokeTarget", target, inv, exploit, manifest, seed=42)
        check(name, result, expected, "unbroken" if expected else "")

    inputs = case_inputs("SetupRevertsZeroArg")
    if args.backend == "evm":
        check_setup_error("SetupRevertsZeroArg", inputs)
    # Same target and exploit: only change Setup's revert to a successful return.
    setup_src = inputs["extra_sources"]["Setup.s.sol"]
    inputs["extra_sources"]["Setup.s.sol"] = setup_src.replace(
        'revert("SETUP_REVERT_SENTINEL");', 'return address(target);')
    check("SetupZeroArgControl", verify_full(**inputs), True, "unbroken")

    print(json.dumps({"backend": args.backend, "passed": len(checks), "skipped": 0}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
