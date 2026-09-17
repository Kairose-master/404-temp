#!/usr/bin/env python3
"""Run real proof checks against the built image; missing tools are fatal.

Mounted by .github/workflows/docker.yml. Application code is imported from
/work inside the IMAGE, never from a bind-mounted checkout.
"""
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

    # Do not install at runtime and do not skip if the compiler is missing.
    import solcx
    from solcx.install import get_executable
    solcx.set_solc_version("0.8.24")
    compiler = get_executable("0.8.24")
    subprocess.run([str(compiler), "--version"], check=True, timeout=15)
    subprocess.run(["forge", "--version"], check=True, timeout=15)
    from trust404.abi import load_extra_sources
    from verify import verify_full

    checks = []

    def check(name, result, expected, violated=None):
        if result.proven is not expected:
            raise AssertionError(f"{args.backend}/{name}: expected {expected}, got {result}")
        if violated is not None and result.violated != violated:
            raise AssertionError(f"{args.backend}/{name}: wrong predicate {result.violated!r}")
        # A broken runner must not satisfy a negative proof fixture accidentally.
        if args.backend == "forge" and result.detail != "forge":
            raise AssertionError(f"{args.backend}/{name}: did not reach ProofResult: {result.detail}")
        checks.append({"case": name, "proven": result.proven, "violated": result.violated})
        print(json.dumps({"backend": args.backend, **checks[-1]}), flush=True)

    for name, expected, violated in (
        ("SetupOnlyOwner", True, "ownerUnchanged"),
        ("PhasedGhost", False, ""),
        ("ApprovalMirage", False, ""),
    ):
        base = args.fixtures / name
        manifest_path = base / "manifest.json"
        man = json.loads(manifest_path.read_text())
        target_path = base / man["target"]["src"]
        extras = load_extra_sources(manifest_path, target_path, man)
        result = verify_full(
            target_name=man["target"]["name"],
            target_src=target_path.read_text(),
            invariants_src=(base / man["invariants"]["contract"]).read_text(),
            exploit_src=(base / "Exploit.sol").read_text(),
            manifest=man, seed=42, extra_sources=extras or None,
        )
        check(name, result, expected, violated)

    # Exercise the constructor path as well as the Setup fixture above.
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

    print(json.dumps({"backend": args.backend, "passed": len(checks), "skipped": 0}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
