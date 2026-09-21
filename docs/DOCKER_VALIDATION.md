# Offline Docker verification

The image installs Python 3.11.13, Foundry v1.7.1 and solc 0.4.26, 0.5.17,
0.6.12, 0.7.6, 0.8.24 and 0.8.28 at build time. These are the patch releases
selected by the audit engine for each supported Solidity minor, plus the public
fixture compiler. Add a private target's exact compiler with
`--build-arg EXTRA_SOLC_VERSIONS="0.8.20"` when it is not in that set.
It currently targets `linux/amd64`. On ARM hosts, explicitly build and run with
`--platform linux/amd64` (requires an amd64 emulation-capable Docker installation).
Other architectures are rejected instead of silently downloading the wrong solc.

Foundry is extracted directly into `/opt/foundry/bin`. There is no installer path
under `/root/.foundry` to copy from. solcx stores its compiler in `/opt/solc`.
`agent/verify.py` looks up the requested, already installed solcx compiler and
passes its absolute path to `forge test --use ... --offline`. A native Forge-only
installation may still use its own already populated version cache; this lookup
does not download anything. Missing compilers must be installed while building,
not after the scoring sandbox loses network access.

## Reproduce the container gate

Run from the repository root:

```sh
docker build --pull --no-cache --platform linux/amd64 \
  -f agent/Dockerfile -t trust404:offline .
docker run --rm --platform linux/amd64 --network none trust404:offline --help
docker run --rm --platform linux/amd64 --network none trust404:offline audit --help
for backend in evm forge; do
  docker run --rm --platform linux/amd64 --network none --entrypoint python \
    --mount "type=bind,src=$PWD/scripts/docker_smoke.py,dst=/checks/docker_smoke.py,readonly" \
    --mount "type=bind,src=$PWD/tests/fixtures/counterexamples,dst=/checks/fixtures,readonly" \
    trust404:offline /checks/docker_smoke.py \
      --root /work --fixtures /checks/fixtures --backend "$backend" || exit 1
done
```

Only the smoke driver and input fixtures are mounted. Agent code, Python
packages, harness and vendored forge-std are taken from the built image so a
checkout mount cannot hide a broken COPY instruction or missing dependency.
There are no host compiler-cache or home-directory mounts. Each backend gets a
fresh container and must pass all its checks without skips:

| Case | Expected |
| --- | --- |
| SetupOnlyOwner | PROVEN, ownerUnchanged |
| PhasedGhost | NOT_PROVEN |
| ApprovalMirage (original HEVM Setup) | NOT_PROVEN on both backends |
| ApprovalMiragePlainSetup (separate control) | NOT_PROVEN on both backends |
| DirectConstructor | PROVEN, unbroken |
| HealthyNoop | NOT_PROVEN |
| SetupZeroArgControl | PROVEN, unbroken (both backends) |
| SetupRevertsZeroArg | SetupDeploymentError / INCONCLUSIVE (both backends) |

Both gates run eight checks. The deployment-error check requires a
backend-specific Setup diagnostic, not any exception.
The zero-argument positive control changes only that Setup's revert into a successful return.

The original ApprovalMirage Setup calls HEVM `vm.addr`. The py-evm backend now
implements that selector, so its NOT_PROVEN result comes from the declared
Setup and the real invariant check. The plain-Setup fixture remains a separate
control. Neither path restores a constructor fallback or counts an
infrastructure exception as a negative proof.

Forge negative fixtures must reach the official `ProofResult` event, not just
exit with an infrastructure error or reverted test. Forge requests `-vvvv`
traces, checks the process exit code before trusting any event, and treats a
successful process without a proof result as an error rather than a negative.

The `docker-offline-verifier / docker-offline` Actions job runs the above gate and
archives build and smoke logs, including on failures. The existing audit workflow
continues to run the full Python unit suite separately. To block merges on this
gate, add its check to the repository's required status checks; the workflow
alone does not change branch protection.

This gate validates packaging and these selected proof paths, not all possible
Setup programs or semantic equivalence of py-evm and Forge. A declared py-evm
Setup now fails closed: it never falls back to the target constructor. See
[Setup failure policy](SETUP_FAILURE.md) for the error contract and remaining
limitations. Python dependencies are exact-version pinned. A pinned base-image
digest and reviewed wheel hashes would be the remaining steps for byte-for-byte
builds.
