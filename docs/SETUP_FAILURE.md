# Declared Setup: fail-closed deployment policy

`deploy.setup` is a mandatory deployment path, not a best-effort hint. This
policy supersedes older architecture notes describing a zero-argument fallback.

The fail-closed rule applies to both verifier backends. For py-evm:

- Absent `deploy.setup`: preserve helper deployment, constructor ABI coercion,
  placeholders and `value_wei` in the existing direct-constructor path.
- Present `deploy.setup`: require a nonempty source path and use the `Setup`
  artifact from that exact source unit. A same-named contract from another file
  is not a substitute. Do not predeploy manifest helpers or encode constructor
  arguments for this path: the declared Setup owns the initial state.
- Failed Setup deployment, reverted `Setup.run()`, missing artifact or missing
  deployed target code raises `SetupDeploymentError`, a `VerifyUnavailable`
  subclass. No target constructor is attempted. The agent CLI reports
  `INCONCLUSIVE`, sets `verifier_available=false`, and returns exit code 2.
  This is not evidence that the candidate is safe or unexploitable.

`SetupRevertsZeroArg` captures the regression: its target is exploitable when
manually constructed, but the declared Setup always reverts. Returning PROVEN
for that substitute world is invalid. Positive controls check that removing
the Setup declaration or making the Setup return successfully still permits
the same target/exploit to be proven. Tests also exercise missing/invalid Setup
metadata, Setup constructor failure and the CLI error contract.

This policy also applies to Forge process failures. Candidate construction or
`run()` reverts are caught inside the temporary test and become a normal failed
candidate. Compilation, Setup, target deployment, and the initial invariant
check happen outside that boundary; any failure there raises
`SetupDeploymentError`/`VerifyUnavailable` and the CLI exits 2.

The py-evm backend emulates the Setup cheatcodes used by the fixtures:
`vm.deal`, `vm.prank`, `vm.addr`, `vm.roll`, and `vm.warp`. A Setup requiring
another Foundry cheatcode still needs the real Forge backend
(`TRUST404_VERIFIER=forge`); the verifier does not manufacture a replacement
world to compensate.

## ApprovalMirage compatibility correction

The first fail-closed Docker run exposed that the original
`ApprovalMirage/Setup.s.sol` calls HEVM `vm.addr`. The py-evm HEVM surface now
implements that selector, so the declared Setup completes and both backends
reach the real invariant check. Both must produce NOT_PROVEN; neither may use a
constructor fallback.

`ApprovalMiragePlainSetup` is a separate, explicitly named control with the
same target, exploit, invariant and manifest. Its Setup resolves just the known
`alice` label to the target's existing constant address without using HEVM.
It retains `makeAddr("alice")` and asserts zero allowance. Both backends must
produce a real NOT_PROVEN result for this control. It is never substituted
by the verifier for the original Setup.

The Python Setup emulator still cannot cover every Foundry cheatcode. Such
targets must use the Forge backend; they are never silently replaced with a
constructor-only world.
