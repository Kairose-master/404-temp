# Declared Setup: fail-closed deployment policy

`deploy.setup` is a mandatory deployment path, not a best-effort hint. This
policy supersedes older architecture notes describing a zero-argument fallback.

For py-evm:

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

This change does not add Foundry cheatcodes to py-evm. A valid Setup requiring
`vm.deal`, `vm.prank` or other HEVM behavior still needs the real Forge backend
(`TRUST404_VERIFIER=forge`); the verifier must not manufacture a replacement
world to compensate. Forge code and its existing result classification are
unchanged by this patch.

## ApprovalMirage compatibility correction

The first real Docker run with this policy exposed that the original
`ApprovalMirage/Setup.s.sol` calls HEVM `vm.addr` and reverts under py-evm.
Its earlier NOT_PROVEN status depended on silently falling back to the target
constructor. That is not a valid reason to retain the fallback. The original
fixture is unchanged and now explicitly expects SetupDeploymentError in
py-evm, while Forge must still produce its real NOT_PROVEN result.

`ApprovalMiragePlainSetup` is a separate, explicitly named control with the
same target, exploit, invariant and manifest. Its Setup resolves just the known
`alice` label to the target's existing constant address without using HEVM.
It retains `makeAddr("alice")` and asserts zero allowance. Both backends must
produce a real NOT_PROVEN result for this control. It is never substituted
by the verifier for the original Setup; no original test fixture is deleted.

Other known divergences, tracked in `tests/python/test_remaining_holes.py`, are
not repaired here. In particular, `_deploy_via_setup` still assumes the target
is Setup's first CREATE child instead of decoding the actual `run()` return
value; multiple CREATEs/CREATE2/existing-address returns are not generally
supported. Block/time/HEVM-in-run differences also remain. Passing the new
regression and Docker checks is not a claim of full harness equivalence.
