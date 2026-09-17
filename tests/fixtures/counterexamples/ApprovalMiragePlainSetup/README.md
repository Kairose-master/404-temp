# ApprovalMirage with an explicit, EVM-compatible Setup

This is a separate control. The original `ApprovalMirage` fixture, including its
`vm.addr`-using Setup, remains unchanged. The target, exploit, invariant and
manifest here are exact copies of that fixture. Only this Setup implementation
differs: it uses the existing fixed address for the single `alice` fixture label
instead of calling the HEVM address. It still contains `makeAddr("alice")`, so a
verifier that incorrectly synthesizes approvals from labels will fail the test.
The Setup asserts that the target starts with zero victim allowance.

Expected: real NOT_PROVEN on both py-evm and Forge. No exception is an acceptable
substitute for that result. The original HEVM fixture must instead produce a
specific SetupDeploymentError in py-evm and real NOT_PROVEN in Forge. Do not
silently substitute this Setup when verifying the original manifest.
