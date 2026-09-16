# DualSurface

트랙 12가 아니다. METHOD §6 한계의 작업 예제.

Worked example for the unsolved frontier: **the same contract has a
designed swap and a real vault bug.** Revenue is not the label.

```
swap0to1()  →  INTENDED_PATH   invariants hold, ETH may move to the caller
withdraw()  →  THEFT           CEI reentrancy, vaultSolvent breaks
```

| file | what |
|---|---|
| `DualSurface.sol` | the protocol |
| `Invariants.sol` | `vaultSolvent` (theft) · `ammBacked` (swap must keep) |
| `ExploitTheft.sol` | reentrancy PoC |
| `ExploitSwap.sol` | just a swap — not a bug |
| `manifest.json` | track-04 shape, `frontier.expect = theft` |

Mirrored under `benches/fixtures/dual_surface/` so
`python -m trust404.benches` scores it with the other class fixtures.

Do not add this to the track-04 12. Those stay the regression gate.

Harder sibling: [`hostile/`](./hostile/) — owner is slot 2, lottery mixes nonce+salt.
Slot-0 Pwn and a CoinFlip clone both miss.
