# benches

Public-exploit eval adapters. Upstream trees are **not** vendored.

```
python3 -m trust404.benches
```

Always scores the local class fixtures under `fixtures/`. Prints
`NOT_ATTACHED` for VERITE / SCONE / EVMbench / PoCo until you set:

| env | dataset |
|---|---|
| `TRUST404_VERITE_DIR` | Verite incident dumps |
| `TRUST404_SCONE_DIR` | SCONE-bench (post-cutoff split) |
| `TRUST404_EVMBENCH_DIR` | EVMbench 117 |
| `TRUST404_POCO_DIR` | Proof-of-Patch 23 |

Local fixtures are the frontier, not a substitute for those numbers:

| fixture | expect | why it exists |
|---|---|---|
| `profit_drain` | theft | invariant break ∧ ETH out |
| `grief_lock` | grief | break ∧ no extract (profit-only agents miss) |
| `intended_arb` | intended_path | extract ∧ invariants hold — **not a bug** |
| `cross_router` | cross-contract shape | ReX failure mode; world planner must see 3 contracts |
| `dual_surface` | theft (+ intended_path) | same pot, two labels — `examples/frontier/` |

See [`docs/FRONTIER.md`](../docs/FRONTIER.md).
