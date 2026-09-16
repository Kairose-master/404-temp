# HostileDesk

트랙 12가 아니다. DualSurface가 라벨이면 이건 **모양**.

슬롯 0은 `totalDeposits`. owner는 슬롯 2. 로또는 `keccak(blockhash, nonce, salt)`.

| 경로 | 슬롯 0 Pwn | CoinFlip 클론 | 엔진 (PR #11) |
|---|---|---|---|
| `execute` → sweep | 빗나감 | — | pad 2칸, `ownerUnchanged` 깨짐 |
| `play` | — | 짐 | `nonce()`/`salt()` 읽고 같은 식 |

`deposit`/`withdraw`는 CEI가 맞다. 그게 버그가 아니다.

파일: `HostileDesk.sol` · `Invariants.sol` · `ExploitSlot.sol` · `ExploitMix.sol`.
