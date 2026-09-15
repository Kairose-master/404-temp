# The Ethernaut — 자동 감사 벤치마크

공개된 The Ethernaut 워게임 레벨 컨트랙트를 `agent/audit.py`(불변식 없이 자동 효과검사)
로 그대로 돌린 결과다. 재현:

```bash
python3 agent/audit.py examples/ethernaut --out audit --quick --include-safe
```

엔진은 **solc 0.8.24 고정** in-memory EVM에서 동적으로 증명한다. 자산 손실 레벨은
Ethernaut 인스턴스가 ETH로 시드되는 것을 흉내 내려고 생성자를 `payable` 로 두었다
(그 외 로직은 원본 유지).

## 결과

| 레벨 | 판정 | 근거 | 비고 |
|---|---|---|---|
| Fallback | ✅ PROVEN (CRITICAL) | owner 탈취 → 인출 | `contribute{1}` 후 receive()로 소유권 탈취 |
| Fallout | ✅ PROVEN (CRITICAL) | owner 탈취 | 오타 생성자 `Fal1out()` 호출 |
| Telephone | ✅ PROVEN (CRITICAL) | owner 탈취 | `tx.origin != msg.sender` — 공격 컨트랙트 경유 |
| Delegation | ✅ PROVEN (CRITICAL) | owner 탈취 | 내부 `Delegate.pwn()` 이 무방비(권한 없이 owner 설정)로 증명됨. 단, 프록시 fallback 경유 delegatecall(계산된 calldata)은 아직 모델 밖 |
| Reentrance | ⚠️ 휴리스틱 | 정적 재진입 신호 | **solc 0.8 경계**: 원본은 0.6. `balances -= amount` 가 0.8 검사수학에서 언더플로 리버트라 순진한 재진입이 성립 안 함. `=0` 스타일(우리 ReentrantVault)은 0.8에서 증명됨 |
| King | ⛔ 모델 밖 | — | 그리핑/DoS(자산 손실·권한 변경 아님) |
| Elevator | ⛔ 모델 밖 | — | 인터페이스 상태 트릭(자산/권한 효과 없음) |
| Vault | ⛔ 모델 밖 | — | private 저장 슬롯의 비밀 읽기(오프체인 스토리지 조회 필요) |

**요약: 소유권/접근제어 계열 4개 자동 증명(PoC 포함), 1개 정적 플래그, 3개 모델 밖.**
약 8초(`--quick`).

## 왜 "전부"는 아직 아닌가 (정직한 경계)

이 도구의 판정 기준은 **온체인에서 관찰되는 효과** — 자금 유출 / owner·admin 탈취 /
부채>담보 / (불변식 제공 시) 임의 술어 위반 — 이다. 다음은 그 모델을 벗어난다:

- **오프체인 추론**: Vault·Privacy(스토리지 슬롯 읽기), Recovery(주소 계산).
- **다중 블록/트랜잭션**: CoinFlip, Predict the Future(블록마다 1회, N회 연속).
- **가스·EVM 퍼즐**: Gatekeeper 1/2/3, Magic Number, Denial(가스 소진 DoS).
- **잔액 증가/DoS**: Force(selfdestruct 강제 송금), King(재등극 차단).
- **pre-0.8 검사수학**: Token·AlienCodex(오버·언더플로) — 0.8.24 고정이라 재현 안 됨.
- **계산된 calldata/프록시 다단계**: Delegation fallback, Puzzle Wallet, Motorbike.

이들은 향후 (a) 스토리지 슬롯 리더, (b) 다중 트랜잭션/다중 블록 시나리오, (c) 선택적
solc 버전(0.6/0.7) 백엔드, (d) fallback 용 calldata 합성으로 확장 가능하다. 현재는
**증명할 수 있는 것만 PROVEN 으로 보고**하고(오탐 0 유지), 나머지는 휴리스틱 또는
모델 밖으로 정직하게 표기한다.
