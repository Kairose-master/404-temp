# The Ethernaut — 자동 감사 벤치마크

공개된 The Ethernaut 레벨 컨트랙트를 `agent/audit.py`(불변식 없이 자동 효과검사)로
그대로 돌린 결과. 재현:

```bash
python3 agent/audit.py examples/ethernaut --out audit --quick --include-safe
```

엔진은 **타깃 pragma에 맞는 solc(0.6/0.7/0.8)** 로 컴파일하는 멀티버전 in-memory EVM에서
동적으로 증명한다. 자산 손실 레벨은 배포 후 별도 '피해자' 계정이 receive/fallback 로
컨트랙트에 자금을 넣어(실제로 자금을 든 컨트랙트를 흉내) 유출을 관찰한다.

## 결과 (6/7 자동 증명, ~10초)

| 레벨 | 판정 | 전략 | 근거 |
|---|---|---|---|
| Fallback | ✅ PROVEN | fuzz(contribute→raw send) | owner 탈취 |
| Fallout | ✅ PROVEN | fuzz(Fal1out) | owner 탈취 |
| Telephone | ✅ PROVEN | access_control | owner 탈취 (tx.origin) |
| Reentrance | ✅ PROVEN | reentrancy-fuzz(donate→withdraw) | 자금 유출 10 ETH (원본 0.6 백엔드) |
| Delegation | ✅ PROVEN | unprotected_init(Delegate.pwn) | owner 탈취 (내부 Delegate 무방비) |
| Vault | ✅ PROVEN | storage:unlock | private 슬롯의 password 를 읽어 `locked` 반전 |
| Elevator | ⛔ 모델 밖 | — | Building 인터페이스 상태 트릭(자산·권한 효과 없음) |

이번에 열린 것: **멀티버전 solc**(pre-0.8 정수 래핑 재현 → Reentrance 0.6),
**스토리지 보조**(private 게이트 → Vault), **피해자 자금 시딩**(자금 보유 컨트랙트의 유출 관찰).

## 아직 모델 밖 (정직한 경계)
판정 기준은 **온체인에서 관찰되는 효과**(자금 유출 / owner·admin 탈취 / 부채>담보 /
상태 플래그 반전 / 불변식 위반)다. 다음은 별도 확장이 필요하다:
- **다중 블록/트랜잭션**: CoinFlip, Predict the Future (블록마다 1회, N회 연속) — 다중 블록 러너 필요.
- **가스·EVM 퍼즐**: Gatekeeper 1/2/3, Magic Number, Denial(가스 소진 DoS).
- **잔액 증가/DoS**: Force(selfdestruct 강제 송금), King(재등극 차단).
- **프록시/계산된 calldata 다단계**: Delegation 프록시 자체(fallback→delegatecall), Puzzle Wallet, Motorbike.
- **다른 자산 축**: Token/Naught Coin(ERC20 잔액), AlienCodex(배열) — 효과검사를 토큰 잔액까지 확장 필요.

참고자료·도구 비교: [`docs/references.md`](../../docs/references.md).
