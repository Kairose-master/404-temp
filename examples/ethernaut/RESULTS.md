# The Ethernaut — 자동 감사 벤치마크

공개 The Ethernaut 레벨을 `agent/audit.py`(불변식 없이 자동 효과검사)로 그대로 돌린 결과.

```bash
python3 agent/audit.py examples/ethernaut --out audit --quick --include-safe
```

멀티버전 solc(0.6/0.7/0.8) in-memory EVM에서 동적으로 증명한다.

## 결과 (10 자동 증명, ~8초)

| 레벨 | 판정 | 전략 | 분류 | 근거 |
|---|---|---|---|---|
| Fallback | ✅ PROVEN | fuzz(contribute→raw send) | SWC-105 | owner 탈취 |
| Fallout | ✅ PROVEN | fuzz(Fal1out) | SWC-105 | owner 탈취 |
| Telephone | ✅ PROVEN | access_control | SWC-105 | owner 탈취(tx.origin) |
| Reentrance | ✅ PROVEN | reentrancy-fuzz | SWC-107 | 자금 유출 10 ETH(0.6 백엔드) |
| Delegation | ✅ PROVEN | **proxy:pwn (2-컨트랙트 배선)** | SWC-112 | fallback→delegatecall 로 owner 탈취 |
| Delegate | ✅ PROVEN | unprotected_init | SWC-118 | 라이브러리 owner 무방비 |
| Vault | ✅ PROVEN | storage:unlock | SWC-136 | private 슬롯 password 읽어 잠금 해제 |
| Privacy | ✅ PROVEN | storage:unlock(bytes16) | SWC-136 | private 슬롯 key 읽어 잠금 해제 |
| Token | ✅ PROVEN | fuzz(transfer) | SWC-101 | 정수 언더플로 토큰 잔액 인플레 |
| CoinFlip | ✅ PROVEN | **multiblock:flip (다중 블록 러너)** | SWC-120 | 블록 엔트로피 예측 → 10연승 |
| King | ⛔ 모델 밖 | — | — | 재등극 차단(그리핑/DoS) |
| Elevator | ⛔ 모델 밖 | — | — | 인터페이스 상태 트릭 |

이번에 추가된 것:
- **2-컨트랙트 배선**: 타깃 생성자가 형제 컨트랙트 주소를 받으면(`Delegation(delegate)`),
  형제를 배포·배선한 뒤 fallback→delegatecall calldata 셀렉터로 성립(Delegation 프록시 본체).
- **다중 블록 러너**: 블록 엔트로피 결과식을 복제한 공격 컨트랙트를 배포하고, 블록을
  넘기며 매 블록 올바른 값으로 호출해 승리 카운터를 임계까지 올림(CoinFlip; Predict 계열 일반화).

## 아직 모델 밖 (정직한 경계)
- **가스·바이트코드 퍼즐 / 사람 추론**: Gatekeeper 1/2/3, Magic Number, Recovery(주소 계산).
- **그리핑/DoS·잔액증가**: King, Denial, Force.
- **인터페이스/제어흐름 트릭**: Elevator, Shop, Switch, GoodSamaritan.
- **더 깊은 다단계 프록시**: Preservation(스토리지 충돌 2단계), Puzzle Wallet, Motorbike.

판정 기준은 **온체인 관찰 효과**(자금 유출 / owner·admin 탈취 / 부채>담보 / 상태 플래그
반전 / 토큰 잔액 인플레 / 예측 카운터 / 불변식 위반)다. 증명 가능한 것만 PROVEN 으로
보고(오탐 0)하고 나머지는 정직히 표기한다. 참고: [`docs/references.md`](../../docs/references.md).
