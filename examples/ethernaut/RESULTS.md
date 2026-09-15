# The Ethernaut — 자동 감사 벤치마크

공개된 The Ethernaut 레벨을 `agent/audit.py`(불변식 없이 자동 효과검사)로 그대로 돌린
결과. 재현:

```bash
python3 agent/audit.py examples/ethernaut --out audit --quick --include-safe
```

엔진은 **타깃 pragma에 맞는 solc(0.6/0.7/0.8)** 멀티버전 in-memory EVM에서 동적으로
증명한다. 자산 보유 컨트랙트는 배포 후 별도 '피해자' 계정이 receive/fallback 로 자금을
넣어 유출을 관찰한다.

## 결과 (8 자동 증명, ~8초)

| 레벨 | 판정 | 전략 | 분류 | 근거 |
|---|---|---|---|---|
| Fallback | ✅ PROVEN | fuzz(contribute→raw send) | SWC-105 | owner 탈취 |
| Fallout | ✅ PROVEN | fuzz(Fal1out) | SWC-105 | owner 탈취 |
| Telephone | ✅ PROVEN | access_control | SWC-105 | owner 탈취 (tx.origin) |
| Reentrance | ✅ PROVEN | reentrancy-fuzz(donate→withdraw) | SWC-107 | 자금 유출 10 ETH (0.6 백엔드) |
| Delegation | ✅ PROVEN* | unprotected_init(Delegate.pwn) | SWC-118 | 내부 Delegate 라이브러리 owner 무방비 (*프록시 본체는 2-컨트랙트 배포 배선 필요) |
| Vault | ✅ PROVEN | storage:unlock | SWC-136 | private 슬롯 password 읽어 `locked` 반전 |
| Privacy | ✅ PROVEN | storage:unlock (bytes16) | SWC-136 | private 슬롯 key 읽어 `locked` 반전 |
| Token | ✅ PROVEN | fuzz(transfer) | SWC-101 | 정수 언더플로로 토큰 잔액 인플레 |
| King | ⛔ 모델 밖 | — | — | 재등극 차단(그리핑/DoS) |
| Elevator | ⛔ 모델 밖 | — | — | Building 인터페이스 상태 트릭 |

이번에 추가로 열린 것:
- **멀티버전 solc** — pre-0.8 의미 재현(Reentrance 0.6, Token 언더플로).
- **스토리지 보조** — private 게이트 읽기(Vault/Privacy, bytes16 포함).
- **피해자 자금 시딩** — 자금 보유 컨트랙트의 유출 관찰.
- **ERC20 잔액 인플레 효과 / delegatecall calldata 셀렉터 퍼징 / receive·fallback 트리거.**

## 아직 모델 밖 (정직한 경계)
판정 기준은 **온체인에서 관찰되는 효과**(자금 유출 / owner·admin 탈취 / 부채>담보 /
상태 플래그 반전 / 토큰 잔액 인플레 / 불변식 위반)다. 다음은 별도 확장이 필요하다:
- **다중 블록/트랜잭션**: CoinFlip, Predict the Future (블록마다 1회, N회 연속).
- **가스·EVM 퍼즐**: Gatekeeper 1/2/3, Magic Number, Recovery(주소 계산).
- **그리핑/DoS·잔액증가**: King, Denial, Force.
- **2-컨트랙트 배선/프록시 다단계**: Delegation 프록시 본체, Preservation, Puzzle Wallet, Motorbike.
- **인터페이스/제어흐름 트릭**: Elevator, Shop, Switch, GoodSamaritan.

이들은 대체로 CTF 퍼즐(사람의 추론)이나 다중 블록/다중 컨트랙트 오케스트레이션이
필요하다. 도구는 **증명 가능한 것만 PROVEN 으로 보고**(오탐 0)하고 나머지는 정직히
모델 밖/휴리스틱으로 표기한다. 참고: [`docs/references.md`](../../docs/references.md).
