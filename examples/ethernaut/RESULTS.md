# The Ethernaut — 자동 감사 벤치마크

공개 The Ethernaut 레벨을 `agent/audit.py`(불변식 없이 자동 효과검사)로 그대로 돌린 결과.

```bash
python3 agent/audit.py examples/ethernaut --out audit --quick --include-safe
```

멀티버전 solc(0.6/0.7/0.8) in-memory EVM에서 동적으로 증명한다.

## 결과 (13 자동 증명, ~11초)

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
| Preservation | ✅ PROVEN | **storage-collision:setFirstTime (2단계 delegatecall)** | SWC-112 | 라이브러리 포인터 덮어쓰기 → owner 탈취 |
| King | ✅ PROVEN | **king-dos:king (그리핑 DoS)** | SWC-113 | revert-receive 로 특권 역할 영구 락 |
| Elevator | ✅ PROVEN | **callback-inconsistency:goTo** | CWE-807 | 외부 콜백 false→true 로 상태 플래그(top) 반전 |

레벨 기준 **12/12 전부 자동 증명**. Delegation 파일은 프록시 본체와 라이브러리 두
컨트랙트를 모두 증명해 총 13개 컨트랙트 정탐(Preservation 의 LibraryContract 헬퍼만
단독으로는 비취약이라 제외).

이번에 추가된 것:
- **콜백 반환 불일치(Elevator)**: 타깃이 외부 인터페이스(대개 `IName(msg.sender)`)의 bool
  반환 메서드를 한 함수 안에서 두 번 호출해 분기·상태전이를 결정하는 구조를 탐지한다.
  공격 컨트랙트가 그 메서드를 호출마다 false→true 로 구현하면 정직한 구현이라면 불가능한
  상태 플래그(`top`) 반전을 강제한다. 배포 시 플래그가 false 인지 확인하고, 공격 후 true 로
  뒤집히는지로 증명한다(오탐 억제).
- **그리핑 DoS(King)**: 특권 역할이 push 송금(`payable(role).transfer(...)`)으로 이전 보유자에게
  환불하면서 `role = msg.sender` 로 갱신하는 구조를 탐지한다. revert 하는 `receive()` 를 가진
  공격 컨트랙트가 역할을 차지하면 이후 정상 응찰의 환불 송금이 revert 해 역할이 영구 락된다.
  베이스라인(EOA 순차 응찰)은 성공하지만 공격 후 동일 응찰이 revert(status 0)하는지로 DoS 를
  증명한다(오탐 억제; pull-payment 안전본은 `.transfer` 미검출로 자동 제외).
- **delegatecall 스토리지 충돌 2단계(Preservation)**: 타깃이 상태변수에 저장된 라이브러리
  주소로 `delegatecall(setTime(uint256))` 하는 구조를 탐지한다. 1단계로 공격 라이브러리를
  가리키도록 라이브러리 포인터(슬롯)를 덮어쓰고, 2단계로 그 라이브러리가 특권 슬롯(owner)을
  `msg.sender` 로 세팅한다. 타깃+공격 라이브러리를 함께 컴파일·배선해 owner 탈취를 관찰한다.
- **2-컨트랙트 배선**: 타깃 생성자가 형제 컨트랙트 주소를 받으면(`Delegation(delegate)`),
  형제를 배포·배선한 뒤 fallback→delegatecall calldata 셀렉터로 성립(Delegation 프록시 본체).
- **다중 블록 러너**: 블록 엔트로피 결과식을 복제한 공격 컨트랙트를 배포하고, 블록을
  넘기며 매 블록 올바른 값으로 호출해 승리 카운터를 임계까지 올림(CoinFlip; Predict 계열 일반화).

## 아직 모델 밖 (정직한 경계)
- **가스·바이트코드 퍼즐 / 사람 추론**: Gatekeeper 1/2/3, Magic Number, Recovery(주소 계산).
- **그리핑/DoS·잔액증가**: Denial, Force. (King 은 이제 자동 증명 — 위 표 참조.)
- **인터페이스/제어흐름 트릭**: Shop, Switch, GoodSamaritan. (Elevator 는 이제 자동 증명 — 위 표 참조.)
- **더 깊은 다단계 프록시**: Puzzle Wallet, Motorbike.
  (Preservation 은 이제 자동 증명 — 위 표 참조.)

판정 기준은 **온체인 관찰 효과**(자금 유출 / owner·admin 탈취 / 부채>담보 / 상태 플래그
반전 / 토큰 잔액 인플레 / 예측 카운터 / 불변식 위반)다. 증명 가능한 것만 PROVEN 으로
보고(오탐 0)하고 나머지는 정직히 표기한다. 참고: [`docs/references.md`](../../docs/references.md).
