# The Ethernaut — 자동 감사 벤치마크

공개 The Ethernaut 레벨을 `agent/audit.py`(불변식 없이 자동 효과검사)로 그대로 돌린 결과.

```bash
python3 agent/audit.py examples/ethernaut --out audit --quick --include-safe
```

멀티버전 solc(0.6/0.7/0.8) in-memory EVM에서 동적으로 증명한다.

## 결과 (33 자동 증명)

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
| Force | ✅ PROVEN | **force:selfdestruct** | SWC-132 | selfdestruct 로 받을 수 없는 컨트랙트에 ETH 강제 주입(0→+) |
| Naught Coin | ✅ PROVEN | **lockup-bypass:transferFrom** | SWC-105 | transfer 락업을 approve+transferFrom 으로 우회 → 잔액 0 |
| Denial | ✅ PROVEN | **gas-griefing:withdraw** | SWC-113 | 수신자 콜백 가스 소진으로 withdraw DoS |
| Shop | ✅ PROVEN | **shop:buy (view 콜백 불일치)** | CWE-807 | price() 두 번 신뢰를 조작해 가격 하락 |
| Gatekeeper Two | ✅ PROVEN | **gatekeeper-two:enter** | SWC-105 | 생성자 호출(extcodesize=0)+XOR 키로 게이트 통과 |
| Magic Number | ✅ PROVEN | **magic-number:setSolver** | TR404-CODEGEN | 10바이트 런타임 solver 로 42 반환 |
| Gatekeeper One | ✅ PROVEN | **gatekeeper-one:enter** | SWC-105 | gasleft()%8191 루프 브루트포스 + tx.origin 키 |
| Recovery | ✅ PROVEN | fuzz(destroy) | SWC-106 | 무방비 selfdestruct 로 잃어버린 컨트랙트 자금 탈취 |
| Switch | ✅ PROVEN | **switch:flipSwitch** | SWC-105 | 고정 오프셋(68) 셀렉터 검사를 calldata 배치로 우회 |
| HigherOrder | ✅ PROVEN | **higher-order:registerTreasury** | SWC-105 | uint8 파라미터를 원시 calldata 로 초과 기록 |
| Alien Codex | ✅ PROVEN | **array-underflow:revise** | SWC-136 | 동적배열 length 언더플로 → slot0(owner) 임의 기록 |
| Dex | ✅ PROVEN | **dex-drain:swap** | TR404-ORACLE | 스팟가격 반올림 반복 스왑으로 풀 소진 |
| Dex Two | ✅ PROVEN | **dex-drain:swap** | TR404-ORACLE | 토큰 미검증 swap 으로 풀 소진 |
| Good Samaritan | ✅ PROVEN | **good-samaritan:requestDonation** | CWE-807 | 커스텀 에러 catch → transferRemainder 전액 인출 |
| Gatekeeper Three | ✅ PROVEN | **gatekeeper-three / unprotected_init** | SWC-105 | construct0r owner 선점 + 3게이트 우회 |
| Stake | ✅ PROVEN | **stake-accounting:StakeWETH** | SWC-105 | 가짜 WETH 회계 버그로 실 ETH 인출 |
| Motorbike | ✅ PROVEN | **uninitialized:initialize** | SWC-118 | 초기화 안 된 Engine 의 initialize() 로 upgrader 선점 |
| Puzzle Wallet | ✅ PROVEN | **puzzle-wallet:setMaxBalance** | SWC-112 | 프록시 스토리지 충돌 + 중첩 multicall → admin 탈취 |
| Impersonator | ✅ PROVEN | **ecdsa-malleability:changeController** | SWC-117 | 대칭 서명(v^1,r,N-s)으로 controller 탈취 |

**공개 The Ethernaut 레벨 31종을 자동 증명**한다(위 표; Delegation 파일은 프록시 본체와
라이브러리 두 컨트랙트를 모두 증명). 비취약 헬퍼(Preservation 의 LibraryContract,
Dex/DexTwo 의 내부 Token ERC20)만 단독으로는 제외된다.

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
아래는 아직 자동 증명에 넣지 않은 레벨이다(작업 중):

- **방어형**: DoubleEntryPoint — Forta 탐지 봇을 "구축"하는 레벨로, 공격을 수행하는 익스플로잇이 아니라 방어기를 짜는 문제라 exploit-prover 모델 밖(정직한 경계).
- **초복잡 다단계**: Magic Animal Carousel — 패킹된 캐러셀 스토리지 오버런. 정식 소스를 주시면 Preservation/UniqueNFT 처럼 정확히 재현해 넣겠습니다.

판정 기준은 **온체인 관찰 효과**(자금 유출 / owner·admin 탈취 / 부채>담보 / 상태 플래그
반전 / 토큰 잔액 인플레 / 예측 카운터 / 불변식 위반)다. 증명 가능한 것만 PROVEN 으로
보고(오탐 0)하고 나머지는 정직히 표기한다. 참고: [`docs/references.md`](../../docs/references.md).
