# METHOD — Autonomous Exploit Prover (TRUST404 Track 04)

## 1. 접근 방식 — 자기검증 루프(Self-validation Loop)가 핵심
입력(타깃 `.sol` · 불변식 세트 · 실행 매니페스트)을 읽어, **탐색 → 생성 → 검증 →
(불변식 미위반 시) 탐색·생성 반복** 의 자기검증 루프를 돈다. 한 후보 PoC 가 불변식을
깨지 못하면 거기서 멈추지 않고 **더 강한 방법으로 단계를 격상(escalate)** 해 다시
탐색·생성한다:

```
  0) llm      — (선택) 로컬/원격 LLM 초안 1개
  1) template — 정적 스코어 상위 계열부터 결정론 템플릿 PoC
  2) synth    — 재진입/AMM/플래시론/스토리지/프록시/다중블록/스토리지충돌/그리핑DoS/콜백
                + **계열 게이트**(capability IR). Ethernaut/DVD 솔버는 타깃 이름이
                아니라 `gasleft_modulo`·`unpermissioned_callback` 같은 태그로 발화.
  3) fuzz     — 범용 호출 시퀀스 탐색 — 미공개 타깃 일반화 축
```

각 후보는 하네스 `_prove()` 를 재현한 검증기(`verify.py`)로 **실제 불변식이 깨지는지**
확인한다. 불변식을 하나라도 깨는 후보를 찾으면 종료코드 0 + `Exploit.sol` +
`result.json`(어느 불변식을 **어떻게** 위반했는지 설명), 예산(`--max-attempts`/
`--timeout`)을 소진할 때까지 못 찾으면 1. 실패한 시도마다 `attempts.log` 에 단계·전략·
검증 결과·유지된 불변식을 남겨 루프 진행을 추적한다. 멀쩡 타깃은 모든 단계를 다 돌아도
어떤 후보도 불변식을 깨지 못하므로 자연히 1로 종료(오탐 0). `ANTHROPIC_API_KEY`(또는
`LLM_API_KEY`·`LLM_BASE_URL`)가 있으면 0단계 LLM 초안을 먼저 시도하고, 없으면 1~3단계
휴리스틱/합성/퍼저만으로 오프라인 동작한다.

이 단계 격상 구조 덕에 트랙 CLI(`agent.py`)가 실무 감사 엔진(`api/prove.py`)의 합성·
퍼저 후보를 그대로 검증에 태운다 — 템플릿이 못 잡는 다단계·다중 컨트랙트·미공개 패턴을
퍼저/합성 단계가 이어받는다(예: `arm()→drain()` 2단계 인출은 템플릿 실패 후 퍼저가
`fuzz(arm → drain)` 로 성립).

## 2. 에이전트 아키텍처
- `scanner.py` — 소스에서 주석을 제거하고 함수 시그니처를 파싱한다. 7대 유형별
  신호를 추출·스코어링한다: 재진입(외부 `call{value:}` 이후에 잔액을 0/감소시키는
  CEI 위반, `nonReentrant` 가드 있으면 감점), 접근 제어(권한 검사 없는 자금 이동·
  `owner=` 대입), 정수 언더플로(`unchecked` 블록 안의 잔액 `-=`), 오라클
  (`spotPrice`/`reserve` + `borrow` + `faucet`/`swap`)에 더해, 컨트랙트 워게임
  유도 3종: **delegatecall 하이재킹**(delegatecall 수신자가 함수 파라미터일 때만
  스코어링 — 고정 immutable 모듈은 무점수), **약한 난수**(블록 엔트로피 소스 +
  keccak/모듈로 혼합 + 값 이전이 한 함수에 공존 — 데드라인 체크만으로는 미발화),
  **미보호 initializer**(`owner`/`admin`을 설정하되 `initialized`/`initializer`/
  owner 가드가 없는 initializer). 특정 타깃 이름을 하드코딩하지 않는다.
- `strategies.py` — 유형별 `Exploit.sol` 템플릿. 스캐너가 뽑은 실제 함수 이름을
  채워 넣고, 못 찾으면 공개셋 관례명으로 폴백한다. `--seed` 기반 PRNG로 동점 유형의
  순서를 결정론적으로 tie-break 한다.
- `verify.py` — 후보 검증기. **기본은 내장 EVM**(solc 0.8.24 + eth-tester/py-evm):
  타깃을 `manifest.deploy.value_wei`(시드) + `constructor_args` 로 배포 →
  `checkAll` 로 배포 직후 건강 확인 → Exploit 에 10 ETH 지급 후
  `run{value: 10 ether}(target)` → 재검사. `TRUST404_VERIFIER=forge` 면 참가 번들
  `harness/src/Harness.sol` 의 `_prove()` 를 임시 Foundry 프로젝트로 엮어
  `forge test` 로 검증한다.
- `agent.py` — 트랙 표준 CLI/오케스트레이션. **자기검증 루프의 본체.** `api/prove.py`
  의 `iter_engine_candidates` 로 template→synth→fuzz 후보를 단계별·지연 생성하고, 각
  후보를 `verify.py` 로 검증한다. 검증 실패 시 다음 후보/단계로 격상하며 반복한다.
  산출물: `--out/Exploit.sol`(증명된, 또는 최선 후보), `--out/attempts.log`(단계 격상 ·
  시도별 번호·전략·검증 결과·유지된 불변식), `--out/result.json`(증명 여부 · 위반한
  불변식 · **어떻게** 위반했는지 설명 · 시도 수 · 거친 단계).
- `audit.py` — 실무 감사 CLI. 임의 `.sol`/디렉터리를 받아 불변식 없이도(자동 효과검사)
  엔진 전량을 돌려 심각도별 리포트(JSON/Markdown)와 PoC를 산출한다. 생성자 인자는
  시그니처에서 자동 합성하고, 스크립트/인터페이스/라이브러리는 건너뛴다.
- `llm.py` — 선택적 LLM 제안기. urllib 만 사용, `temperature=0`. 실패 시 예외를
  던져 휴리스틱으로 degrade.

## 3. 탐색 전략 — 단계 격상형 루프
스캐너 점수 내림차순으로 **템플릿 단계**를 먼저 시도한다(동점은 `--seed` PRNG로 결정론
tie-break). 한 후보가 검증에 실패하면 같은 단계의 다음 후보로, 그 단계가 소진되면 다음
단계로 격상한다: template → **synth**(합성: 재진입 예치→인출, 다중 컨트랙트 AMM 조작·
플래시론, private 슬롯 읽기, 프록시 calldata 배선, 다중 블록 러너, delegatecall 스토리지
충돌, 그리핑 DoS, 콜백 불일치) → **fuzz**(호출 시퀀스 탐색: 단일 호출 → setup→drain
2단계, raw 송금·셀렉터 calldata 포함, SliSE 류 데이터 의존 우선순위). 어느 단계에서든
실패하면 다음 단계로 격상하고, **퍼저 단계는 라운드마다 예산·시퀀스 깊이(단일→쌍→3단계)·입력 풀을 키워 점진 심화(progressive deepening)로 시간 예산(`TRUST404_MAX_SECONDS`)까지 끈질기게 재탐색**한다. 불변식을 깨는 후보가 나오면 즉시 종료(0)하고, `--max-attempts`/`--timeout` 을 소진하면
마지막 후보를 남기고 1로 종료한다. 각 실패는 `attempts.log` 에 `[단계/전략] NOT PROVEN
— invariants held (…)` 로 남아 루프가 왜·어떻게 재탐색했는지 보인다. 멀쩡 타깃은 모든
단계를 다 돌아도 어떤 후보도 불변식을 깨지 못하므로 자연히 1(오탐 0).

## 4. LLM 사용 여부와 프롬프트 개요
LLM 은 **선택적 가속**이다. 키가 있으면 `claude-sonnet-5`, `temperature=0` 으로
1차 후보 초안을 요청한다. 프롬프트에는 타깃 소스 전문, `Invariants.sol` 전문,
스캐너 유형 점수 힌트, 불변식 술어 이름을 넣고 "외부 라이브러리 import 없이
`contract Exploit { function run(address) external payable }` 만 출력" 하도록
제약한다. 키가 없거나 네트워크가 막혀 있거나 파싱에 실패하면 곧바로 휴리스틱
템플릿 경로로 degrade 한다 — 공개셋 4개 취약 타깃은 **오프라인(키 없이)** 만으로
모두 PROVEN 됨을 확인했다.

## 5. 결정론 보장 방법
- 무작위성이 필요한 유일한 지점(동점 유형 tie-break)에 `--seed` PRNG를 쓴다.
  같은 seed → 같은 전략 순서 → 같은 `Exploit.sol`(재실행 diff 동일 확인).
- 최종 코드 생성은 항상 결정론적 템플릿 엔진이 담당한다. LLM 은 초안 제안만 하고,
  `temperature=0` 이라도 남는 비결정성 때문에 "보조 후보"로만 취급한다.
- 검증기는 `manifest.determinism`(block_number/timestamp/seed)과 고정 solc
  0.8.24/evm cancun 을 사용한다. 내장 EVM 은 배포 시점 상태가 시드/인자만의
  함수라 실행마다 동일하다.

## 6. 한계
- 오라클: 스팟 조작과 **같은 블록에서 스팟으로 붕괴하는 TWAP**은 합성한다.
  저장된 Observation[] 윈도우는 `run()` 안에서 Foundry HEVM `warp` 로 채운다.
  py-evm 증명은 `run()` 한 번만 호출한다. `prepare`/`finish` 추가 호출로
  증명하지 않는다.
- 생성자 인자는 JSON 배열·문자열·bytes·address[]·**struct/tuple** 을
  컴파일된 constructor ABI 로 인코딩한다. `deploy.setup` 이 있으면
  `Setup.run()` 반환 주소가 타깃이다 (공식 하네스와 같음).
- 교차 컨트랙트: 같은 컴파일 유닛 + 게터로 형제를 `run(address)` 안에 접는다.
  피해자 approve 는 Setup 이 남긴 것만 쓴다. 검증기가 `makeAddr` 이름을
  보고 승인을 만들지 않는다.
- py-evm 증명은 `run()` 한 번. 매니페스트 determinism 으로 NUMBER/TIMESTAMP 를
  고정하고, 0x7109 에서 warp/roll/deal/addr 를 허용한다. Setup.run() 은
  마지막 CREATE 주소를 타깃으로 쓴다. 선언된 Setup 이 실패하면 생성자 폴백 없이
  배포 오류로 끝낸다.
  실제 두 체인·다른 키의 오프라인 서명 트랜잭션은 밖.
- 키 없는 피해자: 남은 allowance 가 없으면 **permissionless `liquidate(address)` /
  skim / rescue** 로 간다 (Handsel MiniVault). Setup 이 `makeAddr("alice")` 를
  쓰면 검증기가 keccak256("alice") 키로 **실제 approve 트랜잭션** 을 보낸다
  (forge-std 와 동일). 파생식 없는 랜덤 EOA 는 밖.
- 소스 없는 외부 프로토콜: 하드코딩 0x + ERC-20/2612/4626/3156/UniV2
  공식 셀렉터 (ethereum/ERCs). 바이트코드 PUSH4 로 계열만 고른다. 디컴파일 없음.
- 여러 블록 커밋-리빌: `prepare` 에서 commit, HEVM `roll` / py-evm `mine_block`
  후 `reveal`. 같은 트랜잭션의 두 번의 호출은 같은 블록이라 안 된다.
- Vyper/순수 Yul 은 `opaque_ir` — 계열 synth 를 건너뛰고 퍼저만 돌린다.
- 숨은 셋 심화(한 `run()`): read-only reentrancy, ERC4626 첫 입금 인플레,
  ERC777/721 훅 재진입, nonce 없는 서명 재사용, CREATE2 변태.
- 여러 취약점이 조합돼야 성립하는 공격, 다중 트랜잭션/다중 블록 상태가 필요한
  공격은 단일 `run()` 템플릿으로는 얕게만 시도한다.
- 검증기는 하네스 `_prove` 의 단일 호출 의미를 재현한다. 하네스가 향후 다중 호출·
  다중 액터로 확장되면 검증기도 맞춰 갱신해야 한다.
- 하드코딩한 정답은 없다. 스캐너 점수가 0 이하인 유형은 생성 자체를 건너뛰므로,
  공개셋에 없는 완전히 새로운 유형(비공개 타깃)은 가장 가까운 템플릿으로만 접근한다.
- 워게임 유도 3종(delegatecall/난수/initializer)도 단일 `run()` 안에서 성립하는
  형태만 다룬다. delegatecall 하이재킹은 슬롯 0 = owner/admin 레이아웃을 가정하며
  (owner/admin 슬롯은 선행 상태변수 개수로 계산해 Pwn 을 패딩한다),
  약한 난수는 블록 엔트로피에 public `nonce`/`seed` 가 섞여 있으면 게터를
  읽어 같은 식을 복제한다.
  initializer는 무인자 또는 단일 address 인자 형태를 지원한다.
- 트랙의 PROVEN 은 **불변식 위반**이다. 수익이 나와도 불변식이 유지되면 미증명.
  (의도된 스왑 vs 도난 같은 라벨 문제는 채점 밖. 노트만: [`docs/FRONTIER.md`](./docs/FRONTIER.md))

---

## 재현 (타깃 12개: 공개셋 6 + 워게임 유도 6)
```bash
# 내장 EVM 검증기(기본, forge 불필요)
for t in ReentrantVault OpenVault BadAccounting NaiveOracle DelegateVault \
         PredictableLottery OpenInitializer SafeVault BoundedOwner LibraryVault \
         CommitLottery GuardedInitializer; do
  python3 agent/agent.py \
    --contract targets/$t/src/$t.sol \
    --invariants targets/$t/Invariants.sol \
    --manifest  targets/$t/manifest.json \
    --out out/$t --timeout 300 --seed 42 --max-attempts 8
  echo "$t -> exit $?"
done
# 기대: 취약 7개 exit 0(PROVEN), 멀쩡 5개 exit 1
```
검증 결과 요약:

| 타깃 | 계열 | 판정 | 깨진 술어 | exit |
| --- | --- | --- | --- | --- |
| ReentrantVault | 재진입 | PROVEN | vaultSolvent | 0 |
| OpenVault | 접근 제어 | PROVEN | ownerUnchanged | 0 |
| BadAccounting | 정수 언더플로 | PROVEN | vaultSolvent | 0 |
| NaiveOracle | 오라클 조작 | PROVEN | protocolSolvent | 0 |
| DelegateVault | delegatecall 하이재킹 | PROVEN | ownerUnchanged | 0 |
| PredictableLottery | 약한 난수 | PROVEN | houseSolvent | 0 |
| OpenInitializer | 미보호 initializer | PROVEN | adminUninitialized | 0 |
| SafeVault | (안전) | NOT PROVEN | — | 1 |
| BoundedOwner | (안전) | NOT PROVEN | — | 1 |
| LibraryVault | (안전) | NOT PROVEN | — | 1 |
| CommitLottery | (안전) | NOT PROVEN | — | 1 |
| GuardedInitializer | (안전) | NOT PROVEN | — | 1 |

`forge test`(`test/Prove.t.sol`)로도 12개 타깃 전부 같은 판정을 검증한다.
