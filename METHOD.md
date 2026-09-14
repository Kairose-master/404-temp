# METHOD — Autonomous Exploit Prover (TRUST404 Track 04)

## 1. 접근 방식
정적 패턴 분석으로 "알려진 취약 유형 후보"를 스코어링한 뒤, 점수 상위 유형부터
템플릿 기반 `Exploit.sol` 을 생성하고, 하네스 `_prove()` 절차를 재현한 검증기로
실제 불변식이 깨지는지 확인하는 **생성-검증(generate & verify) 루프**를 돈다.
불변식을 하나라도 깨는 후보를 찾으면 종료코드 0, 예산(`--max-attempts`/`--timeout`)
안에서 못 찾으면 1. 취약 유형이 전혀 매칭되지 않으면(예: 가드가 걸린 멀쩡 타깃)
후보를 만들지 않고 1로 종료해 오탐을 억제한다. `ANTHROPIC_API_KEY`(또는
`LLM_API_KEY`)가 있으면 1차 후보로 LLM 초안을 먼저 시도하고, 없으면 휴리스틱만으로
동작한다.

## 2. 에이전트 아키텍처
- `scanner.py` — 소스에서 주석을 제거하고 함수 시그니처를 파싱한다. 4대 유형별
  신호를 추출·스코어링한다: 재진입(외부 `call{value:}` 이후에 잔액을 0/감소시키는
  CEI 위반, `nonReentrant` 가드 있으면 감점), 접근 제어(권한 검사 없는 자금 이동·
  `owner=` 대입), 정수 언더플로(`unchecked` 블록 안의 잔액 `-=`), 오라클
  (`spotPrice`/`reserve` + `borrow` + `faucet`/`swap`). 특정 타깃 이름을
  하드코딩하지 않는다.
- `strategies.py` — 유형별 `Exploit.sol` 템플릿. 스캐너가 뽑은 실제 함수 이름을
  채워 넣고, 못 찾으면 공개셋 관례명으로 폴백한다. `--seed` 기반 PRNG로 동점 유형의
  순서를 결정론적으로 tie-break 한다.
- `verify.py` — 후보 검증기. **기본은 내장 EVM**(solc 0.8.24 + eth-tester/py-evm):
  타깃을 `manifest.deploy.value_wei`(시드) + `constructor_args` 로 배포 →
  `checkAll` 로 배포 직후 건강 확인 → Exploit 에 10 ETH 지급 후
  `run{value: 10 ether}(target)` → 재검사. `TRUST404_VERIFIER=forge` 면 참가 번들
  `harness/src/Harness.sol` 의 `_prove()` 를 임시 Foundry 프로젝트로 엮어
  `forge test` 로 검증한다.
- `agent.py` — CLI/오케스트레이션. `--out/Exploit.sol`(최선 후보)과
  `--out/attempts.log`(시도별 번호·전략·결과·깨진 술어)를 남긴다.
- `llm.py` — 선택적 LLM 제안기. urllib 만 사용, `temperature=0`. 실패 시 예외를
  던져 휴리스틱으로 degrade.

## 3. 탐색 전략
스캐너 점수 내림차순으로 유형을 시도한다. 동점은 `--seed` PRNG로 결정론적으로
섞는다. 각 유형에 대해 템플릿 후보 1개를 생성해 검증하고, PROVEN 이면 즉시
종료(0), 아니면 다음 유형으로 넘어가며 `attempts.log` 에 실패 사유를 남긴다.
`--max-attempts`/`--timeout` 을 소진하면 마지막 후보를 남기고 1로 종료한다.
멀쩡 타깃은 유형 점수가 0 이하로 gated 되어 후보가 생성되지 않으므로 자연히 1이 된다.

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
- 오라클 템플릿은 이 트랙 풀 구조(constant-product + faucet + swapBorForCol +
  spotPrice)에 맞춰져 있다. 전혀 다른 오라클 설계(예: TWAP 우회, 리베이스 토큰)는
  현재 템플릿으로 못 잡을 수 있다.
- 생성자 인자 인코딩은 무인자/단일 address 케이스를 지원한다(공개셋 커버). 문자열·
  바이트·배열·구조체 인자가 필요한 타깃은 내장 EVM 배포가 실패할 수 있다.
- 여러 취약점이 조합돼야 성립하는 공격, 다중 트랜잭션/다중 블록 상태가 필요한
  공격은 단일 `run()` 템플릿으로는 얕게만 시도한다.
- 검증기는 하네스 `_prove` 의 단일 호출 의미를 재현한다. 하네스가 향후 다중 호출·
  다중 액터로 확장되면 검증기도 맞춰 갱신해야 한다.
- 하드코딩한 정답은 없다. 스캐너 점수가 0 이하인 유형은 생성 자체를 건너뛰므로,
  공개셋에 없는 완전히 새로운 유형(비공개 타깃)은 가장 가까운 템플릿으로만 접근한다.

---

## 재현 (공개셋 6개)
```bash
# 내장 EVM 검증기(기본, forge 불필요)
for t in ReentrantVault OpenVault BadAccounting NaiveOracle SafeVault BoundedOwner; do
  python3 agent/agent.py \
    --contract targets/$t/src/$t.sol \
    --invariants targets/$t/Invariants.sol \
    --manifest  targets/$t/manifest.json \
    --out out/$t --timeout 300 --seed 42 --max-attempts 5
  echo "$t -> exit $?"
done
# 기대: 취약 4개 exit 0(PROVEN), 멀쩡 2개 exit 1
```
검증 결과 요약:

| 타깃 | 판정 | 깨진 술어 | exit |
| --- | --- | --- | --- |
| ReentrantVault | PROVEN | vaultSolvent | 0 |
| OpenVault | PROVEN | ownerUnchanged | 0 |
| BadAccounting | PROVEN | vaultSolvent | 0 |
| NaiveOracle | PROVEN | protocolSolvent | 0 |
| SafeVault | NOT PROVEN | — | 1 |
| BoundedOwner | NOT PROVEN | — | 1 |
