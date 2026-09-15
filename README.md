# TRUST404 · Track 04 — Autonomous Exploit Prover

스마트컨트랙트 취약점을 **재현 가능한 PoC로 자동 증명**하는 에이전트.
입력(타깃 `.sol`·불변식 세트·매니페스트)을 읽어 **탐색 → 생성 → 검증 → (불변식 미위반 시)
탐색·생성 반복** 의 **자기검증 루프(Self-validation Loop)** 를 돈다. 한 후보 PoC 가
불변식을 못 깨면 멈추지 않고 더 강한 방법으로 단계를 격상한다:
`0) LLM(선택) → 1) 계열 템플릿 → 2) 합성(synth) → 3) 범용 퍼저(fuzz)`. 각 후보는 하네스
`_prove()` 를 재현한 검증기로 실제 불변식 위반을 확인하고, 결과를 `result.json`(위반한
불변식 + **어떻게** 위반했는지)과 `attempts.log`(단계 격상 추적)로 남긴다.

## 제출물 3종
| # | 제출물 | 위치 |
|---|---|---|
| A | 에이전트 코드 + Dockerfile + 표준 CLI | [`agent/`](./agent) |
| B | METHOD.md | [`METHOD.md`](./METHOD.md) |
| C | Exploit.sol PoC (에이전트 산출물) | [`exploits/`](./exploits) |

## 타깃셋 12개 결과 (공개셋 6 + 워게임 유도 6)
| 타깃 | 계열 | 판정 | 깨진 술어 | exit |
|---|---|---|---|---|
| ReentrantVault | 재진입 | PROVEN | vaultSolvent | 0 |
| OpenVault | 접근 제어 | PROVEN | ownerUnchanged | 0 |
| BadAccounting | 정수 언더플로 | PROVEN | vaultSolvent | 0 |
| NaiveOracle | 오라클 조작 | PROVEN | protocolSolvent | 0 |
| DelegateVault | delegatecall 하이재킹 | PROVEN | ownerUnchanged | 0 |
| PredictableLottery | 약한 난수 | PROVEN | houseSolvent | 0 |
| OpenInitializer | 미보호 initializer | PROVEN | adminUninitialized | 0 |
| SafeVault | (CEI + 뮤텍스) | NOT PROVEN | — | 1 |
| BoundedOwner | (타임락 + 상한) | NOT PROVEN | — | 1 |
| LibraryVault | (고정 모듈 delegatecall) | NOT PROVEN | — | 1 |
| CommitLottery | (커밋-리빌 난수) | NOT PROVEN | — | 1 |
| GuardedInitializer | (initialized 가드) | NOT PROVEN | — | 1 |

취약 7개는 자동 증명(정탐), 멀쩡 5개는 미발견(오탐 없음) — 12/12 정확.
각 PoC는 내장 EVM 검증기(`_prove` 절차 재현)에서 불변식 위반을 확인했고,
`forge test`(`test/Prove.t.sol`)로도 같은 판정을 검증한다.

새로 추가한 3개 취약 계열은 잘 알려진 컨트랙트 워게임에서 가져왔다:
**delegatecall 하이재킹**(Ethernaut Delegation/Preservation, Parity),
**약한 난수**(Ethernaut CoinFlip, Capture the Ether "Predict the Future"),
**미보호 initializer**(Ethernaut Motorbike, 초기화 안 된 프록시). 각 취약 타깃마다
같은 표면을 가지지만 안전한 대응 타깃을 함께 넣어 오탐을 억제하는지 검증한다.

## 빠른 시작
```bash
pip install -r agent/requirements.txt
python3 -c "import solcx; solcx.install_solc('0.8.24')"
for t in ReentrantVault OpenVault BadAccounting NaiveOracle DelegateVault \
         PredictableLottery OpenInitializer SafeVault BoundedOwner LibraryVault \
         CommitLottery GuardedInitializer; do
  python3 agent/agent.py --contract targets/$t/src/$t.sol \
    --invariants targets/$t/Invariants.sol --manifest targets/$t/manifest.json \
    --out out/$t --timeout 300 --seed 42 --max-attempts 5
  echo "$t -> exit $?"
done
```
Docker 실행·검증기 두 경로(내장 EVM / forge)는 [`agent/README.md`](./agent/README.md) 참고.

## 웹에서 Foundry로 실제 테스트 (`forge test`)
저장소는 자체 완결형 Foundry 프로젝트입니다. `forge-std` 최소 버전을
`lib/forge-std` 에 벤더링해 별도 다운로드 없이 컴파일되며, 참가 번들 하네스
`harness/src/Harness.sol` 의 `_prove()` 로 12개 타깃을 검증합니다.

```bash
forge test -vv
# 기대: 취약 7개 test_*_PROVEN 통과, 멀쩡 5개 test_*_NOT_PROVEN 통과
```

Claude Code on the web 세션에서는 `.claude/hooks/session-start.sh` 훅이 세션 시작 시
Foundry(forge)를 설치합니다(네트워크 정책이 github.com 다운로드를 허용해야 함).
설치가 막히면 forge 없이 도는 에이전트 내장 EVM 검증기를 쓰세요:
```bash
python3 agent/agent.py --contract targets/ReentrantVault/src/ReentrantVault.sol \
  --invariants targets/ReentrantVault/Invariants.sol \
  --manifest targets/ReentrantVault/manifest.json --out out/ReentrantVault \
  --timeout 300 --seed 42 --max-attempts 5
```

## 실무 감사 CLI — `agent/audit.py`
트랙 하네스(수기 Invariants)가 없어도, **임의의 `.sol` 파일이나 디렉터리**를 그대로
감사해 **동적으로 증명된 취약점 리포트**(JSON + Markdown + PoC)를 뽑는다. 불변식을
안 주면 자동 효과검사(자금 유출 / owner·admin 탈취 / 부채>담보)로 판정하고, 주면 그
불변식으로 증명한다. 생성자 인자는 시그니처에서 자동 합성한다.

```bash
python3 agent/audit.py <파일|디렉터리> --out audit
#   audit/report.md    사람용 리포트 (심각도·SWC/CWE·요약표·수정 가이드·PoC 경로)
#   audit/report.json  기계용
#   audit/report.sarif SARIF 2.1.0 — GitHub code scanning / IDE 업로드용
#   audit/exploits/<Contract>.sol  증명된 PoC
# CI 게이트:  --fail-on critical   (발견 시 exit 3)
# 대규모:     --quick (퍼저 예산 축소) · --max-contracts N (우선순위 상위 N개만)
# 리포트엔 SWC/CWE·소스 위치·수정 코드 diff 가 포함된다.
# The Ethernaut 벤치마크 결과: examples/ethernaut/RESULTS.md

# Docker (엔트리포인트 서브커맨드):
docker build -t track04 -f agent/Dockerfile .
docker run --rm -v "$PWD:/scan" track04 audit /scan --out /scan/audit
```
CI: [`.github/workflows/audit.yml`](./.github/workflows/audit.yml) 가 PR·푸시마다 감사를
돌려 `report.sarif` 를 GitHub code scanning 에 업로드한다(리포트는 아티팩트로 보관). 게이트로
쓰려면 워크플로의 `--fail-on critical` 스텝을 켠다.
동적 증명이 성립하지 않거나 샌드박스가 모델링하지 못하는 계열은 **정적 휴리스틱**으로
잡아 별도 소견(HIGH, "휴리스틱")으로 보고한다 — 예: **수신자 콜백을 mint 이전에 부르는
재진입**과 그 `tx.origin == msg.sender` EOA 게이트가 **EIP-7702(Pectra)** 로 무력화되는
NFT 패턴(코드 보유 EOA 가 콜백 재진입으로 유일성/한도 우회). 동적 증명(PROVEN)과
정적 휴리스틱을 명확히 구분해 오탐 없이 보고한다.

발견마다 **SWC/CWE 표준 분류 + 수정 가이드 + 소스 위치(파일:라인)**를 붙인다. 엔진
전량(스캐너 7계열 템플릿 + 범용 퍼저: 호출 시퀀스 · 재진입 합성 · 다중 컨트랙트 AMM
가격 조작(플래시론식) · 시스템 내부 플래시론 차용자 · 스토리지 보조(private 슬롯 읽기) ·
2-컨트랙트 프록시 배선 · 다중 블록 러너 · delegatecall 스토리지 충돌 2단계 · 그리핑 DoS ·
콜백 반환 불일치)를 그대로 쓰며, 불변식 없이도 자동 효과검사(자금 유출 / owner·admin 탈취 /
부채>담보 / 토큰 잔액 인플레 / 특권 역할 영구 락 / 상태 플래그 반전)로 판정한다. 같은 입력 +
같은 `--seed` → 같은 PoC(결정론).
The Ethernaut 공개 레벨 **12/12 전부 자동 증명**(총 13개 컨트랙트).

## 리서치 & 대시보드
- 참고자료·도구 비교(중국 区块链 연구·MVD-HG·Beosin VaaS·ChainMaker 등): [`docs/references.md`](./docs/references.md)
- 취약점 분석 + 4대 공격 기법 + 최신 논문 정리: [`FINDINGS.md`](./FINDINGS.md)
- 라이브 원버튼 콘솔(배포→생성→실행→증명): https://trust404-prover.vercel.app
- 취약점 분석 대시보드: https://trust404-prover.vercel.app/analysis.html
- 프론트엔드 소스: [`web/index.html`](./web/index.html)

## 레이아웃
```
agent/       에이전트 (agent.py=트랙 CLI·자기검증 루프, audit.py=실무 감사 CLI, scanner, strategies, verify, llm, Dockerfile)
api/prove.py 공용 엔진 — 스캐너/템플릿/합성/퍼저 + iter_engine_candidates(단계별 후보 생성기)
exploits/    타깃별 생성된 Exploit.sol + attempts.log (제출물 C)
harness/     참가 번들 하네스 사본 (forge 검증 경로용)
targets/     타깃 12개 (공개셋 6 + 워게임 유도 6: 취약 7 / 안전 5)
web/         Vercel 배포 프론트엔드
lib/forge-std/  벤더링한 최소 forge-std (다운로드 불필요)
test/        forge test (Prove.t.sol) — 12개 타깃 _prove 검증
foundry.toml Foundry 프로젝트 설정
.claude/     SessionStart 훅 (웹 세션에서 forge 설치)
METHOD.md    제출물 B
FINDINGS.md  취약점/기법/논문 리서치
```
