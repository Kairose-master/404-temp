# TRUST404 · Track 04 — Autonomous Exploit Prover

스마트컨트랙트 취약점을 **재현 가능한 PoC로 자동 증명**하는 에이전트.
입력(타깃 `.sol` · 불변식 · 매니페스트)을 읽어
**탐색 → 생성 → 검증 → (미위반 시) 단계 격상** 의 자기검증 루프를 돈다.

```
0) LLM(명시적 개발 모드)  →  1) 계열 템플릿  →  2) 합성(synth)  →  3) 퍼저(fuzz)
```

각 후보는 하네스 `_prove()` 를 재현한 검증기로 불변식 위반을 확인한다.
깨면 exit 0 + `Exploit.sol` + `result.json` + `attempts.log`.
예산 소진 시 exit 1. 멀쩡한 타깃은 전 단계를 돌아도 안 깨지므로 오탐 0.

방법: [`METHOD.md`](./METHOD.md). 공개 타깃은 `targets/` 회귀 fixture에만 두고,
표준 엔진은 입력 소스의 capability·ABI·불변식 의존성으로 후보를 도출한다.

## 제출물 3종

| # | 제출물 | 위치 |
|---|---|---|
| A | 에이전트 + Dockerfile + 표준 CLI | [`agent/`](./agent) |
| B | METHOD.md | [`METHOD.md`](./METHOD.md) |
| C | Exploit.sol (에이전트 산출 원본) | [`Exploit.sol`](./Exploit.sol) |

## 트랙 심사 기준 대응

| 칸 | 이 제출물 |
|---|---|
| PoC가 실행되어 불변식을 깨는가 | 취약 7/7 PROVEN. 제출 Docker의 기본 검증기는 `forge test --offline` |
| 결정론 | LLM을 끈 고정 이미지에서 같은 `--seed` → 바이트 동일 `Exploit.sol` |
| 취약만 깨고 정상은 유지 | 안전 5/5 NOT PROVEN. 오탐 0 |
| 스스로 찾은 경로인가 | 입력 source/ABI 근거와 실제 호출 trace를 `result.json`에 기록하며 타깃 이름으로 분기하지 않음 |
| 비공개 일반화·최소 PoC | 복합 ABI·깊이 3까지 점진 탐색하고, 발견 경로를 호출 삭제 재실행으로 축약한 뒤 Forge 재검증 |

## 타깃 12개 (공개 6 + 워게임 유도 6)

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

취약 7 정탐 · 정상 회귀 타깃 5 미발견 — **12/12**. `NOT_PROVEN`은 안전성 증명이
아니라 주어진 탐색 예산에서 재현 가능한 위반을 찾지 못했다는 뜻이다.

## 빠른 시작

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r agent/requirements.txt
python3 -c "import solcx; solcx.install_solc('0.8.24')"
for t in ReentrantVault OpenVault BadAccounting NaiveOracle DelegateVault \
         PredictableLottery OpenInitializer SafeVault BoundedOwner LibraryVault \
         CommitLottery GuardedInitializer; do
  python3 agent/agent.py \
    --contract   targets/$t/src/$t.sol \
    --invariants targets/$t/Invariants.sol \
    --manifest   targets/$t/manifest.json \
    --out out/$t --timeout 300 --seed 42 --max-attempts 8
  echo "$t -> exit $?"
done
# 기대: 취약 7개 exit 0, 멀쩡 5개 exit 1
```

CLI·검증기 두 경로(내장 EVM / forge)와 Docker 실행: [`agent/README.md`](./agent/README.md).

```bash
forge test -vv
# 취약 7 × test_*_PROVEN · 안전 5 × test_*_NOT_PROVEN
```

## 레이아웃

```
agent/        A — agent.py (트랙 CLI), Dockerfile, scanner, strategies, verify
METHOD.md     B
Exploit.sol   C — 에이전트가 OpenVault에서 생성한 제출용 PoC 원본
exploits/     공개·확장 타깃별 실행 결과 보관
targets/      공개 12 (취약 7 / 안전 5)
harness/      참가 번들 _prove() 사본
test/         forge (Prove.t.sol)
```

## 트랙 밖

채점 입구가 아니다. 엔진 진화·한계 노트.

- 한계절 확장: [`docs/FRONTIER.md`](./docs/FRONTIER.md) · 예제 [`examples/frontier/`](./examples/frontier/)
- 계열별 취약 컨트랙트: [`examples/families/`](./examples/families/)
- 엔진 로그: [`ARCHITECTURE.md`](./ARCHITECTURE.md)
- 참고자료: [`docs/references.md`](./docs/references.md) · [`FINDINGS.md`](./FINDINGS.md)
- 임의 `.sol` 감사 CLI: `python3 agent/audit.py <파일|디렉터리> --out audit`
