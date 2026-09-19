# TRUST404 · Track 04 — Autonomous Exploit Prover

스마트컨트랙트 취약점을 **재현 가능한 PoC로 자동 증명**하는 에이전트.
입력(타깃 `.sol` · 불변식 · 매니페스트)을 읽어
**탐색 → 생성 → 검증 → (미위반 시) 단계 격상** 의 자기검증 루프를 돈다.

```
0) LLM(선택)  →  1) 계열 템플릿  →  2) 합성(synth)  →  3) 퍼저(fuzz)
```

각 후보는 하네스 `_prove()` 를 재현한 검증기로 불변식 위반을 확인한다.
깨면 exit 0 + `Exploit.sol` + `result.json` + `attempts.log`.
예산 소진 시 exit 1. 멀쩡한 타깃은 전 단계를 돌아도 안 깨지므로 오탐 0.

방법: [`METHOD.md`](./METHOD.md). 이름 하드코딩 없음 — 소스 capability로 계열 발화.

## 제출물 3종

| # | 제출물 | 위치 |
|---|---|---|
| A | 에이전트 + Dockerfile + 표준 CLI | [`agent/`](./agent) |
| B | METHOD.md | [`METHOD.md`](./METHOD.md) |
| C | Exploit.sol (에이전트 산출) | [`exploits/`](./exploits) |

## 채점 4칸

| 칸 | 이 제출물 |
|---|---|
| PoC가 불변식을 깨는가 | 취약 7/7 PROVEN. 내장 EVM `_prove` 재현 + `forge test` |
| 결정론 | 같은 `--seed` → 바이트 동일 `Exploit.sol` |
| 취약만 깨고 정상은 유지 | 안전 5/5 NOT PROVEN. 오탐 0 |
| 스스로 찾은 경로 · 일반화 | 타깃 이름 없음. 워게임 유도 3계열 + 안전 페어 |

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

취약 7 정탐 · 안전 5 미발견 — **12/12**. 워게임 3계열은 각각 안전 대응 타깃이 있다.

## 빠른 시작

### 브라우저 콘솔 — Docker 권장

Docker Desktop(또는 Docker Engine + Compose)을 실행한 다음, 저장소 루트에서:

```bash
docker compose up --build
```

터미널에 `TRUST404 ready`가 나오면 **http://localhost:8000** 을 연다.
Windows PowerShell, macOS, Linux에서 같은 명령을 사용한다. Compose가 빌드 경로와
`linux/amd64`를 지정하므로 별도 Python·solc·Foundry 설치나 파일 마운트는 필요 없다.
Apple Silicon에서는 Docker의 amd64 에뮬레이션을 사용한다.

1. 공개 타깃의 **Run pipeline**을 누른다. `OpenVault`는 PROVEN,
   `SafeVault`는 NOT PROVEN이 기준이다(미발견은 안전성 보증이 아니다).
2. 내 컨트랙트는 소스를 붙여 넣거나 `.sol`/ZIP을 업로드한 뒤 **분석/증명**을 실행한다.
   ZIP의 import 의존 파일도 함께 넣는다. 결과와 생성된 `Exploit.sol`은 화면에서 확인한다.
3. 종료는 `Ctrl+C`, 백그라운드 실행은 `docker compose up --build -d`,
   종료·정리는 `docker compose down`.

기본 12개 타깃과 Solidity 0.8.24 소스 검증, ZIP 읽기는 **실행 중 인터넷 없이도** 동작한다.
최초 이미지 빌드, 다른 solc 버전 설치, 웹 import 검색, 외부 LLM은 인터넷이 필요하다.
웹 검증은 컨테이너 안의 임시 EVM을 사용하며 실제 체인·지갑에 연결하지 않는다.
웹 실행 결과는 메모리에 있으므로 새로고침하면 사라진다. 파일 산출물을 보관하려면
아래의 CLI 또는 [Docker CLI 안내](agent/README.md#docker)를 사용한다.

상태 확인: `docker compose ps`에서 `healthy`, 로그: `docker compose logs --tail=100 web`.
준비 상태 API는 `http://localhost:8000/api/health`이며 Python 의존성과 solc 설치를 확인한다.

| 증상 | 확인·해결 |
|---|---|
| Docker daemon/pipe 연결 오류 | Docker Desktop이 실행 중인지, Linux containers 모드인지 확인한다. 엔진 접근 권한이 필요하다. |
| 8000 포트 사용 중 | PowerShell: `$env:TRUST404_PORT=8001; docker compose up --build` / bash: `TRUST404_PORT=8001 docker compose up --build`. 이후 localhost:8001로 접속한다. |
| 첫 빌드 다운로드 실패 | 인터넷 연결과 프록시를 확인하고 다시 빌드한다. 실행 시 필요한 solc/Foundry는 이미지에 설치된다. |
| 다른 증명 실행 중(503) | 진행 중인 검증이 끝난 후 재시도한다. 컴파일러 설정 충돌을 막기 위해 증명은 하나씩 실행한다. |

### Python CLI

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

Docker 없이 웹 콘솔을 실행하려면 의존성 설치 후 같은 컴파일러 경로를 준비한다:

```bash
python -c "from api.prove import _ensure_solc; _ensure_solc()"
python scripts/serve.py
```

```bash
forge test -vv
# 취약 7 × test_*_PROVEN · 안전 5 × test_*_NOT_PROVEN
```

## 레이아웃

```
agent/        A — agent.py (트랙 CLI), Dockerfile, scanner, strategies, verify
METHOD.md     B
exploits/     C — 타깃별 Exploit.sol + attempts.log + result.json
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
