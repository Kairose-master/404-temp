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

최초 1회 환경을 준비한다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r agent/requirements.txt
python -c "import solcx; solcx.install_solc('0.8.24'); solcx.set_solc_version('0.8.24'); print(solcx.get_solc_version())"
```

그다음 공개 타깃 12개를 고정 시드와 공식 Forge 검증기로 실행한다.
Foundry가 저장소 루트의 `out/`을 빌드 산출물 경로로 사용하므로, 에이전트 결과는
충돌하지 않는 `demo-results/`에 저장한다.

```bash
source .venv/bin/activate
export TRUST404_VERIFIER=forge
export TRUST404_ENABLE_LLM=0

for t in ReentrantVault OpenVault BadAccounting NaiveOracle DelegateVault \
         PredictableLottery OpenInitializer SafeVault BoundedOwner LibraryVault \
         CommitLottery GuardedInitializer
do
  python agent/agent.py \
    --contract "targets/$t/src/$t.sol" \
    --invariants "targets/$t/Invariants.sol" \
    --manifest "targets/$t/manifest.json" \
    --out "demo-results/$t" \
    --timeout 300 \
    --seed 42 \
    --max-attempts 8

  echo "$t -> exit $?"
done
```

기대 결과는 취약 타깃 7개가 exit `0`(`PROVEN`), 정상 타깃 5개가 exit
`1`(`NOT_PROVEN`)이다. exit `2`는 입력·환경·실행 오류다. 생성된 증명 자료는 다음처럼
확인할 수 있다.

```bash
cat demo-results/OpenVault/attempts.log
python3 -m json.tool demo-results/OpenVault/result.json
cat demo-results/OpenVault/Exploit.sol
```

`exit 2`와 `INCONCLUSIVE (verifier unavailable)`은 취약점 판정이 아니라 검증기
준비 실패다. 위의 solc 확인 명령이 `0.8.24`를 출력하는지 먼저 확인한다.

## 비공개 타깃 실행

아래 명령은 모두 **이 README가 있는 저장소 루트**에서 실행한다. 즉 현재 폴더에
`agent/`, `targets/`, `README.md`가 보여야 한다. 비공개 파일을 저장소 밖의 임의
경로에 둬도 실행할 수 있지만, 경로 혼동을 피하려면 저장소 루트 아래
`private-targets/<타깃 이름>/`에 한 타깃씩 두는 방식을 권장한다.

### 1. 받은 파일 배치

예를 들어 계약 이름이 `MyVault`이고 다음 파일을 받았다고 가정한다.

- 타깃 계약: `MyVault.sol`
- 불변식: `Invariants.sol`
- 배포 정보: `manifest.json`
- 선택 파일: `Setup.s.sol`, import되는 다른 `.sol` 파일

저장소 루트에서 폴더를 만들고 파일을 다음 위치에 복사한다.

```bash
mkdir -p private-targets/MyVault/src
mkdir -p private-results

cp /받은/파일의/절대경로/MyVault.sol \
  private-targets/MyVault/src/MyVault.sol
cp /받은/파일의/절대경로/Invariants.sol \
  private-targets/MyVault/Invariants.sol
cp /받은/파일의/절대경로/manifest.json \
  private-targets/MyVault/manifest.json
```

복사가 끝나면 최소 구조가 정확히 이렇게 보여야 한다.

```text
404-temp/                         # 저장소 루트: 여기서 명령 실행
├── agent/
├── README.md
├── private-targets/              # 비공개 입력 전용, Git에서 제외됨
│   └── MyVault/                  # manifest.json의 source-unit 루트
│       ├── manifest.json         # src/ 안이 아니라 이 위치
│       ├── Invariants.sol        # manifest의 invariants.contract와 일치
│       └── src/
│           └── MyVault.sol       # manifest의 target.src와 일치
└── private-results/              # 실행 후 결과가 생기는 위치, Git에서 제외됨
```

`MyVault.sol`이 `import "./Dependency.sol";`을 사용한다면 import 상대경로를
바꾸지 말고 다음처럼 둔다.

```text
private-targets/MyVault/
├── manifest.json
├── Invariants.sol
└── src/
    ├── MyVault.sol
    └── Dependency.sol            # ./Dependency.sol
```

`import "../interfaces/IVault.sol";`이라면 파일은
`private-targets/MyVault/interfaces/IVault.sol`에 있어야 한다. `@openzeppelin/...`
같은 source-unit 경로를 사용하면 `private-targets/MyVault/@openzeppelin/...` 아래에
같은 구조로 넣는다. import 파일을 `node_modules/`에만 두지 말고
`manifest.json` 아래의 비공개 번들 안에 포함한다.

복잡한 초기 배포를 위해 manifest에 `"setup": "Setup.s.sol"`이 있으면
`private-targets/MyVault/Setup.s.sol`도 반드시 있어야 한다. 이 파일 안의 계약 이름은
`Setup`이어야 하고 `run() returns (address)`가 배포된 타깃 주소를 반환해야 한다.

경로 세 개는 다음처럼 서로 정확히 대응해야 한다.

| 실제 호스트 파일 | `manifest.json` 값 | CLI 인자 |
|---|---|---|
| `private-targets/MyVault/src/MyVault.sol` | `target.src: "src/MyVault.sol"` | `--contract private-targets/MyVault/src/MyVault.sol` |
| `private-targets/MyVault/Invariants.sol` | `invariants.contract: "Invariants.sol"` | `--invariants private-targets/MyVault/Invariants.sol` |
| `private-targets/MyVault/Setup.s.sol` | `deploy.setup: "Setup.s.sol"` | 별도 인자 없음; manifest에서 자동 로드 |

`target.name`은 `MyVault.sol` 안의 실제 계약 이름 `MyVault`와 같아야 한다.
Setup을 받지 않았다면 `deploy.setup` 키를 manifest에 쓰면 안 된다. 생성자 인자는
`deploy.constructor_args`, 초기 ETH는 wei 단위의 `deploy.value_wei`에 적는다.
전체 manifest 예시는 [`QUICKSTART.md`](./QUICKSTART.md)에 있다.

### 2. 로컬에서 실행

가상환경을 활성화한 저장소 루트에서 실행한다.

```bash
TARGET_DIR="$PWD/private-targets/MyVault"

TRUST404_VERIFIER=evm python agent/agent.py \
  --contract "$TARGET_DIR/src/MyVault.sol" \
  --invariants "$TARGET_DIR/Invariants.sol" \
  --manifest "$TARGET_DIR/manifest.json" \
  --out private-results/MyVault --timeout 300 --seed 42 --max-attempts 24
```

`--out private-results/MyVault`는 입력 폴더 안이 아니라 저장소 루트의 출력 전용
폴더를 가리킨다. 실행 후 위치는 다음과 같다.

| 생성 위치 | 내용 |
|---|---|
| `private-results/MyVault/Exploit.sol` | 증명된 PoC, 또는 미발견 시 마지막 후보 |
| `private-results/MyVault/result.json` | 판정, 위반 불변식, 전략, 시도 수와 실행 trace |
| `private-results/MyVault/attempts.log` | 후보 생성·검증·단계 격상 로그 |

종료 코드 `0`일 때만 `Exploit.sol`이 실제로 불변식 위반을 증명한 PoC다. 종료 코드
`1`은 예산 내 미발견, `2` 또는 `INCONCLUSIVE`는 입력·컴파일러·검증기 오류다.
`Setup.s.sol`이 Foundry cheatcode를 사용하면 로컬 EVM 대신 아래 Docker/Forge 경로를
사용한다.

### 3. Docker로 실행하고 결과를 호스트에 보존

먼저 저장소 루트에서 이미지를 한 번 빌드한다.

```bash
docker build --platform linux/amd64 -t track04 -f agent/Dockerfile .
```

Docker에는 호스트 경로가 자동으로 보이지 않는다. 입력 폴더와 출력 폴더를 각각
마운트해야 한다.

```bash
TARGET_DIR="$PWD/private-targets/MyVault"
mkdir -p private-results

docker run --rm \
  -v "$TARGET_DIR:/target:ro" \
  -v "$PWD/private-results:/results" \
  track04 \
  --contract /target/src/MyVault.sol \
  --invariants /target/Invariants.sol \
  --manifest /target/manifest.json \
  --out /results/MyVault \
  --timeout 300 --seed 42 --max-attempts 24
```

이 명령의 경로 대응은 다음과 같다.

| 호스트에서 보이는 경로 | 컨테이너에서 보이는 경로 | 용도 |
|---|---|---|
| `$PWD/private-targets/MyVault` | `/target` | 읽기 전용 입력(`:ro`) |
| `$PWD/private-results` | `/results` | 쓰기 가능한 출력 |
| `$PWD/private-results/MyVault/result.json` | `/results/MyVault/result.json` | 동일한 결과 파일 |

`--out /results/MyVault`이므로 컨테이너가 쓰는 `/results/MyVault/*`는 호스트의
`private-results/MyVault/*`에 즉시 나타난다. 출력 마운트
`-v "$PWD/private-results:/results"`를 빼면 파일이 컨테이너 내부에만 생성되고,
`--rm`으로 컨테이너가 종료될 때 함께 사라진다.

### 4. 불변식과 manifest 없이 소스만 받은 경우

이 경우 표준 증명 CLI에 임의의 manifest를 만들어 넣지 말고 `audit` 모드를 쓴다.
파일 하나라면 `private-targets/source-only/MyVault.sol`, 프로젝트 전체라면
`private-targets/source-only/MyProject/`, zip이면
`private-targets/source-only/MyProject.zip`에 둔다. 프로젝트는 import 상대경로를
보존한 채 폴더 전체를 복사한다.

```bash
mkdir -p private-targets/source-only
mkdir -p audit/MyProject

# 프로젝트 폴더 전체를 분석하는 예
python agent/audit.py private-targets/source-only/MyProject \
  --out audit/MyProject --seed 42 --include-safe
```

감사 결과는 `audit/MyProject/report.json`, `report.md`, `report.sarif`에 생기고,
동적으로 증명된 PoC만 `audit/MyProject/exploits/<Contract>.sol`에 생성된다. 감사
모드는 `result.json`과 `attempts.log`를 만들지 않는다.

Docker에서는 프로젝트와 결과 폴더를 다음처럼 연결한다.

```bash
mkdir -p audit/MyProject

docker run --rm \
  -v "$PWD/private-targets/source-only/MyProject:/target:ro" \
  -v "$PWD/audit/MyProject:/results" \
  track04 audit /target --out /results --seed 42 --include-safe
```

단일 파일을 분석하려면 마지막 입력 `/target`을 `/target/MyVault.sol`로 바꾼다.
zip을 분석하려면 zip이 들어 있는 폴더를 `/target`에 마운트하고 마지막 입력을
`/target/MyProject.zip`으로 바꾼다.

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
