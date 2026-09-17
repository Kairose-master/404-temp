# Autonomous Exploit Prover — 에이전트 (제출물 A)

TRUST404 Track 04. 타깃 스마트컨트랙트를 입력받아 취약 유형을 스코어링하고,
유형별 템플릿으로 `Exploit.sol` 을 결정론적으로 생성한 뒤, 하네스 `_prove()`
절차를 재현한 검증기로 실제 불변식이 깨지는지 확인한다.

## 표준 CLI
```
python3 agent/agent.py --contract <path> --invariants <path> --manifest <path> \
                       --out <dir> --timeout <sec> --seed <int> --max-attempts <int>
```
| 종료코드 | 의미 |
|---|---|
| 0 | 불변식을 1개 이상 깨는 `Exploit.sol` 확보 (`--out/Exploit.sol`) |
| 1 | 예산 내 미발견 (`--out/Exploit.sol` 에 마지막 후보, 증명 아님) |
| 2 | 입력/검증기/내부 오류 (검증기 부재 포함 — 미발견과 합치지 않음) |

산출물: `--out/Exploit.sol`(최선 후보), `--out/attempts.log`(시도별 로그).

## 구성
| 파일 | 역할 |
|---|---|
| `agent.py` | CLI·오케스트레이션·생성-검증 루프·종료코드 |
| `scanner.py` | 정적 분석: 함수 시그니처 추출 + 4대 유형 스코어링 |
| `strategies.py` | 유형별 `Exploit.sol` 템플릿 + seed 기반 결정론 순서 |
| `verify.py` | 후보 검증기(내장 EVM 기본 / forge 선택) — `_prove` 재현 |
| `llm.py` | 선택적 LLM 초안 제안기(`temperature=0`, 없어도 degrade) |

## 검증기 두 경로
- **내장 EVM (기본)**: `solc 0.8.24` + `eth-tester`/`py-evm`. forge·네트워크 불필요.
  타깃을 `value_wei` 시드 + `constructor_args` 로 배포 → `checkAll` 건강 확인 →
  Exploit 에 10 ETH 지급 후 `run{value:10 ether}` → 재검사.
- **forge (선택)**: `TRUST404_VERIFIER=forge` + `TRUST404_HARNESS_DIR=<harness>` 로
  참가 번들 `harness/src/Harness.sol` 의 `_prove()` 를 `forge test` 로 실행.

## Docker

### 1. 빌드 — build context 는 반드시 저장소 루트(`.`)
```bash
# 반드시 번들 최상위(404-temp/)에서 실행한다.
docker build --platform linux/amd64 -t track04 -f agent/Dockerfile .
```
- **끝의 `.` 이 build context.** Dockerfile 은 `agent/`·`harness/`·`api/`·
  `trust404/`·`lib/`·`targets/` 를 모두 `COPY` 하므로 context 가 저장소 루트여야
  한다. `docker build -t track04 ./agent` 처럼 `./agent` 를 주면 Docker 가 나머지
  폴더를 못 봐서 `COPY harness ...` 단계에서 실패한다.
- **`-f agent/Dockerfile`** 로 Dockerfile 위치만 따로 알려준다(context 와 별개).
- **`--platform linux/amd64`** 는 Apple Silicon(ARM) Mac 에서 필수다. 이미지는
  x86-64 `solc 0.8.24` 를 넣으므로 Dockerfile 이 amd64 를 명시적으로 요구한다.

### 2. 내장 타깃 실행 — 이름만 바꿔서
```bash
# 타깃 이름을 변수에 넣는다. <T> 처럼 꺾쇠를 그대로 쓰면 shell(zsh/bash)이
# 리다이렉션으로 해석해 "no such file or directory: T" 로 죽는다. 반드시 치환할 것.
T=ReentrantVault
docker run --rm -v "$PWD:/w" track04 \
  --contract   /w/targets/$T/src/$T.sol \
  --invariants /w/targets/$T/Invariants.sol \
  --manifest   /w/targets/$T/manifest.json \
  --out /w/out/$T --seed 42 --max-attempts 5
```
`-v "$PWD:/w"` 로 저장소를 컨테이너의 `/w` 에 마운트하고, `--out /w/out/$T` 로
결과(`Exploit.sol`·`result.json`·`attempts.log`)를 호스트로 되돌려 받는다.
사용 가능한 이름: `ReentrantVault OpenVault BadAccounting NaiveOracle DelegateVault
PredictableLottery OpenInitializer SafeVault BoundedOwner LibraryVault CommitLottery
GuardedInitializer`.

12개 전부 한 번에:
```bash
for T in ReentrantVault OpenVault BadAccounting NaiveOracle DelegateVault \
         PredictableLottery OpenInitializer SafeVault BoundedOwner LibraryVault \
         CommitLottery GuardedInitializer; do
  docker run --rm -v "$PWD:/w" track04 \
    --contract   /w/targets/$T/src/$T.sol \
    --invariants /w/targets/$T/Invariants.sol \
    --manifest   /w/targets/$T/manifest.json \
    --out /w/out/$T --seed 42 --max-attempts 8
  echo "$T -> exit $?"   # 취약 7개 exit 0, 멀쩡 5개 exit 1
done
```

### 3. 임의의 컨트랙트 실행 — 어떤 `.sol` 이든
불변식(`Invariants.sol`)과 매니페스트(`manifest.json`)가 **있으면** 트랙 CLI 를
그대로 쓴다. 컨트랙트가 저장소 밖에 있으면 그 폴더를 마운트하면 된다:
```bash
docker run --rm \
  -v "$PWD:/w" \
  -v "/absolute/path/to/MyProject:/proj" \
  track04 \
  --contract   /proj/src/MyVault.sol \
  --invariants /proj/Invariants.sol \
  --manifest   /proj/manifest.json \
  --out /w/out/MyVault --seed 42 --max-attempts 8
```
불변식·매니페스트가 **없으면** `audit` 서브커맨드로 라우팅한다. 생성자 인자를
시그니처에서 자동 합성하고 자동 효과검사로 엔진 전량을 돌려 심각도별 리포트
(JSON/Markdown)와 PoC 를 낸다. 파일 하나든 디렉터리든 받는다:
```bash
# 파일 하나
docker run --rm -v "$PWD:/w" track04 audit /w/path/to/MyContract.sol --out /w/audit
# 디렉터리 전체(스크립트/인터페이스/라이브러리는 건너뜀)
docker run --rm -v "$PWD:/w" track04 audit /w/contracts --out /w/audit
```
`audit` 매니페스트 스키마와 불변식 작성법은 `targets/*/manifest.json` 과
`targets/*/Invariants.sol` 을 그대로 본떠 쓰면 된다.

### 옵션·환경변수
- `--seed <int>` 결정론 시드(같은 시드 → 바이트 동일 산출). `--max-attempts <int>`
  후보 예산. `--timeout <sec>` 시간 예산.
- `-e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY` 를 주면 0단계 LLM 초안을 먼저 시도하고,
  없으면 오프라인 휴리스틱/합성/퍼저만으로 동작한다(네트워크 불필요).
- `-e TRUST404_VERIFIER=forge` 로 검증기를 py-evm 대신 Foundry `forge test` 경로로
  바꾼다(이미지에 Foundry 1.7.1·vendored `forge-std` 포함).

이미지는 빌드 시 `solc 0.8.24`, Foundry **1.7.1**, vendored `forge-std` 를 넣으므로
실행 시 네트워크가 없어도 된다. 기본 검증기는 py-evm.

## 로컬 실행 (Docker 없이)
```bash
pip install -r agent/requirements.txt
python3 -c "import solcx; solcx.install_solc('0.8.24')"
python3 agent/agent.py --contract targets/ReentrantVault/src/ReentrantVault.sol \
  --invariants targets/ReentrantVault/Invariants.sol \
  --manifest targets/ReentrantVault/manifest.json \
  --out out/ReentrantVault --timeout 300 --seed 42 --max-attempts 5
```

## 공개셋 결과
취약 4개(Reentrant/Open/BadAccounting/NaiveOracle) → exit 0(PROVEN),
멀쩡 2개(SafeVault/BoundedOwner) → exit 1. 자세한 내용은 `../METHOD.md`.
