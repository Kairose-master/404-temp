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

산출물: `--out/Exploit.sol`(증명된 후보 또는 마지막 후보),
`--out/attempts.log`(시도별 로그), `--out/result.json`(판정·위반 불변식·도출 근거·
호출 trace·퍼저 최소화 결과). `NOT_PROVEN`은 예산 내 미발견이며 안전성 증명을 뜻하지 않는다.

## 구성
| 파일 | 역할 |
|---|---|
| `agent.py` | CLI·오케스트레이션·생성-검증 루프·종료코드 |
| `scanner.py` | 정적 분석: 함수 시그니처 추출 + 7개 취약 유형 스코어링 |
| `strategies.py` | 유형별 `Exploit.sol` 템플릿 + seed 기반 결정론 순서 |
| `verify.py` | 후보 검증기(제출 Docker는 Foundry 기본 / 로컬 EVM 보조) — `_prove` 재현 |
| `llm.py` | 명시적 개발 모드용 LLM 초안 제안기(제출 Docker에서는 비활성) |

## 검증기 두 경로
- **Foundry (제출 Docker 기본)**: 고정된 Foundry 1.7.1과 참가 번들
  `harness/src/Harness.sol`로 `forge test --offline`을 실행한다. 주최 측 표준 채점
  의미와 같은 경로이며 별도 환경변수가 필요 없다.
- **내장 EVM (로컬 개발 보조)**: `TRUST404_VERIFIER=evm`으로 선택한다.
  `solc 0.8.24` + `eth-tester`/`py-evm`을 사용하며,
  타깃을 `value_wei` 시드 + `constructor_args` 로 배포 → `checkAll` 건강 확인 →
  Exploit 에 10 ETH 지급 후 `run{value:10 ether}` → 재검사.
  두 경로 모두 후보 자체의 revert는 다음 후보로 진행하고, Setup·배포·초기 불변식
  실패는 exit 2로 종료한다.

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
  --out /w/demo-results/$T --seed 42 --max-attempts 5
```
`-v "$PWD:/w"` 로 저장소를 컨테이너의 `/w` 에 마운트하고,
`--out /w/demo-results/$T` 로 결과(`Exploit.sol`·`result.json`·`attempts.log`)를
호스트로 되돌려 받는다. 저장소의 `out/`은 Foundry 빌드 산출물 경로이므로 에이전트
결과 경로로 사용하지 않는다.
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
    --out /w/demo-results/$T --seed 42 --max-attempts 8
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
  --out /w/demo-results/MyVault --seed 42 --max-attempts 8
```
불변식·매니페스트가 **없으면** `audit` 서브커맨드로 라우팅한다. 생성자 인자를
시그니처에서 자동 합성하고 자동 효과검사로 엔진 전량을 돌려 심각도별 리포트
(JSON/Markdown/SARIF)와 PoC 를 낸다. 파일 하나·디렉터리·**zip** 을 받는다.

**컨트랙트를 어디에 두나 (중요).** 컨테이너 안은 호스트와 분리돼 있으므로, 감사할
파일은 반드시 **마운트한 경로 안**에 있어야 한다. `-v "$PWD:/w"` 는 지금 폴더를
컨테이너의 `/w` 로 연결하는 것이라, 인자 경로도 `/w/...` 로 줘야 한다. 컨테이너
바깥(호스트 절대경로)을 그대로 주면 "파일 없음"이 난다.

```bash
# 1) 파일 하나 — 지금 폴더 기준 상대경로가 /w 아래로 매핑된다
docker run --rm -v "$PWD:/w" track04 audit /w/MyContract.sol --out /w/audit

# 2) 폴더가 다른 곳에 있으면 그 폴더를 통째로 마운트
docker run --rm \
  -v "$PWD:/w" \
  -v "/absolute/path/to/MyProject:/proj" \
  track04 audit /proj --out /w/audit

# 3) zip 을 그대로 — 컨테이너가 임시 폴더에 풀어서 감사한다
docker run --rm -v "$PWD:/w" track04 audit /w/MyProject.zip --out /w/audit
```

**여러 .sol + import 자동 해석.** 디렉터리나 zip 을 주면, 감사 대상 파일마다
`import` 문을 파싱해 의존 파일을 트리에서 찾아 하나로 인라인(flatten)한 뒤 컴파일한다.
`remappings.txt` 없이도 별칭 import 를 처리한다:

- `import "./IVault.sol";` · `import "../base/VaultBase.sol";` — 상대경로 해석.
- `import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";` — 별칭은
  **경로 접미사 최장 일치**로 트리에서 실제 파일을 찾는다(그 라이브러리가 zip/폴더
  안 `lib/`·`node_modules/` 어디에 있든 무방). 그러니 의존 라이브러리도 함께 넣어라.
- `import {Base as Parent} from "./Base.sol";`, `import * as Types from "./Types.sol";`
  같은 symbol/namespace alias도 flatten 결과에 반영한다.
- 감사 **대상**은 각 파일에 직접 선언된 구체 컨트랙트뿐이다. import 로 끌려온 베이스·
  인터페이스·라이브러리와 `lib/`·`node_modules/`·`test/`·`script/` 폴더는 대상에서
  제외하되, import 해석용으로는 계속 참조한다.
- 해석 못 하거나 같은 접미사의 후보가 여러 개인 import는 분석 오류(exit 2)로 남긴다.

불변식을 함께 증명하려면 `--invariants Inv.sol` 를 준다. `audit` 매니페스트 스키마와
불변식 작성법은 `targets/*/manifest.json` 과 `targets/*/Invariants.sol` 을 본떠 쓰면 된다.

### 옵션·환경변수
- `--seed <int>` 결정론 시드(같은 시드 → 바이트 동일 산출). `--max-attempts <int>`
  후보 예산. `--timeout <sec>` 시간 예산.
- 표준 Docker 실행은 API 키가 주변 환경에 있어도 LLM을 사용하지 않는다. 개발용
  LLM 실험은 `-e TRUST404_ENABLE_LLM=1`과 `-e ANTHROPIC_API_KEY=...`(또는
  `LLM_BASE_URL`/`LLM_API_KEY`)를 함께 줘야 활성화된다.
- `-e TRUST404_VERIFIER=evm`으로만 내장 EVM을 선택한다. 지정하지 않으면 공식 표준인
  Foundry `forge test` 경로다.

이미지는 빌드 시 `solc 0.8.24`, Foundry **1.7.1**, vendored `forge-std` 를 넣으므로
실행 시 네트워크가 없어도 된다. 제출 Docker의 기본 검증기는 Foundry다.

## 로컬 실행 (Docker 없이)
```bash
pip install -r agent/requirements.txt
python3 -c "import solcx; solcx.install_solc('0.8.24')"
python3 agent/agent.py --contract targets/ReentrantVault/src/ReentrantVault.sol \
  --invariants targets/ReentrantVault/Invariants.sol \
  --manifest targets/ReentrantVault/manifest.json \
  --out demo-results/ReentrantVault --timeout 300 --seed 42 --max-attempts 5
```

## 공개셋 결과
취약 7개 → exit 0(`PROVEN`), 정상 5개 → exit 1(`NOT_PROVEN`). 자세한 내용은
`../METHOD.md`.
