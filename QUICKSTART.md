# TRUST404 빠른 시작

이 문서는 공개 예제가 아니라 새로 받은 비공개 타깃을 실행하는 절차를 설명한다.
실행 방식은 입력 파일에 따라 두 가지다.

| 받은 입력 | 실행 방식 | 대표 결과 |
|---|---|---|
| 컨트랙트 + `Invariants.sol` + `manifest.json` | 표준 증명 CLI | `result.json`, `Exploit.sol`, `attempts.log` |
| `.sol` 파일, 프로젝트 폴더 또는 zip만 있음 | 감사 CLI | `report.json`, `report.md`, `report.sarif`, `exploits/*.sol` |

## 1. 설치

저장소 루트에서 실행한다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r agent/requirements.txt
python -c "import solcx; solcx.install_solc('0.8.24'); solcx.set_solc_version('0.8.24'); print(solcx.get_solc_version())"
forge --version
```

solc 확인 명령은 `0.8.24`를 출력하고 `forge --version`도 성공해야 한다. manifest가
다른 `target.solc`를 지정하면 그 정확한 버전도 `solcx.install_solc(...)`로 설치한다.
`exit 2` 또는
`INCONCLUSIVE (verifier unavailable)`은 취약점 미발견이 아니라 검증기 준비
실패이므로 결과로 채점하면 안 된다.

## 2. 불변식과 매니페스트가 있는 비공개 타깃

권장 번들 구조는 다음과 같다. `manifest.json`이 있는 폴더가 Solidity source-unit의
루트이며, 이 아래의 `.sol` 파일은 import 의존성과 보조 계약으로 함께 로드된다.

```text
/absolute/path/MyVault/
├── manifest.json
├── Invariants.sol
├── Setup.s.sol          # 선택: 복잡한 배포가 필요할 때
└── src/
    ├── MyVault.sol
    └── Dependency.sol   # 선택: import 의존성
```

최소 `manifest.json` 예제:

```json
{
  "schema": "trust404.track04.manifest/0.1",
  "target": {
    "name": "MyVault",
    "src": "src/MyVault.sol",
    "solc": "0.8.24",
    "evm_version": "cancun"
  },
  "deploy": {
    "mode": "local",
    "constructor_args": [],
    "value_wei": "10000000000000000000"
  },
  "determinism": {
    "block_number": 21000000,
    "block_timestamp": 1735689600,
    "seed": 42
  },
  "invariants": {
    "contract": "Invariants.sol",
    "predicates": ["vaultSolvent"]
  }
}
```

`target.name`은 실제 계약 이름과 같아야 한다. `target.src`와
`invariants.contract`는 `manifest.json` 기준 상대경로다. 생성자 인자는
`deploy.constructor_args`, 초기 ETH는 wei 단위의 `deploy.value_wei`에 적는다.
복잡한 배포라면 `deploy.setup`에 `Setup.s.sol` 같은 source-unit 경로를 지정한다.
그 파일은 `Setup` 계약과 `run() returns (address)`를 제공해야 한다. Foundry
cheatcode를 쓰는 Setup은 아래 Docker/Forge 경로로 실행한다.

`Invariants.sol`의 `Invariants` 계약은 다음 ABI를 제공해야 한다.

```solidity
function checkAll(address target)
    external view
    returns (bool allHold, string memory firstViolated);
```

Docker와 같은 공식 Forge 검증기로 로컬 실행:

```bash
TARGET_DIR=/absolute/path/MyVault
TRUST404_VERIFIER=forge python agent/agent.py \
  --contract "$TARGET_DIR/src/MyVault.sol" \
  --invariants "$TARGET_DIR/Invariants.sol" \
  --manifest "$TARGET_DIR/manifest.json" \
  --out private-results/MyVault \
  --timeout 300 --seed 42 --max-attempts 24
```

`--out`은 현재 작업 디렉터리 기준 경로다. 위 명령의 결과는 정확히 다음 위치에
생긴다.

```text
private-results/MyVault/
├── Exploit.sol
├── result.json
└── attempts.log
```

- `Exploit.sol`: exit 0이면 실제 검증을 통과한 PoC다. exit 1 또는 2에서는 마지막으로
  생성한 후보일 수 있으므로 증명된 PoC로 취급하지 않는다.
- `result.json`: `proven`, `invariant_violated`, `strategy`, `attempts`, `stages`, 실행
  trace와 검증 피드백을 담는다.
- `attempts.log`: 각 후보, 검증 결과, 다음 단계로 격상한 이유를 담는다.

종료 코드는 `0 = PROVEN`, `1 = 예산 내 미발견`, `2 = 입력·검증기·내부 오류`다.

### Docker/Forge로 실행

먼저 저장소 루트에서 이미지를 빌드한다.

```bash
docker build --platform linux/amd64 -t track04 -f agent/Dockerfile .
```

이미지에는 `0.4.26`, `0.5.17`, `0.6.12`, `0.7.6`, `0.8.24`, `0.8.28`이
들어 있다. manifest의 `target.solc`가 다른 정확한 버전(예: `0.8.20`)이면 빌드 시
`--build-arg EXTRA_SOLC_VERSIONS="0.8.20"`을 추가한다.

비공개 입력은 읽기 전용으로, 결과 폴더는 쓰기 가능하게 각각 마운트한다.

```bash
TARGET_DIR=/absolute/path/MyVault
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

컨테이너의 `/results/MyVault`는 호스트의
`$PWD/private-results/MyVault`에 대응하므로 컨테이너가 종료되어도 세 결과 파일이
남는다. 출력 경로를 마운트하지 않으면 컨테이너 삭제와 함께 결과도 사라진다.

## 3. 소스만 있는 비공개 타깃

불변식과 매니페스트가 없다면 감사 CLI로 `.sol` 파일, 프로젝트 폴더 또는 zip을
분석한다. 폴더와 zip에서는 import 의존성도 함께 찾는다.

```bash
python agent/audit.py /absolute/path/private-target \
  --out audit/private --seed 42 --include-safe
```

결과 위치:

```text
audit/private/
├── report.json
├── report.md
├── report.sarif
└── exploits/
    └── MyVault.sol      # 동적으로 증명된 계약에만 생성
```

감사 모드는 `result.json`이나 `attempts.log`를 만들지 않는다. 계약별 상세 결과는
`report.json`에 모이고, 사람이 읽을 요약은 `report.md`, CI 연동 결과는
`report.sarif`에 기록된다.

Docker로 실행할 때도 결과 디렉터리를 호스트에 마운트한다.

```bash
TARGET_DIR=/absolute/path/private-target
mkdir -p audit/private
docker run --rm \
  -v "$TARGET_DIR:/target:ro" \
  -v "$PWD/audit/private:/results" \
  track04 audit /target --out /results --seed 42 --include-safe
```

단일 파일은 `/target/MyVault.sol`, zip은 `/target/project.zip`처럼 마지막 입력 경로만
바꾸면 된다.

## 4. 결과 확인 순서

표준 증명 CLI에서는 먼저 프로세스 종료 코드를 확인하고, 다음으로
`result.json`의 `proven`과 `invariant_violated`를 확인한 뒤 `Exploit.sol`을 재현한다.
`attempts.log`는 실패 원인이나 탐색 예산 소진 여부를 진단할 때 사용한다.

감사 CLI에서는 `report.md`로 요약을 읽고 `report.json`의 계약별 `proven` 값을
확인한다. `audit/private/exploits/`에 생성된 PoC는 해당 보고서의 계약명과 대응한다.
