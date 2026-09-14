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
| 2 | 사용법/내부 오류 |

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
```bash
# 번들 최상위에서
docker build -f agent/Dockerfile -t track04-agent .
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v "$(pwd)/targets/ReentrantVault:/work/target:ro" \
  -v "$(pwd)/out:/work/out" \
  track04-agent \
  --contract /work/target/src/ReentrantVault.sol \
  --invariants /work/target/Invariants.sol \
  --manifest /work/target/manifest.json \
  --out /work/out --timeout 300 --seed 42 --max-attempts 5
```
이미지는 빌드 시 `solc 0.8.24` 를 받아 고정하므로 실행 시 네트워크가 없어도 된다
(채점 샌드박스 전제). LLM 키가 없으면 오프라인 휴리스틱으로 동작한다.

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
