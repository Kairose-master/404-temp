# TRUST404 · Track 04 — Autonomous Exploit Prover

스마트컨트랙트 취약점을 **재현 가능한 PoC로 자동 증명**하는 에이전트.
타깃을 입력받아 취약 유형을 스코어링하고, `Exploit.sol` 을 결정론적으로 생성한 뒤,
하네스 `_prove()` 절차를 재현한 검증기로 실제 불변식이 깨지는지 확인한다.

## 제출물 3종
| # | 제출물 | 위치 |
|---|---|---|
| A | 에이전트 코드 + Dockerfile + 표준 CLI | [`agent/`](./agent) |
| B | METHOD.md | [`METHOD.md`](./METHOD.md) |
| C | Exploit.sol PoC (에이전트 산출물) | [`exploits/`](./exploits) |

## 공개셋 6개 결과
| 타깃 | 판정 | 깨진 술어 | exit |
|---|---|---|---|
| ReentrantVault | PROVEN | vaultSolvent | 0 |
| OpenVault | PROVEN | ownerUnchanged | 0 |
| BadAccounting | PROVEN | vaultSolvent | 0 |
| NaiveOracle | PROVEN | protocolSolvent | 0 |
| SafeVault | NOT PROVEN | — | 1 |
| BoundedOwner | NOT PROVEN | — | 1 |

취약 4개는 자동 증명(정탐), 멀쩡 2개는 미발견(오탐 없음). 각 PoC는 내장 EVM
검증기와 독립 검증기 양쪽에서 불변식 위반을 확인했다.

## 빠른 시작
```bash
pip install -r agent/requirements.txt
python3 -c "import solcx; solcx.install_solc('0.8.24')"
for t in ReentrantVault OpenVault BadAccounting NaiveOracle SafeVault BoundedOwner; do
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
`harness/src/Harness.sol` 의 `_prove()` 로 6개 타깃을 검증합니다.

```bash
forge test -vv
# 기대: 취약 4개 test_*_PROVEN 통과, 멀쩡 2개 test_*_NOT_PROVEN 통과
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

## 리서치 & 대시보드
- 취약점 분석 + 4대 공격 기법 + 최신 논문 정리: [`FINDINGS.md`](./FINDINGS.md)
- 라이브 원버튼 콘솔(배포→생성→실행→증명): https://trust404-prover.vercel.app
- 취약점 분석 대시보드: https://trust404-prover.vercel.app/analysis.html
- 프론트엔드 소스: [`web/index.html`](./web/index.html)

## 레이아웃
```
agent/       에이전트 (agent.py, scanner, strategies, verify, llm, Dockerfile)
exploits/    타깃별 생성된 Exploit.sol + attempts.log (제출물 C)
harness/     참가 번들 하네스 사본 (forge 검증 경로용)
targets/     공개 타깃 6개
web/         Vercel 배포 프론트엔드
lib/forge-std/  벤더링한 최소 forge-std (다운로드 불필요)
test/        forge test (Prove.t.sol) — 6개 타깃 _prove 검증
foundry.toml Foundry 프로젝트 설정
.claude/     SessionStart 훅 (웹 세션에서 forge 설치)
METHOD.md    제출물 B
FINDINGS.md  취약점/기법/논문 리서치
```
