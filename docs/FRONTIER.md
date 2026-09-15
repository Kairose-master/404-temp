# 아직 안 닫힌 프론티어

> 트랙 제출 입구가 아니다. 채점은 [`README.md`](../README.md) · [`METHOD.md`](../METHOD.md).
> 이 문서는 METHOD §6 한계의 확장 노트다.

2025–2026 문헌(A1, PoCo, ReX, EvoPoC, Verite, SmartFuzz, EVMbench, SCONE/Mythos,
软件学报 2026 DeFi 서베이, Smart-Target)이 **실행 익스플로잇**을 주전장으로
옮겼다. 이 문서는 그 논문들이 *풀었다고 주장하는 것*과, 코드에 방금 넣은
1–4가 *실제로 닫는 것*, 그리고 **그래도 남는 구멍**을 구분한다.

엔진 쪽 구현:

| # | 축 | 코드 | 닫는 것 | 안 닫는 것 |
|---|---|---|---|---|
| 1 | profit oracle | `trust404/profit.py` | 불변식 플립과 추출 가치를 분리. THEFT / GRIEF / INTENDED_PATH / NONE | USD, 수수료토큰, 리베이싱, 의도 여부 |
| 2 | HKG | `trust404/hkg.py` | 평탄 capability → 프로토콜/원인/프리미티브 경로. synth 순서 | 교차 프로토콜 그래프, SMT 도달 |
| 3 | 공개 벤치 | `trust404/benches.py` `benches/` | 어댑터 + 로컬 클래스 픽스처. 미첨부 데이터셋은 NOT_ATTACHED | VERITE/SCONE/EVMbench 점수 자체 (트리 없음) |
| 4 | 월드 모델 | `trust404/world.py` | 한 컴파일 유닛의 N 컨트랙트를 시퀀스로 접어 `run(address)` 에 넣음 | 교차 프로토콜, 교차 체인, 피해자 선행 트랜잭션 |

프론티어 픽스처는 `benches/fixtures/` 에 있다. `intended_arb` 가 순수 반례고,
**한 프로토콜에 두 표면이 같이 있는 작업 예제**는
[`examples/frontier/DualSurface.sol`](../examples/frontier/DualSurface.sol) 이다.

```
swap0to1()  INTENDED_PATH   불변식 유지, ETH 가 호출자에게 이동할 수 있음
withdraw()  THEFT           CEI 재진입, vaultSolvent 깨짐
```

---

## 1. 의도된 경로 문제 — 수익 ≠ 취약점

SCONE은 USD로 채점한다. Verite는 FP 0 을 "구체적 수익"으로 정의한다. A1 은
`$9.33M`, Mythos 는 `$35M`, EvoPoC 는 `$116M` 재현. 전부 **추출 가능 가치 =
성공** 이다.

반례가 `benches/fixtures/intended_arb` 이다. 상수곱 페어에서 스왑은 프로토콜
그 자체다. 불변식(`reservesBacked`)은 유지되고 공격자 ETH 는 늘어날 수 있다.
profit-only 에이전트는 이걸 익스플로잇으로 보고한다. 아니다.

분류 (`trust404.profit.classify`):

```
invariant broken ∧ Δ > 0   →  THEFT          진짜 도난
invariant broken ∧ Δ ≤ 0   →  GRIEF          King / 기부 DoS / 락
invariant held   ∧ Δ > 0   →  INTENDED_PATH  ← 프론티어
invariant held   ∧ Δ ≤ 0   →  NONE
```

왜 논문이 못 닫나.

- PropertyGPT (NDSS'25) 는 **이미 있는** Certora 속성을 RAG 한다. 속성 없는
  프로토콜이 대부분이다.
- LLM 이 불변식을 합성하면 순환이다. 익스플로잇이 스펙을 정의한다.
- 청산, 차익, 기부, 자발적 소각은 프로토콜이 *원하는* 추출이다. 경제 모델
  없이 구분할 술어가 없다.

우리가 한 것: 분류를 엔진 산출에 넣고, INTENDED_PATH 를 성공으로 포장하지
않는다. `result.json` 의 `profit.classification` 이 `theft` 가 아니면
PROVEN 을 경제적 성공이라고 부르지 말 것.

남는 구멍: **의도 스펙을 문서/테스트/주석에서 버그를 누수하지 않고 추론**
하는 일. 2026년에도 열려 있다.

---

## 2. 교차 프로토콜 합성 — HKG 는 아직 한 프로토콜 안

EvoPoC 의 핵심 문장: 익스플로잇 합성은 코드 생성이 아니라 프로토콜 의미 위
구조적 추론. 우리 HKG 는 그 문장을 평탄 태그 위에 한 층 올린 것이다.

ReX: frontier LLM 은 단일 컨트랙트 PoC 는 만들고 **교차 컨트랙트에서 무너진다.**
软件学报 2026: 계약층 vs DeFi 프로토콜층.

우리 월드 모델이 닫는 것: *한 파일 안* 의 Token + Pair + Router. `plan_world` 가
시퀀스를 접어 `run(address)` 로 넣는다. 하네스 계약을 깨지 않는다.

안 닫는 것 — 실제 수십억이 나간 자리:

| 사고 | 필요한 세계 |
|---|---|
| Euler 2023 | 렌딩 + 청산 + 오라클 + DEX, 한 원자 번들 |
| Kyberswap 2023 | 틱/집중유동성 산술 + 라우터 + 풀 교차 |
| Beanstalk | *다른* 프로토콜(Aave) 플래시론으로 거버넌스 투표 |
| 1inch Yul calldata | 라우터 내부 어셈블리 + 외부 페어 |
| Ether.fi AtomicQueue 2026-09 | 큐 + solver 컨트랙트 + 자산 (Truster 계열의 프로토콜층) |

HKG 에 `amm → oracle_spot → spot_amm_drain` 경로는 있다.
`lending[Aave] → flash → governance[Beanstalk] → drain` 경로는 없다.
그걸 넣으려면 프로토콜 *인스턴스* 그래프가 필요하고, 온체인 상태(누가 어떤
풀에 얼마)가 필요하다. 오프라인 트랙 하네스는 그 상태를 갖지 않는다.

남는 구멍: **프로토콜 인스턴스 그래프 + 원자 번들 플래너.** 월드 모델 v0 은
그 입구다.

---

## 3. 정지 규칙 / 완전성

A1 은 5 round 안에 대부분. SmartFuzz 는 CRP 로 계속 반성. 우리는
`--max-attempts` / `--timeout`. 전부 **예산 소진 = 미발견** 이다.

미발견은 "익스플로잇이 없다"가 아니다. X 에서 나온 문장 그대로: 에이전트에게
감사를 맡길 수는 있어도, 감사가 *끝났다*고 스스로 판정하게 두면 안 된다.

완전성의 유일한 고전적 답은 심볼릭 전수(Smart-Target, SliSE Stage II,
hevm/Halmos)이고, 그건 경로폭발로 DeFi 프로토콜층에서 죽는다. 소프트웨어학보
2024(董)가 이미 쓴 문장이다.

남는 구멍: **능력 집합 C 아래에서 익스플로잇이 존재하지 않는다** 는 증명.
우리 `should_run` 이 건너뛴 synth 는 "이 소스가 그 능력을 안 보여서"이지
"능력이 없어서"가 아니다. 정규식 IR 은 침묵을 안전으로 해석한다. 그건 버그
다. (P1: solc AST. 아직 안 넣음.)

---

## 4. 패치의 쌍대 — 익스플로잇보다 어렵다

EVMbench: Exploit **71%**, Patch **42%**. PoCo: 잘 만든 PoC 50/50, 논리 정확
32/50. 감사자가 실제로 필요한 산출은 "고쳤고, 같은 프리미티브가 더 이상
안 통해."

Aegis 는 `Safe<X>` PoC 가 같은 익스플로잇을 패배시키는 것으로 이걸 한다.
우리는 아직 패치 후보를 생성하지 않는다. FINDINGS 의 diff 는 사람용이다.

남는 구멍: **Proof-of-Patch 를 트랙 게이트로.** PoCo 23건 + EVMbench patch
split. `benches/manifest.json` 에 어댑터만 달아 두었다.

---

## 5. 시간 — 오프라인 증명은 레이스를 못 닫는다

A1 Monte Carlo: 즉시 탐지 성공 86–89%, 일주일 늦으면 6–21%. SCONE 의 0-day
2건은 `$3.7k` 를 `$3.5k` API 비용으로 뽑았다. 경제적으로 아슬아슬하다.

우리 검증기는 제네시스에서 결정론 블록을 고정한다. 오라클 업데이트, 멤풀
순서, 크로스체인 메시지 지연은 세계가 아니다. 포크 상태조차 첨부하지 않으면
(VERITE_DIR) 역사 블록을 재생할 수 없다.

남는 구멍: **어느 블록이 세계인가** 에 대한 정책. 오프라인 트랙과 라이브
헌팅은 같은 루프가 아니다. 섞어서 "에이전트가 $N 을 벌 수 있다"고 쓰지 말 것.

---

## 6. 자산 이론이 불완전하다

profit oracle 은 ETH 잔액과 선택적 `balanceOf` 다. 깨지는 것:

- fee-on-transfer / rebasing / ERC777 훅
- ERC-4626 인플레이션 공격 (donation 계열의 회계층)
- EIP-7702 위임 EOA (피처는 있고 수익 모델은 없음)
- Vyper (Ultrafuzz 가 넣음. 우리는 solc 만)

EvoPoC 의 SMT+자산 시뮬 2단도 토큰 이론이 닫혀 있어야 한다. 이론 밖의
토큰은 수익을 위조하거나 숨긴다.

---

## 7. 오염 vs 일반화 — 워게임 완주는 증거가 아니다

Aegis Ethernaut 40/40, DVD 18/18 은 카탈로그가 그 패턴을 가졌다는 뜻이다.
SCONE 의 post-cutoff split 이 정직한 평가다. EVMbench 도 저장소에서 온
117건.

문헌에 **없는** 스플릿: 능력 집합을 나눠, A–F 로 개발하고 G–H 는 한 번도
안 본 채로 시험. 우리가 트랙 12/12 와 Ethernaut 32 를 회귀 게이트로 유지하는
이유와, 그걸 일반화 증거로 안 쓰는 이유다.

`benches/` 어댑터는 SCONE/EVMbench/VERITE 를 점수로 주장하지 않는다.
트리가 없으면 `NOT_ATTACHED`. 그게 이 축의 정직함이다.

---

## 8. 이 네 축을 넣어도 남는 연구 질문

한 문장으로:

> **실행 가능한 익스플로잇을 만드는 일**은 2026년에 엔지니어링 문제가 됐다.
> **그것이 도둑질인지, 프로토콜이 가격에 넣은 추출인지, 그리고 더 없는지를
> 말하는 일**은 아직 과학 문제다.

구체적 질문, 우선순위대로:

1. 의도 스펙을 버그 없이 어디서 얻는가. (불변식 합성의 순환)
2. 교차 프로토콜 원자 번들을 어떤 그래프에 올리는가. (HKG 의 다음 층)
3. 능력 C 아래의 부재 증명. (정지 규칙)
4. 패치가 같은 프리미티브를 죽이는가. (Proof-of-Patch)
5. 어느 블록이 세계인가. (시간)
6. 토큰 이론의 열린 집합. (자산)
7. held-out capability split. (평가)

1과 2가 이 문서의 주제다. 픽스처 `intended_arb` 와 `cross_router` 가 그
두 질문을 코드로 고정한다. 벤치 점수로 덮지 말 것.
