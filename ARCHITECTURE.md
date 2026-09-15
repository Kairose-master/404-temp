# TRUST404 엔진 아키텍처 강화안 (v0.3)

> 트랙 제출 입구는 [`README.md`](./README.md) · [`METHOD.md`](./METHOD.md) 다.
> 이 문서는 엔진 진화 로그다. 채점 칸이 아니다.

이 문서는 `docs/references.md` · `FINDINGS.md` 에 모아 둔 도구/논문을 **직접 읽고**
현재 코드에 대조해 내린 강화안이다. v0.2 는 레벨 솔버를 capability 로 일반화했다.
v0.3 은 그 위에 **1 profit · 2 HKG · 3 공개벤치 · 4 월드 모델** 을 코드로 넣는다.

아직 논문이 못 닫은 구멍은 [`docs/FRONTIER.md`](docs/FRONTIER.md) 가 주제다.
`intended_arb` 픽스처가 그 반례다.

> 원칙: 하네스 계약(`IExploit.run(address)` / `IInvariants.checkAll`)은 유지한다.
> 레벨 솔버는 버리지 않고 **계열(capability)로 일반화해 엔진에 남긴다.**
> PROVEN 은 불변식 위반이다. 수익은 별도 분류다. 둘을 섞어 성공이라고 부르지 않는다.

---

## 0. v0.3 에서 착수한 코드

| 축 | 파일 | 하는 일 |
|---|---|---|
| 1 profit oracle | `trust404/profit.py` · `agent/verify.py` | 펀딩 이후 vs run 이후 Δ. THEFT/GRIEF/INTENDED_PATH/NONE |
| 2 HKG | `trust404/hkg.py` | 프로토콜 → 원인 → 프리미티브. synth 순서 |
| 3 공개 벤치 | `trust404/benches.py` `benches/` | VERITE/SCONE/EVMbench 어댑터. 없으면 NOT_ATTACHED |
| 4 월드 모델 | `trust404/world.py` | N 컨트랙트 시퀀스를 `run(address)` 로 접음 |
| 프론티어 | `docs/FRONTIER.md` `benches/fixtures/` | intended_arb / grief_lock / profit_drain / cross_router |

`python -m trust404.benches` 는 로컬 4개만 채점하고 업스트림을 점수라고 거짓말하지 않는다.

---

이 문서는 `docs/references.md` · `FINDINGS.md` 에 모아 둔 도구/논문을 **직접 읽고**
현재 코드(`api/prove.py` 5555줄, 레벨 솔버 26개)에 대조해 내린 강화안이다.
이번 PR(`feat/engine-generalize`)은 **P0를 코드로 착수**한다. P1–P3은 다음 작업.

> 원칙: 하네스 계약(`IExploit.run(address)` / `IInvariants.checkAll`)은 유지한다.
> 레벨 솔버는 버리지 않고 **계열(capability)로 일반화해 엔진에 남긴다.**

---

## 0. 이번에 착수한 코드 (P0)

| 변경 | 왜 |
|---|---|
| `trust404/` 패키지 | `prove.py` 신모듈. 스캐너·피처 IR·레지스트리·타깃 로더·크리티크 |
| `trust404/features.py` | Ethernaut 솔버를 **이름 없는 capability 태그**로 승격 |
| `trust404/registry.py` | 태그가 없는 타깃에서 비싼 synth 컴파일/배포를 건너뜀 |
| `trust404/scan.py` | `agent/scanner.py` 단일 소스. 트랙 CLI와 엔진 점수 드리프트 제거 |
| `trust404/targets.py` | `targets/*/src` 가 정본. `api/prove.py` 임베드는 Vercel 폴백 |
| `trust404/critique.py` | 실패를 다음 후보/LLM 재시도의 **탐색 신호**로 (PoCo/A1) |
| `tests/python/` | 스캐너 페어·피처 게이트·디스크 타깃 — solc 없이 도는 회귀 |
| `pyproject.toml` | 패키지로 import. `importlib` 경로 해킹 축소 |

레벨 솔버 → 계열 매핑 (엔진에 그대로 두고, 이름 하드코딩은 제거):

| 옛 레벨 솔버 | 일반화 계열 | capability |
|---|---|---|
| Gatekeeper One | `gas_modulo_origin_gate` | `gasleft_modulo` ∧ `tx_origin_mask` |
| Gatekeeper Two | `constructor_extcodesize_gate` | `extcodesize_zero` |
| Gatekeeper Three | `typo_init_and_send_gate` | `construct0r` / `send_gate` |
| Puzzle Wallet | `proxy_wallet_slot_collision` | `proxy_admin` ∧ `nested_multicall` |
| HigherOrder | `calldata_width_confusion` | `calldata_fullword_sstore` |
| Switch | `calldata_offset_selector_check` | `selector_offset_check` |
| Magic Carousel | `packed_storage_overflow` | `packed_id_overflow` |
| Alien Codex | `storage_array_underflow` | `array_length_unchecked` |
| Dex / DexTwo | `spot_amm_drain` / `unverified_token_swap` | `dex_spot_swap` |
| King | `push_payment_griefing` | `push_refund_role` |
| Elevator / Shop | `view_callback_inconsistency` | `view_callback_twice` |
| CoinFlip | `block_entropy_runner` | `block_entropy` |
| Delegation | `fallback_delegatecall_proxy` | `fallback_delegatecall` |
| Preservation | `delegatecall_slot_collision` | `delegatecall_stored_lib` |
| Motorbike | `unguarded_initializer` | `unguarded_initialize` |
| Impersonator | `ecdsa_s_malleability` | `ecrecover` |
| Stake | `fake_token_accounting` | `fake_weth` |
| Force | `forced_ether` | `selfdestruct` ∨ `no_receive` |
| … | (registry.py 전량) | |

SafeVault 같은 타깃에서 `_synth_gatekeeper_one` 을 컴파일하지 않는 것이 이 PR의
가시적 이득이다. 패턴이 있는 **무명 컨트랙트**에서는 그대로 발화한다.

---

## 1. 참고자료를 읽고 내린 구조 결정

### 1.1 SliSE (FSE 2024, [arXiv:2403.11254](https://arxiv.org/abs/2403.11254)) — 슬라이싱을 퍼지 *앞에*

SliSE는 I-CFG → I-PDG 를 만들고, `call{value:}` / ERC 훅을 슬라이싱 시드로 써서
CEI 위반 경로만 남긴 뒤 심볼릭으로 도달성을 확인한다. 복잡한 컨트랙트(DB1, 평균
1812 LOC)에서 F1 **78.65%** — 비교 도구 최고가 9.26%. 심볼릭 단계가 FP를 78→27로
줄인다.

**지금 우리:** `scan_target` 은 함수 본문 안에서 `call{value:}` 앞뒤에
`balances[msg.sender]=0` 이 있는지만 본다. 교차 함수·교차 컨트랙트 재진입은 슬라이싱
없이 놓친다. METHOD.md 의 "SliSE 류 우선순위"는 **호출 시퀀스 휴리스틱**이지
프로그램 슬라이싱이 아니다.

**넣을 것 (P1):**
1. `trust404/ir/` — solc `--ast-compact-json` 으로 함수 CFG.
2. value-call / ERC 훅을 시드로 **backward slice** (SliSE Stage I). 그 슬라이스에만
   재진입 합성·퍼저를 태운다.
3. Stage II(심볼릭)는 당장 hevm/Halmos 를 넣지 않고, 지금 내장 EVM 검증기가 그 역할을
   한다. 슬라이스는 예산 배분에만 쓴다.

### 1.2 A1 (arXiv:2507.05558) — 도구 6개가 에이전트의 손

A1 은 LLM 이 도구를 고른다: 소스(프록시 해석) · 생성자 인자 · 상태 읽기 ·
코드 sanitizer · **concrete execution** · 수익 정규화. 실패 PoC 히스토리를 남기고
최근 것을 우선한다. 실행은 역사 블록 상태 위.

**지금 우리:** LLM 은 stage 0 **원샷 초안**이고, `held_invariants` 는
`result.json` 에만 적힌다. 생성자 인자는 address/uint 기본값.

**이번에 넣은 것:** `trust404.critique` + agent 루프가 실패를 LLM 재시도 프롬프트에
넣는다 (temperature=0 유지, 키가 있을 때만).  
**다음 (P1):** 생성자 인자 도구를 `Setup.s.sol` 실행으로 교체 (Harness 주석이 이미
정본 배포기로 Setup 을 지목). sanitizer 는 import 평탄화(`_flatten_sources`)를
에이전트 도구로 노출.

### 1.3 PoCo (ACM TOSEM, [arXiv:2511.02780](https://arxiv.org/abs/2511.02780)) — ReAct + Foundry 피드백

PoCo 는 취약점 **자연어 설명**에서 Foundry PoC 를 만든다. 도구: glob/grep/read/edit +
`forge compile` / `forge test`. Reason–Act–Observe. 잘 만들어진 PoC 50/50, 논리적으로
맞는 PoC 32/50 (64%). 제로샷 6%, 워크플로 32%. 주석이 구체적일수록 성공률이 12%→55%.

**교훈:** (1) 컴파일/테스트 stderr 가 다음 액션의 입력이다. (2) 스캐폴딩을 최소화하고
실행 도구를 노출한다. (3) 패치 후에도 PoC 가 실패하는지로 **논리 정확성**을 검사한다.

**지금 우리:** 템플릿 엔진이 결정론의 뼈대 — 이건 트랙 요구라 유지. PoCo 식 ReAct 는
LLM 경로에만 적용.  
**다음 (P2):** `TRUST404_VERIFIER=forge` 와 py-evm 을 같은 시드로 교차검증하고
불일치면 `verifier_disagreement` 를 result.json 에 남긴다. 가능하면
[Proof-of-Patch](https://github.com/ASSERT-KTH/Proof-of-Patch/) 23건을
`examples/proof-of-patch/` 벤치에 추가 (Ethernaut 만으로는 워게임 바이어스).

### 1.4 MVD-HG ([Astronaut-diode/MVD-HG](https://github.com/Astronaut-diode/MVD-HG)) — 랭킹 프론트엔드

AST+CFG+DFG 이종그래프 + GNN. 라인/컨트랙트 두 단위, 7종 분류. **탐지/랭킹**이지
증명이 아니다. `docs/references.md` 의 상호보완 구도가 맞다.

**넣을 것 (P2, 선택):** `audit.py --rank mvdhg` 가 의심 라인을 먼저 주고, 우리
퍼저 입력 풀이 그 라인의 함수를 우선한다. 모델 가중치는 벤더하지 말고 어댑터만.

### 1.5 소프트웨어学报 3계층 · 6방법 — 우리가 비워 둔 칸

钱鹏 등, [软件学报 2022 33(8)](https://www.jos.org.cn/html/2022/8/6375.htm) 은 취약점을
**Solidity 코드층 / EVM 실행층 / 블록체인 시스템층** 으로 나눈다. 탐지는
형식검증 · 심볼릭 · 퍼징 · IR · 딥러닝.

董伟良 등, [软件学报 2024 35(1)](https://www.jos.org.cn/html/2024/1/6810.htm) 은 여기에
**오염 분석(taint)** 을 6번째 축으로 넣고, 중국 연구는 퍼징·ML 편중, 국제는
심볼릭·형식검증 편중이라고 비교한다. 핵심 챌린지 한 줄:

> 탐지된 취약점의 **exploitability 가 낮다** (교차 컨트랙트 의존).

그건 이 도구의 존재 이유다. 탐지가 아니라 **실행 PoC**.

| 서베이 층 | 유형 | 이번 PR 계열 |
|---|---|---|
| Solidity | 재진입, 오버플로, 접근제어, 예외처리, DoS, 타입혼동 | `cei_violation`, `unchecked_arithmetic`, `unguarded_owner_write`, `push_send`, `donation_accounting_dos` |
| EVM | short address, tx.origin, call stack | `tx_origin`, `raw_calldata` (short-address는 P1 AST) |
| 시스템 | timestamp/block 의존, TOD | `block_entropy` |

EthPloit(퍼징+오염→익스플로잇), teEther(심볼릭 페이로드) 는 "생성-검증"의 선행.
우리는 동적 증명을 기본으로 두고 슬라이스(SliSE)·오염(P1)을 예산 배분에만 쓴다.

중국 측 도구 개방성 26% vs 국제 63% — 이 레포는 엔진을 패키지로 열어 둔다.

## 1.6 Damn Vulnerable DeFi / Capture the Ether / Paradigm CTF — 워게임 솔버가 아니라 계열

Ethernaut 32는 이미 동적 증명된다. DVD v4 와 Paradigm CTF 는 **교차 컨트랙트
프로토콜** 이라 `run(address)` 한 방이 아니라 월드 모델이 필요하다. 그래도
레벨 솔버를 더 넣지 않고 계열로 승격한다 (`trust404/synth_defi.py`):

| DVD / CTF / 사고 | 계열 | 이번에 |
|---|---|---|
| Unstoppable | `donation_accounting_dos` | 템플릿 synth |
| Truster | `unpermissioned_callback` | 템플릿 synth |
| Ether.fi AtomicQueue 2026-09 (SlowMist) | 같은 `unpermissioned_callback` (`solver != msg.sender`) | 피처 공유 |
| Selfie | `governance_flashloan` | 템플릿 synth |
| Climber | `execute_before_schedule` | 템플릿 synth |
| Naive receiver | `unpermissioned_flashloan` | 피처만 (P1 synth) |
| Puppet v1/v2 | 기존 `_synth_amm` / `spot_price` | 있음 |
| Puppet v3 TWAP | `twap_oracle` | P1 — 블록 워프 월드 |
| Backdoor (Gnosis factory) | `gnosis_factory_callback` | 피처 |
| Wallet mining CREATE2 | `create2_predict` | 피처 |
| ABI smuggling | 기존 `selector_offset_check` | 있음 |
| Capture the Ether Predict | 기존 `block_entropy_runner` | 있음 |
| Paradigm Vault (smarx) | 프록시 Guard initialize + emergencyCall | `unguarded_initialize` + `unpermissioned_callback` |

참조 솔버 모음 (베끼지 않고 계열만 추출):
[SunWeb3Sec/damn-vulnerable-defi-v4-solutions](https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions),
[WTFAcademy/WTF-CTF](https://github.com/WTFAcademy/WTF-CTF).

X에서 반복되는 교훈 (2026-08~09):
- "finding a bug ≠ proving it exploitable" (@0xNicos) — 우리 검증기 계약.
- Foundry 테스트가 그린이어도 메인넷과 다를 수 있다 (@jvst_tammy) — py-evm vs forge 교차검증(P2).
- Cancun 이후 selfdestruct 는 컨트랙트를 안 지우지만 **강제 ETH 주입은 남는다**.
- 실사고 AtomicQueue 는 Truster 와 동일 계열 — 워게임 솔버가 실세계로 일반화되는 증거.

## 1.7 실행 가능한 해킹 플레이그라운드

[@_AlexBiryukov_ 2026-09](https://x.com/_AlexBiryukov_/status/2098687075021144115)
24개 Aug–Sep 사고를 **인브라우저 EVM** 으로 재실행. 우리 py-evm 경로와 같다.
다음 벤치 후보: 그 PoC 레지스트리를 `examples/incidents/` 로 가져와
`unpermissioned_callback` 등이 이름 없이 발화하는지 회귀.

### 1.8 Beosin VaaS · ChainMaker/WANA

형식검증(27항목)과 WASM CFG(WANA)는 EVM 전제와 직교한다. 지금 스코프 밖.
다만 VaaS 의 **IDE 위치+사유** UX 는 SARIF + `report.md` 의 파일:라인과 같다.
P1 에서 스캐너가 solc AST 를 쓰면 라인 정보가 정확해진다 (지금 정규식은 라인 없음).

### 1.9 SoK $1B / Anthropic 에이전트

손실 1순위는 접근 제어, 그 다음 오라클·재진입. 우리 7계열은 이 분포를 덮는다.
빠진 실세계 계열은 DVD 쪽에서 이번 PR에 넣었다: **거버넌스 플래시론(Selfie)**,
**무허가 콜백(Truster/AtomicQueue)**. 서명 리플레이(체인 id 누락)는 P1.

---

## 2. 목표 레이어 (유지)

```
Surfaces      agent.py · audit.py · POST /api/prove · CI SARIF
Orchestrator  Loop(budget, escalate, critique → next candidate)
Providers     template | synth(family, feature-gated) | fuzz | llm(critique)
IR            features.py (지금) → solc AST + slice (P1)
World         Deploy / Act / Snapshot / CheckAll
Backends      py-evm (기본) | anvil+forge (교차검증)
```

---

## 3. 남은 백로그 (우선순위)

| # | 항목 | 근거 | 크기 |
|---|---|---|---|
| P1 | solc AST 파서 + SliSE Stage I 슬라이스 | FSE 2024, 교차함수 재진입 | M |
| P1 | 템플릿 관례명 폴백 삭제, 스캔 시그니처만 | METHOD 한계절 | S |
| P1 | Setup.s.sol 을 py-evm 정본 배포기 | Harness 주석, A1 ctor 도구 | S |
| P1 | 효과 오라클 플러그인 (DoS/공급량/권한락) | fuzz checker 4종뿐 | M |
| P1 | **profit oracle** (extractable ETH) | Verite / A1 / SCONE 2025–26 | M |
| P1 | capability → 계층 지식(의미/원인/프리미티브) | EvoPoC HKG | M |
| P2 | py-evm vs forge 교차검증 | PoCo 논리 정확성 | S |
| P2 | Proof-of-Patch 23건 + VERITE/SCONE/EVMbench 부분집합 | 워게임 바이어스 제거 | M |
| P2 | Aegis식 카탈로그 스윕을 synth 앞단으로 | Ethernaut 40/40는 카탈로그 완주 | S |
| P2 | 퍼저 progressive deepening 을 루프가 명시 구동 | METHOD 에만 존재 | S |
| P2 | `index.html`/`web/`/`analysis.html`/`track04.html` 1개로 | 표면 부채 | S |
| P2 | Vercel job+poll (60s 컷 회피) | prove.py maxDuration 60 | M |
| P3 | default branch `main` | CI 가 main+claude/** | S |
| P3 | 교차 컨트랙트 월드 모델 | ReX 약점, JOS 2026 DeFi층, Euler/Kyberswap | L |
| P3 | hevm/Halmos 심볼릭 백엔드 (선택) | SliSE Stage II, Smart-Target | L |

트랙 12/12 와 Ethernaut 32 증명은 **회귀 게이트**로 유지한다. 일반화 패치가
정탐을 떨어뜨리면 피처 태그를 느슨하게 (OR) 되돌린다 — `should_run` 의 기본이
이미 OR 이다.

프론티어 질문(의도 경로, 교차 프로토콜, 정지 규칙, 패치 쌍대)은 이 표의 다음
칸이 아니라 [`docs/FRONTIER.md`](docs/FRONTIER.md) 다. 벤치 점수로 덮지 말 것.

---

## 5. 2025–2026 최신 문헌 (이번 보강)

워게임 솔버를 더 넣는 대신, **측정 벤치 · 수익 오라클 · 교차컨트랙트 · 지식그래프**
네 축이 문헌에서 반복된다. 우리 엔진이 비워 둔 칸과 1:1이다.

### 5.1 미국 · 국제 — 생성-검증이 주류가 됨

| 연구 | 연 | 숫자 | 우리 엔진에 넣을 것 |
|---|---|---|---|
| **A1** Gervais/Zhou [2507.05558](https://arxiv.org/abs/2507.05558) | 2025–26 | VERITE 63%, $9.33M, 5 round 안에 대부분 | 이미 도구 6개·실패 히스토리. **수익 정규화**는 아직 없음 |
| **PoCo** KTH [2511.02780](https://arxiv.org/abs/2511.02780) | 2025–26 | 잘 만든 PoC 50/50, 논리 32/50 | critique 루프 착수. 패치 후 실패로 논리 정확성 검사 = P2 |
| **ReX** Prompt to Pwn [2508.01371](https://arxiv.org/abs/2508.01371) | 2025–26 | Gemini 2.5 Pro 평균 67%, 산술 93%. **교차 컨트랙트는 약함** | 월드 모델(멀티 tx)이 단일 `run(address)` 보다 급하다 |
| **Verite** [2501.08834](https://arxiv.org/abs/2501.08834) | 2025 | 29건 구체 익스플로잇, $18M+, FP 0, 12건은 실공격보다 많이 뽑음 | **profit-guided fuzz**: checker 를 잔액 감소만이 아니라 extractable USD/ETH 로 |
| **EvoPoC** [2605.02868](https://arxiv.org/abs/2605.02868) | 2026-05 | 88 사고 96.6% ESR, $116M 재현, A1 대비 ESR 2× · 가치 8.5×, 0-day 16 | capability registry 를 **계층 지식그래프**(프로토콜 의미 → 실패원인 → 프리미티브)로 승격. 검증을 SMT 도달 + 자산 시뮬 2단 |
| **SmartFuzz** [2511.12164](https://arxiv.org/abs/2511.12164) | 2025-11 | 30분에 +5.8–74.7% 탐지, FN −80% | CRP(연속 반성) = 우리 critique. RCC(의존 체인) = 호출 시퀀스를 전역/로컬 에이전트로 쪼갬 |
| **EVMbench** OpenAI+Paradigm+OtterSec [2603.04915](https://arxiv.org/abs/2603.04915) | 2026-03 | 117취약/40레포. GPT-5.3-Codex Exploit **71%**, Patch 42%. X 보고 6개월 전 <20% → 72% | 트랙 12 + Ethernaut 만으로 일반화를 주장하지 말 것. 공개 eval 에 올려라 |
| **SCONE-bench** Anthropic [2025-12](https://www.anthropic.com/research/smart-contracts) · [Mythos 2026-05](https://www.anthropic.com/research/exploit-evals) | 2025–26 | cutoff 이후 $4.6M / Mythos $35M, 2849 신규에서 0-day 2건($3.7k, API $3.5k) | **수익(USD)이 채점 단위**. 발견 ≠ 증명 ≠ 수익 |
| **PropertyGPT** NDSS'25 Distinguished | 2025 | Certora 속성을 RAG 로 새 컨트랙트에 이전 | 불변식 합성: 사람 속성 코퍼스에서 retrieve |
| **iAudit** ICSE'25 | 2025 | 263건 F1 91%. 원인 설명은 GT와 38%만 일치 | LLM 설명은 채점하지 말 것. EVM만 |
| **Ultrafuzz** Monad [2026-09](https://monad.xyz/blog/open-sourcing-ultrafuzz) | 2026-09 | 수백 전문화 에이전트, Solidity+Vyper | 단일 루프 유지하되 **전략 병렬**(템플릿/synth/fuzz/llm)은 예산만 나누면 됨 |
| **Aegis** catalog-driven | 2026 | Ethernaut **40/40**, DVD **18/18**, fork 재현 4건(Socket/Audius/DAO Maker/Beanstalk) | 카탈로그 스윕 + 우리 합성. 워게임 완주는 "카탈로그가 그 패턴을 가졌다"는 뜻이지 일반화가 아님 |

ReX의 한 줄: *frontier LLM은 단일 컨트랙트 PoC는 잘 만들고, 교차 컨트랙트에서 무너진다.*
EvoPoC의 한 줄: *익스플로잇 합성은 코드생성이 아니라 프로토콜 의미 위 구조적 추론이다.*
SCONE의 한 줄: *즉시 탐지 성공확률 86–89%, 일주일 늦으면 6–21% (A1 Monte Carlo).*

### 5.2 중국 — 탐지에서 재현·DeFi 층으로

| 연구 | 연 | 요지 | 엔진 |
|---|---|---|---|
| **揭晚晴 등, 智能合约与DeFi协议漏洞检测技术综述**, 软件学报 2026, 37(1):344–377, [jos.007413](http://www.jos.org.cn/1000-9825/7413.htm) | 2026 | 계약을 **스마트컨트랙트 층 vs DeFi 프로토콜 층**으로 분리. 계약층은 LLM이 주엔진 또는 전통방법과 결합. 프로토콜층은 공격 전/후 탐지. 기존 서베이의 DeFi 공백을 메움 | 우리 7계열은 계약층. DVD 계열(donation/unpermissioned callback/governance flashloan)이 프로토콜층 진입점. **프로토콜층 없이 Ethernaut만 돌리면 서베이가 지적한 공백을 그대로 재현** |
| **Smart-Target**, 基于目标制导符号执行, 软件学报 2025(12) | 2025 | 정적/주석 취약 문을 목표로 CFG 가지치기. SB Curated에서 Mythril 대비 탐지 시간 −60.8%, 재현 −92.2%, **재현 가능한 테스트케이스 출력** | P1 슬라이스의 중국 대응물. 스캐너가 찍은 sink를 심볼릭/퍼저 시드로 |
| 罗一帆 등, 基于人工智能的智能合约漏洞检测研究综述, 网络空间安全科学学报 2025 | 2025 | 2020–25 NLP/GNN/LLM. 데이터 질·설명가능성·확장성이 한계 | DL은 랭킹만 (MVD-HG와 동일 자리) |
| 应用科学学报 2025 opcode bigram+RF | 2025 | 정확도 93.6% Macro-F1 93.9% | 탐지. 증명 아님 |
| 计算机工程 2025 AST-embed BiGRU-ATT | 2025 | 5종(재진입·반환미검사·타임스탬프·접근·DoS), 시퀀스 대비 micro-F1 +13pt | AST 임베딩은 P1 파서와 맞닿음 |
| 通信学报 2025 双模态交叉注意力 | 2025 | 단일 모달 대비 +2%p | 소스+바이트코드 이중 모달 — 우리는 소스만 |
| **Knowdit** [2603.26270](https://arxiv.org/abs/2603.26270) | 2026 | 감사 지식 요약 + agentic 탐지 | 카탈로그를 프롬프트가 아니라 IR 태그로 |
| **Chiral Analysis** [2607.17987](https://arxiv.org/abs/2607.17987) | 2026 | 비즈니스 경로 간 관계 불일치 | view-callback 불일치(Elevator/Shop)의 일반형 |

중국 2024 서베이(董)는 "탐지의 exploitability가 낮다"고 했고, 2025 Smart-Target / 2026 JOS DeFi 서베이는 **재현 테스트케이스**와 **프로토콜층**으로 그 문장을 실행한다. 우리 자리는 그대로다.

### 5.3 X · 워게임 · 실사고 (2026-08–09)

- EVMbench 공개 직후: "best agent exploits **72.2%**. six months ago under 20%." ([@RaZiaH_Q](https://x.com/RaZiaH_Q/status/2095880613530161641))
- [crypto.training/hacks](https://crypto.training/hacks/) 24건 Aug–Sep 인브라우저 재실행. Sep 목록에 **EtherFi Veda AtomicQueue** — 우리가 Truster 계열로 묶은 바로 그 사고.
- 복잡한 공격 학습 세트 (Kyberswap, 1inch Yul calldata, GMX, VTHO, Euler) — calldata 폭/셀렉터 오프셋은 이미 `calldata_width_confusion`·`selector_offset_check`. Euler·Kyberswap은 **교차 컨트랙트 가격/청산**이라 월드 모델 없이는 안 된다.
- "에이전트가 감사를 하게 둘 수는 있어도, 감사가 *끝났다*고 스스로 판정하게 두면 안 된다." — 우리 exit 1(미발견)을 성공으로 포장하지 말 것.

### 5.4 백로그에 추가되는 항목

| # | 항목 | 근거 | 크기 |
|---|---|---|---|
| P1 | **profit oracle** (잔액만이 아니라 extractable ETH/USD) | Verite, A1, SCONE | M |
| P1 | capability registry → **HKG 한 단계**(프로토콜 의미 / 원인 / 프리미티브) | EvoPoC | M |
| P2 | 공개 벤치: VERITE + SCONE-bench 부분집합 + EVMbench exploit split | 워게임 바이어스 | M |
| P2 | Aegis식 **카탈로그 스윕을 synth 앞에** (히트만 검증) | Ethernaut 40/40는 카탈로그 완주 | S |
| P2 | Smart-Target식 sink 가지치기를 퍼저 시드로 | 软件学报 2025(12) | M |
| P3 | 교차 컨트랙트 월드 모델 (ReX가 깨진 지점) | ReX, JOS 2026 DeFi층, Euler/Kyberswap | L |

- 같은 입력 + 같은 `--seed` → 같은 `Exploit.sol`
- 안전 페어(SafeVault 등)는 전 단계 소진 후 exit 1
- LLM 은 초안/재시도만, 최종 판정은 EVM
- 하네스는 타깃 이름을 모른다
