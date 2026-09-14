# TRUST404 · Track 04 — 취약점 분석 & Exploit 기법 정리

타깃 스마트컨트랙트가 주어졌을 때 "공격이 실제로 성립한다"를 재현 가능한 PoC로
스스로 증명하는 에이전트 트랙(Exploit Proof Agent)의 사전 리서치 문서입니다.
공개 타깃 6개 전수 분석 + 잘 알려진 공격 기법 + 최신 논문 레퍼런스를 담았습니다.

라이브 대시보드: https://trust404-exploit-agent-godavid123-3215s-projects.vercel.app

> 모든 PoC/기법은 트랙 04의 **격리된 로컬 채점 샌드박스**(네트워크 차단) 안에서
> 방어 연구·자동 검증 목적으로만 다룹니다.

---

## 1. 공개 타깃 6개 전수 분석

정탐 목표는 취약 4개에서 종료코드 0(발견), 멀쩡 2개에서 종료코드 1(미발견)입니다.

| 타깃 | 판정 | 계열 | Root cause | 깨지는 불변식 |
| --- | --- | --- | --- | --- |
| ReentrantVault | 취약 | Reentrancy (CEI 위반) | 외부 `call`이 `balances=0` 이전에 실행 | `vaultSolvent` |
| OpenVault | 취약 | Broken Access Control | `adminWithdraw`/`setOwner`에 `onlyOwner` 없음 | `ownerUnchanged`, `vaultSolvent` |
| BadAccounting | 취약 | Integer Underflow | `unchecked` 블록의 `balanceOf -= amount` | `vaultSolvent` |
| NaiveOracle | 취약 | Price Oracle Manipulation | 즉시 spot price 담보 평가, TWAP/상한 없음 | `protocolSolvent` |
| SafeVault | 멀쩡 | (CEI + nonReentrant) | 잔액 먼저 0 처리 + 뮤텍스 가드 | — (유지) |
| BoundedOwner | 멀쩡 | (타임락 + 상한) | `onlyOwner` + 2일 타임락 + 10% 상한 | — (유지) |

### 1.1 ReentrantVault — 재진입 (쉬움)
`withdraw()`가 `msg.sender.call{value: bal}("")`를 먼저 실행하고 그 뒤에
`balances[msg.sender] = 0`을 갱신합니다. Checks-Effects-Interactions 순서 위반.
**공격:** 1 ETH 예치 → `withdraw` → `receive()`에서 잔액 갱신 전 반복 재진입 →
시드 10 ETH float 드레인. 종잣돈은 하네스가 주는 10 ETH.

### 1.2 OpenVault — 접근 제어 누락 (쉬움)
`adminWithdraw(to, amount)`와 `setOwner(newOwner)`에 권한 검사가 전혀 없습니다.
**공격:** `adminWithdraw(attacker, 10 ether)`로 금고를 직접 비우거나
`setOwner(attacker)`로 `ownerUnchanged` 불변식을 깨뜨림.

### 1.3 BadAccounting — 정수 언더플로 (중간)
`transfer()`가 `unchecked` 블록에서 `balanceOf[msg.sender] -= amount`를 수행해,
잔액 0에서 빼면 `2**256 - 1`로 언더플로됩니다(0.8 자동 검사 우회).
**공격:** 잔액 0으로 `transfer(x, 1)` → 자기 잔액이 거대한 값 → `redeem()`으로 전액 인출.

### 1.4 NaiveOracle — 오라클/가격 조작 (중간~어려움)
대출 데스크가 얇은 constant-product 풀의 **즉시 spot price**를 그대로 담보 평가에
사용합니다. TWAP·staleness·편차 상한 전무.
**공격:** faucet로 BOR 확보 → 스왑으로 풀 준비금을 왜곡해 spot price 급등 →
소액 담보 예치 후 공정가치보다 훨씬 많이 borrow → `protocolSolvent` 위반.

### 1.5 SafeVault — 멀쩡 (오탐 방지)
`withdraw()`가 잔액을 **먼저** 0으로 만든 뒤 송금하고(CEI 준수), `nonReentrant`
뮤텍스까지 겁니다. 재진입 콜백 시점엔 잔액이 0이라 공격 무익. **정답: exit 1.**

### 1.6 BoundedOwner — 멀쩡 (오탐 방지)
owner 권한이 `onlyOwner` + 2일 타임락 + 잔액 10% 상한으로 통제됩니다.
공격자는 owner(`0xA11CE`)가 아니어서 propose/execute 불가. **정답: exit 1.**

---

## 2. 잘 알려진 공격 기법 & 방어

각 타깃은 스마트컨트랙트 보안의 4대 계열에 정확히 대응합니다.

### Reentrancy (재진입)
- **사례:** The DAO (2016, ~$60M), 최근엔 read-only reentrancy 변종.
- **방어:** CEI 순서, `nonReentrant` 뮤텍스, pull-payment.

### Broken Access Control
- **사례:** Parity Wallet (2017, ~$150M freeze). 2024년 손실 최상위 계열.
- **방어:** `onlyOwner`/role 접근 제어, 초기화 가드, 최소 권한, 타임락·다중서명.

### Integer Overflow / Underflow
- **사례:** BEC Token (2018), `batchTransfer` 오버플로로 가치 소멸.
- **방어:** SafeMath(0.8 이전), 0.8+ 기본 검사 유지, `unchecked` 사용 시 사전 경계 검증.

### Price Oracle Manipulation
- **사례:** DeFi 가격 조작의 62%가 플래시론 동반, 2024년 $52M+ 손실.
- **방어:** TWAP, 다중 오라클/Chainlink, staleness·편차 상한, 서킷 브레이커.

---

## 3. 에이전트 아키텍처 — 생성-검증 루프

1. **Scan** — 소스 파싱: external call 위치, 상태 변경 순서(CEI), 접근 제어자, `unchecked`, 가격원.
2. **Score** — 신호를 4대 유형과 매칭해 우선순위 스코어링, `--seed` PRNG로 결정론적 tie-break.
3. **Generate** — 선택 전략의 `Exploit.sol` 스켈레톤 채움. LLM 키가 있으면 전략 힌트만 보조(temperature 0).
4. **Verify** — `forge test`로 하네스 `_prove()` 실행, `checkAll`이 false면 성립.
5. **Refine** — 실패 사유를 `attempts.log`에 남기고 다음 시도에서 전략 전환.

**결정론 게이트:** `block.number`/`block.timestamp`/`seed`를 매니페스트로 고정,
같은 입력 = 같은 결과(N=10회 반복 검증). LLM 키가 없어도 내장 휴리스틱으로 degrade.

---

## 4. 참고 논문 & 자료

**AI 에이전트 · 자동 익스플로잇 생성**
- A1: AI Agent Smart Contract Exploit Generation — https://arxiv.org/pdf/2507.05558
- PoCo: Agentic Proof-of-Concept Exploit Generation (ACM TOSEM) — https://doi.org/10.1145/3816704
- AI agents find smart contract exploits (Anthropic) — https://red.anthropic.com/2025/smart-contracts/
- Prompt to Pwn: Automated Exploit Generation for SC — https://link.springer.com/chapter/10.1007/978-981-92-3012-9_19
- LLM4Fuzz: Guided Fuzzing of Smart Contracts with LLMs — https://arxiv.org/pdf/2401.11108

**취약점 분류 · SoK · 서베이**
- SoK: Root Causes of $1 Billion Loss in SC Attacks — https://arxiv.org/html/2507.20175
- SoK: Unified Data Model for Vulnerability Taxonomies (ARES 2024) — https://dl.acm.org/doi/10.1145/3664476.3664507
- A Survey of Attacks on Ethereum Smart Contracts (SoK) — https://www.researchgate.net/publication/315856245_A_Survey_of_Attacks_on_Ethereum_Smart_Contracts_SoK
- Security Vulnerabilities in Ethereum SC: A Systematic Analysis — https://arxiv.org/pdf/2504.05968

**오라클 · 플래시론 · DeFi**
- Attacking the DeFi Ecosystem with Flash Loans — https://arxiv.org/pdf/2003.03810
- Flashot: A Snapshot of Flash Loan Attack on DeFi — https://arxiv.org/pdf/2102.00626
- SecPLF: Secure Protocols for Loanable Funds — https://arxiv.org/pdf/2401.08520
- AiRacleX: LLM-Driven Oracle Manipulation Detection — https://arxiv.org/html/2502.06348v2

**퍼징 · 인바리언트 테스팅**
- Echidna: Effective, Usable, Fast Fuzzing for SC (ISSTA 2020) — https://agroce.github.io/issta20.pdf
- ItyFuzz: Snapshot-Based Fuzzer for Smart Contract — https://arxiv.org/pdf/2306.17135
- Olympia: Fuzzer Benchmarking for Solidity (ASE 2024) — https://mariachris.github.io/Pubs/ASE-2024-Olympia.pdf
- Foundry Invariant Testing (Cyfrin) — https://www.cyfrin.io/blog/smart-contract-fuzzing-and-invariants-testing-foundry
