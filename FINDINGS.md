# TRUST404 · Track 04 — 취약점 분석 & Exploit 기법 정리

타깃 스마트컨트랙트가 주어졌을 때 "공격이 실제로 성립한다"를 재현 가능한 PoC로
스스로 증명하는 에이전트 트랙(Exploit Proof Agent)의 사전 리서치 문서입니다.
공개 타깃 6개 전수 분석 + 잘 알려진 공격 기법 + 최신 논문 레퍼런스를 담았습니다.

라이브 대시보드: https://trust404-prover.vercel.app

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

## 2.5 컨트랙트 워게임 유도 계열 (신규 3종)

공개셋 4대 계열 위에, 잘 알려진 스마트컨트랙트 워게임(Ethernaut, Damn Vulnerable
DeFi, Capture the Ether)이 가르치는 계열 3종을 스캐너·전략·타깃에 추가했다. 각
계열마다 **취약 타깃 1개 + 같은 표면을 가진 안전 타깃 1개**를 넣어, 스캐너가
취약본만 스코어링하고 안전본은 gated(오탐 없음)되는지 검증한다. 세 계열 모두
에이전트가 오프라인 내장 EVM으로 자동 증명한다.

### delegatecall 하이재킹 (Ethernaut Delegation / Preservation, Parity)
- **취약(DelegateVault):** `execute(address module, bytes data)`가 호출자가 준
  모듈을 `delegatecall` 한다. 모듈 코드가 타깃 저장소 컨텍스트에서 돌아 슬롯 0
  (`owner`)을 덮어쓴다. 에이전트는 슬롯 0을 `msg.sender`로 쓰는 `Pwn` 모듈을
  배포해 소유권을 탈취 → `ownerUnchanged` 위반.
- **안전(LibraryVault):** delegatecall 대상이 생성자에서 고정한 `immutable` 모듈
  뿐이고 함수 인자로 주소를 받지 않는다. 스캐너 판별자: delegatecall 수신자가
  **함수 파라미터**일 때만 스코어링. 고정 모듈은 무점수 → 오탐 없음.
  단, 대상을 고정하는 것만으로는 부족하다 — 모듈의 **스토리지 레이아웃이
  프록시와 정렬**되어야 한다. 예전 모듈은 `pings`가 슬롯 0이라 `run(ping())`
  한 번이 슬롯 0(`owner`)을 덮어써 `ownerUnchanged`를 깨는 잠복 반례였다.
  현재 모듈은 슬롯 0을 `owner` 미러로 예약하고 카운터를 슬롯 1에 두어 어떤
  페이로드로도 owner 슬롯을 건드릴 수 없다(내장 EVM으로 확인).
- **방어:** 신뢰된 라이브러리만 delegatecall, 프록시 저장소 레이아웃 정렬, EIP-1967.

### 약한/예측 가능한 난수 (Ethernaut CoinFlip, Capture the Ether "Predict the Future")
- **취약(PredictableLottery):** 당첨값을 `keccak256(block.timestamp, prevrandao,
  number) % 100`으로 정한다. 호출자가 같은 트랜잭션에서 동일 값을 계산할 수 있다.
  에이전트는 소스의 엔트로피 식을 그대로 복제해 항상 맞는 값을 제출, 하우스 float를
  솔벤시 하한 밑으로 드레인 → `houseSolvent` 위반.
- **안전(CommitLottery):** 당첨 조건이 블록 변수가 아니라 사전 커밋된 해시(commit-
  reveal)다. 스캐너 판별자: 블록 엔트로피 소스 **AND** (keccak256/모듈로 혼합)
  **AND** 값 이전이 같은 함수에 있을 때만 스코어링. `block.timestamp` 데드라인
  체크만으로는 트리거되지 않는다 → 오탐 없음.
- **방어:** commit-reveal, Chainlink VRF, 미래 블록해시, 온체인 즉시 엔트로피 금지.

### 미보호 initializer (Ethernaut Motorbike, 초기화 안 된 프록시)
- **취약(OpenInitializer):** `initialize()`에 `initialized` 가드도 접근 제어도 없어
  누구나 첫 호출로 admin 슬롯을 차지한다. 에이전트가 initializer를 호출해 탈취 →
  `adminUninitialized` 위반.
- **안전(GuardedInitializer):** `require(!initialized)` 가드가 있고 생성자에서 이미
  초기화됨. 스캐너 판별자: `require(!initialized)`/`initializer` modifier/
  `_disableInitializers`/owner 가드가 있으면 무점수 → 오탐 없음.
- **방어:** OpenZeppelin `initializer`/`_disableInitializers()`, 배포 즉시 초기화,
  생성자 로직 이전.

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

**중국 区块链(블록체인) 스마트컨트랙트 보안 연구**
국내(한국)·영미권 외에 중국 학계의 축적이 크다. 이들 서베이는 취약점을 Solidity 코드층
· EVM 실행층 · 블록체인 시스템층의 3계층으로 나누고, 탐지 기법을 형식검증 · 심볼릭 실행
· 퍼징 · 중간표현 · 딥러닝의 5류로 분류한다(국내 중국 연구는 퍼징·ML에 집중, 심볼릭·형식
검증은 상대적으로 적다고 지적). 우리 도구의 "생성-검증(동적 증명)" 접근은 이 분류의
퍼징 + 동적 검증에 해당하며, "위험 신호"가 아니라 실행 PoC로 확증한다는 점이 차별점이다.
- 智能合约安全漏洞检测技术研究综述 (스마트컨트랙트 보안 취약점 탐지 기술 연구 종합), 软件学报(Journal of Software) — https://www.jos.org.cn/jos/article/abstract/6375
- 智能合约漏洞检测技术综述 (스마트컨트랙트 취약점 탐지 기술 종합), 软件学报 2024 — https://www.jos.org.cn/html/2024/1/6810.htm
- 智能合约安全漏洞检测研究进展 (스마트컨트랙트 보안 취약점 탐지 연구 진전), 软件学报 — https://www.jos.org.cn/jos/article/abstract/7046
- 区块链智能合约漏洞检测与自动化修复综述 (블록체인 스마트컨트랙트 취약점 탐지·자동수정 종합), 计算机应用(Journal of Computer Applications) — https://www.joca.cn/CN/10.11772/j.issn.1001-9081.2022020179
- 基于深度学习的智能合约漏洞检测方法综述 (딥러닝 기반 스마트컨트랙트 취약점 탐지 방법 종합), 四川大学学报 2023 — http://science.scu.edu.cn/zh/article/doi/10.19907/j.0490-6756.2023.020001/
- BCodeVis：面向区块链智能合约的漏洞检测可视分析方法 (블록체인 스마트컨트랙트 취약점 탐지 시각분석), 计算机辅助设计与图形学学报 2024 — https://www.jcad.cn/cn/article/pdf/preview/10.3724/SP.J.1089.2024-00496.pdf
- SliSE — Efficiently Detecting Reentrancy Vulnerabilities in Complex Smart Contracts (프로그램 슬라이싱 + 심볼릭 실행, 복합 컨트랙트 재진입), Zexu Wang·Jiachi Chen·Yanlin Wang·Yu Zhang·Weizhe Zhang·Zibin Zheng (中山大学·哈尔滨工业大学), FSE 2024 — https://arxiv.org/abs/2403.11254
- A Comparative Evaluation of Automated Analysis Tools for Solidity Smart Contracts, Zhiyuan Wei 등, 2023 — https://arxiv.org/abs/2310.20212
- Unity is Strength: Enhancing Precision in Reentrancy Vulnerability Detection — https://arxiv.org/abs/2402.09094

**컨트랙트 워게임 (신규 계열의 출처 · 벤치마크)**
- Ethernaut (OpenZeppelin) — https://ethernaut.openzeppelin.com
  · Delegation / Preservation(delegatecall 하이재킹), CoinFlip(약한 난수),
  Motorbike(미보호 initializer), Reentrancy, Token(언더플로)
- Damn Vulnerable DeFi — https://www.damnvulnerabledefi.xyz
  · Puppet/Compromised(오라클 조작), Selfie(거버넌스 플래시론), Climber(delegatecall)
- Capture the Ether — https://capturetheether.com
  · Predict the Future / Guess the Random Number(약한 난수), Token Sale/Whale(오버·언더플로)
- Ethernaut/CTF 자동 풀이 · LLM 벤치마크
  - Can LLMs Solve Ethernaut? / SC-Bench 계열 SC 취약점 벤치마크 — https://arxiv.org/abs/2410.11550
  - CTF 자동 해결 에이전트(NYU CTF Bench) — https://arxiv.org/abs/2406.05590
- delegatecall / 프록시 초기화 취약 정리
  - SoK: Delegatecall & Proxy Upgrade 패턴 위험 (USENIX/ARES 계열) — https://arxiv.org/abs/2403.00758
  - "Do not initialize your logic contract" — OpenZeppelin UUPS/Initializable 가이드
    https://docs.openzeppelin.com/contracts/5.x/api/proxy#Initializable
- 온체인 난수 위험 (Chainlink VRF, commit-reveal)
  - Chainlink VRF: Verifiable Random Function — https://docs.chain.link/vrf
