# 참고자료 — 스마트컨트랙트 취약점 탐지 연구·도구

TRUST404 Track 04(Autonomous Exploit Prover)를 만들며 참고한 자료 모음이다. 이 도구의
입장은 **"위험 신호"가 아니라 실행되는 PoC로 확증(생성-검증, dynamic proof)** 이며, 아래
도구/논문들과의 관계를 함께 정리한다.

## 1. 이 도구의 접근 (positioning)
- **생성-검증 루프**: 정적 스캐너(7계열 템플릿) + 범용 퍼저(호출 시퀀스 · 재진입 합성 ·
  다중 컨트랙트 AMM 조작 · 플래시론 차용자 · 스토리지 보조)로 후보를 만들고, 내장 EVM에서
  불변식/효과가 실제로 깨지는지 검증한 것만 보고한다(오탐 0 지향).
- **멀티버전 백엔드**: 타깃 pragma에 맞춰 solc 0.6/0.7/0.8을 골라 컴파일(pre-0.8 정수
  래핑 등 실제 의미 재현).
- **분류·연동**: 발견마다 SWC/CWE + 수정 diff + 소스 위치, SARIF 2.1.0 출력(GitHub code
  scanning), CI 게이트.

## 2. 사용자 제시 자료 (신규)
- **MVD-HG** — 소스코드 기반 **이종 그래프(AST+CFG+DFG) 융합 + GNN** 으로 라인·컨트랙트
  두 단위에서 7종(산술·재진입·타임스탬프 의존·위험 delegatecall 등)을 분류(Python/Solidity).
  → 우리와 상호보완: MVD-HG는 학습 기반 "탐지/랭킹", 우리는 "동적 증명". 스캐너가 랭킹한
  후보를 우리 검증기가 확증하는 파이프라인이 가능.
  https://github.com/Astronaut-diode/MVD-HG
- **Beosin VaaS-ETH Extension** — VS Code 확장. ETH 스마트컨트랙트 **형식 검증** 기반
  자동 탐지(위험 코드 위치·사유 표시, 로컬 실행, 5대 분류·27항목). 상용 감사 도구의
  IDE 통합 사례.
  https://gitee.com/boc_v2_admin/Beosin-VaaS-ETH-Extension · 원본 https://github.com/BeosinBeosin/Beosin-VaaS-ETH-Extension
- **ChainMaker(长安链) 스마트컨트랙트 취약점 탐지** — 심볼릭 실행 경로 정보를 사전 정의
  규칙과 매칭. **WASM** 컨트랙트는 WANA가 WASM 바이트코드에서 CFG를 구성해 분석(EVM 외
  런타임의 계약 보안 사례).
  https://docs.chainmaker.org.cn/dev/%E6%99%BA%E8%83%BD%E5%90%88%E7%BA%A6%E6%BC%8F%E6%B4%9E%E6%A3%80%E6%B5%8B%E5%B7%A5%E5%85%B7.html
  (WASM vulcheck: https://docs.chainmaker.org.cn/tech/ )

## 3. 중국 区块链 스마트컨트랙트 보안 연구
취약점을 Solidity 코드층·EVM 실행층·시스템층으로, 탐지를 형식검증·심볼릭·퍼징·중간표현·
딥러닝(·오염분석)으로 분류하는 서베이. **탐지의 exploitability 가 낮다**는 공통 한계가
이 도구(동적 PoC)의 자리이다. 상세 매핑은 [`ARCHITECTURE.md`](../ARCHITECTURE.md) §1.5.

- 钱鹏 등, 智能合约安全漏洞检测技术研究综述, 软件学报 2022, 33(8):3059-3085
  DOI 10.13328/j.cnki.jos.006375 — https://www.jos.org.cn/html/2022/8/6375.htm
  3계층(코드/EVM/시스템) × 5방법. 형식검증은 자동화 낮음·도달 불가 경로 FP.
  심볼릭은 경로폭발. 퍼징은 의미 부족. IR은 규칙 우회. DL은 위치 설명 없음.
- 董伟良 등, 智能合约漏洞检测技术综述, 소프트웨어学报 2024, 35(1):38-62
  DOI 10.13328/j.cnki.jos.006810 — https://www.jos.org.cn/html/2024/1/6810.htm
  84편(~2021-07). 6방법(+오염). 중국=퍼징·ML, 국제=심볼릭·형식검증.
  개방성 중국 26% / 국제 63%. EthPloit(퍼징+오염→익스플로잇), teEther(심볼릭 페이로드).
- 智能合约安全漏洞检测研究进展, 软件学报 — https://www.jos.org.cn/jos/article/abstract/7046
- 区块链智能合约漏洞检测与自动化修复综述, 计算机应用 — https://www.joca.cn/CN/10.11772/j.issn.1001-9081.2022020179
- 基于深度学习的智能合约漏洞检测方法综述, 四川大学学报 2023 — http://science.scu.edu.cn/zh/article/doi/10.19907/j.0490-6756.2023.020001/
- BCodeVis：面向区块链智能合约的漏洞检测可视分析方法, 计算机辅助设计与图形学学报 2024 — https://www.jcad.cn/cn/article/pdf/preview/10.3724/SP.J.1089.2024-00496.pdf
- SliSE — FSE 2024, 中山大学·哈尔滨工业大学 — https://arxiv.org/abs/2403.11254
  I-PDG 슬라이싱 + 심볼릭. 복잡 컨트랙트 F1 78.65% (비교도구 ≤9.26%).
- A Comparative Evaluation of Automated Analysis Tools for Solidity, Zhiyuan Wei 등, 2023 — https://arxiv.org/abs/2310.20212

## 4. 자동 익스플로잇 생성 · 벤치마크
- A1: AI Agent Smart Contract Exploit Generation — https://arxiv.org/pdf/2507.05558
  도구 6개(소스·ctor·상태·sanitizer·concrete exec·수익). 실패 PoC 히스토리.
- PoCo: Agentic Proof-of-Concept Exploit Generation (ACM TOSEM) — https://doi.org/10.1145/3816704 · https://arxiv.org/abs/2511.02780
  ReAct + forge compile/test. 잘 만들어진 PoC 50/50, 논리 정확 32/50.
  데이터셋 https://github.com/ASSERT-KTH/Proof-of-Patch/
- AI agents find smart contract exploits (Anthropic) — https://red.anthropic.com/2025/smart-contracts/
- SoK: Root Causes of $1 Billion Loss in SC Attacks — https://arxiv.org/html/2507.20175

## 5. 컨트랙트 워게임 · 실사고 (벤치마크, 레벨 솔버 아님)
- The Ethernaut — https://ethernaut.openzeppelin.com (`examples/ethernaut/RESULTS.md`, 32 자동 증명)
- Damn Vulnerable DeFi v4 — https://www.damnvulnerabledefi.xyz
  계열 승격: Unstoppable→donation DoS, Truster→unpermissioned callback,
  Selfie→governance flashloan, Climber→execute-before-schedule.
  솔버 참고(베끼지 않음): https://github.com/SunWeb3Sec/damn-vulnerable-defi-v4-solutions
- Capture the Ether — https://capturetheether.com
- Paradigm CTF — Vault 등(프록시 Guard + emergencyCall)
- WTF-CTF (Foundry 모음) — https://github.com/WTFAcademy/WTF-CTF
- 실사고 2026-09 Ether.fi AtomicQueue (SlowMist): `solve()` 의 solver 인자
  접근제어 없음 → Truster 와 **같은 계열**. https://x.com/SlowMist_Team/status/2098344499923784048
- 인브라우저 EVM 재실행 플레이그라운드 (24건 Aug–Sep 2026): https://crypto.training/hacks/

## 6. 접근 비교 (요약)
| 도구/연구 | 방법 | 산출 | 확증 방식 |
| --- | --- | --- | --- |
| MVD-HG | 이종그래프+GNN | 취약 라인/유형 분류 | 학습 예측 |
| Beosin VaaS | 형식 검증 | 위험 위치·사유 | 정형 증명 |
| ChainMaker/WANA | 심볼릭+규칙 (WASM CFG) | 규칙 매칭 경보 | 경로 조건 |
| SliSE | 슬라이싱+심볼릭 | 재진입 경보 | 도달성 검증 |
| EthPloit / teEther | 퍼징+오염 / 심볼릭 페이로드 | 익스플로잇 시드 | 부분 실행 |
| PoCo / A1 | LLM ReAct + Foundry | PoC 초안 | forge test · 역사 상태 |
| **본 도구** | 스캐너+계열 synth+퍼저 **생성-검증** | 실행 PoC + SWC/CWE + 수정 diff | **내장 EVM 동적 증명** |
