#!/usr/bin/env python3
# TRUST404 Track 04 — Auditor CLI (실무용 래퍼)
# =============================================================================
# 임의의 .sol 파일 또는 디렉터리를 입력받아, 익스플로잇 증명 엔진(스캐너 템플릿
# 7계열 + 범용 퍼저: 호출 시퀀스 · 재진입 합성 · 다중 컨트랙트 AMM 조작 · 플래시론
# 차용자)을 돌려 **동적으로 증명된 취약점**을 찾아 감사 리포트를 만든다.
#
#   - 불변식을 안 줘도 동작한다(자동 효과검사: 자금 유출 / owner 탈취 / 부채>담보).
#     프로젝트 관례대로 `<Name>.invariants.sol` 또는 --invariants 를 주면 그 불변식으로
#     증명한다.
#   - 산출물: report.json (기계용) · report.md (사람용) · exploits/<Contract>.sol (PoC).
#   - 결정론: 같은 입력 + 같은 --seed → 같은 PoC.
#
# 사용:
#   python3 agent/audit.py <파일|디렉터리> [--out audit] [--seed 42]
#        [--invariants Inv.sol] [--seed-eth 10] [--fail-on proven|high|critical|none]
#        [--include-safe] [--quiet]
# 종료코드: --fail-on 기준으로 발견 시 3, 정상 종료 0, 사용법/내부 오류 2.
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path

EXIT_OK, EXIT_ERROR, EXIT_FINDINGS = 0, 2, 3

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def load_engine():
    """엔진(api/prove.py)을 경로로 로드한다 — 패키징에 의존하지 않는다."""
    here = Path(__file__).resolve().parent
    for p in (here.parent / "api" / "prove.py", here / "prove.py", Path("api/prove.py")):
        if p.exists():
            spec = importlib.util.spec_from_file_location("t404engine", p)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            return m
    raise SystemExit("error: exploit engine (api/prove.py) not found")


_SKIP_NAMES = {"Setup", "Invariants", "Test", "Script"}

def concrete_contracts(src, eng):
    """소스에서 인터페이스/라이브러리/추상/스크립트를 제외한, 외부 상태변경 함수를
    가진 구체 컨트랙트 이름을 등장 순서대로 돌려준다."""
    s = eng._strip_comments(src)
    bodies = eng._contract_bodies(s)
    is_scriptish = "forge-std" in src or "import" in src and re.search(r"is\s+(Script|Test)\b", s)
    out = []
    for m in re.finditer(r"(abstract\s+)?(contract|interface|library)\s+(\w+)", s):
        is_abstract, kind, name = m.group(1), m.group(2), m.group(3)
        if kind != "contract" or is_abstract or name in _SKIP_NAMES:
            continue
        if is_scriptish and (name.endswith("Setup") or name.endswith("Script") or name.endswith("Test")):
            continue
        body = bodies.get(name, "")
        fns = eng._functions(body)
        has_mut = any(f.get("external") and "view" not in f["head"] and "pure" not in f["head"] for f in fns)
        # receive/fallback 만 있거나 위험 프리미티브를 쓰는 컨트랙트도 분석 대상
        interesting = bool(re.search(r"\breceive\s*\(|\bfallback\s*\(|delegatecall|selfdestruct|\.call\s*\{\s*value", body))
        # 함수가 전혀 없는 inert 컨트랙트(Force 원형)도 강제-ETH 대상으로 분석
        inert = (not fns) and (not re.search(r"\b(receive|fallback|payable)\b", body))
        if (has_mut or interesting or inert) and name not in out:
            out.append(name)
    return out


def synth_ctor_args(eng, src, contract):
    """타깃 생성자 시그니처를 읽어 배포용 기본 인자를 합성한다. 문자열/바이트/배열/
    구조체가 필요하면 None(분석 불가)을 돌려준다."""
    body = eng._contract_bodies(eng._strip_comments(src)).get(contract, "")
    m = re.search(r"constructor\s*\(([^)]*)\)", body)
    if not m or not m.group(1).strip():
        return []
    def default_for(t):
        if t == "address": return "0x000000000000000000000000000000000000dEaD"
        if t.startswith("uint") or t.startswith("int"): return 10**18
        if t == "bool": return False
        if t == "bytes32": return "0x" + "11" * 32
        if re.fullmatch(r"bytes\d+", t): return "0x" + "11" * int(t[5:])
        if t == "string": return "trust404"
        if t == "bytes": return "0x"
        return None
    args = []
    for p in m.group(1).split(","):
        toks = p.split()
        if not toks:
            continue
        t = toks[0]
        arr = re.fullmatch(r"([a-z0-9]+)\[(\d+)\]", t)
        if arr:
            elem = default_for(arr.group(1))
            if elem is None:
                return None
            args.append([elem] * int(arr.group(2)))
            continue
        if t == "address":
            args.append("0x000000000000000000000000000000000000dEaD")  # 유효한 20-byte 테스트 주소
        elif t.startswith("uint") or t.startswith("int"):
            args.append(10**18)
        elif t == "bool":
            args.append(False)
        elif t == "bytes32":
            args.append("0x" + "11" * 32)   # 알려진 값(자체 배포이므로 우리가 안다)
        elif t == "string":
            args.append("trust404")
        elif t == "bytes":
            args.append("0x")
        else:
            return None  # 배열/구조체 등 → 안전하게 분석 스킵
    return args


def severity_for(res):
    """엔진 결과 → 심각도 + 사람이 읽을 근거."""
    if not res.get("proven"):
        scores = (res.get("steps") or [{}])[0].get("scores") or {}
        positive = {k: v for k, v in scores.items() if v > 0}
        if positive:
            fam = max(positive.items(), key=lambda kv: kv[1])[0]
            return "MEDIUM", f"정적 신호 감지({fam}) — 동적 증명 미성립(휴리스틱)", True
        return "INFO", "취약 패턴 미검출", False
    reason = (res.get("firstViolated") or "").lower()
    strat = res.get("strategy") or ""
    # 효과/전략 기반 심각도
    if "owner" in reason or "hijack" in reason or strat.startswith(("delegatecall", "unprotected_init", "flashloan")):
        sev = "CRITICAL"
    elif "drain" in reason or "solvent" in reason or strat.startswith(("reentrancy", "access_control", "integer")):
        sev = "CRITICAL"
    elif "debt" in reason or "collateral" in reason or strat.startswith(("oracle", "amm", "weak_randomness")):
        sev = "HIGH"
    else:
        sev = "HIGH"
    return sev, res.get("firstViolated") or "invariant violated", True


FAMILY_KO = {
    "reentrancy": "재진입 (CEI 위반)",
    "access_control": "접근 제어 누락",
    "integer_underflow": "정수 언더플로",
    "oracle_manipulation": "오라클 가격 조작",
    "delegatecall_hijack": "delegatecall 하이재킹",
    "weak_randomness": "약한 난수",
    "unprotected_init": "미보호 initializer",
    "griefing_dos": "그리핑 DoS (예상치 못한 revert)",
    "callback_inconsistency": "신뢰 못 할 콜백 반환 신뢰",
}

# 계열 → 표준 분류(SWC/CWE) + 수정 가이드 + 코드 핫스팟 탐지용 토큰.
CLASS = {
    "reentrancy": {
        "rule": "SWC-107", "cwe": "CWE-841", "title": "Reentrancy (재진입)",
        "fix": "Checks-Effects-Interactions 순서 준수, nonReentrant 뮤텍스, pull-payment 패턴.",
        "hot": r"\.call\s*\{\s*value"},
    "access_control": {
        "rule": "SWC-105", "cwe": "CWE-284", "title": "Missing / broken access control",
        "fix": "특권 함수에 onlyOwner/role 접근 제어, 초기화 가드, 최소 권한, 타임락·다중서명.",
        "hot": r"\bowner\s*=|\.call\s*\{\s*value"},
    "integer_underflow": {
        "rule": "SWC-101", "cwe": "CWE-191", "title": "Integer overflow / underflow",
        "fix": "0.8+ 기본 오버플로 검사 유지, unchecked 블록은 사전 경계 검증 후에만 사용.",
        "hot": r"unchecked"},
    "oracle_manipulation": {
        "rule": "TR404-ORACLE", "cwe": "CWE-345", "title": "Price oracle manipulation",
        "fix": "TWAP·다중 오라클(Chainlink)·staleness/편차 상한·서킷 브레이커. 단일 블록 spot price 금지.",
        "hot": r"spotPrice|getPrice|quote|reserve"},
    "delegatecall_hijack": {
        "rule": "SWC-112", "cwe": "CWE-829", "title": "Delegatecall to untrusted callee",
        "fix": "신뢰된 고정 라이브러리에만 delegatecall, 프록시 저장소 레이아웃 정렬(EIP-1967).",
        "hot": r"delegatecall"},
    "weak_randomness": {
        "rule": "SWC-120", "cwe": "CWE-330", "title": "Weak / predictable randomness",
        "fix": "commit-reveal, Chainlink VRF, 미래 블록해시. 온체인 즉시 엔트로피 금지.",
        "hot": r"block\.(timestamp|prevrandao|difficulty|number)|blockhash"},
    "unprotected_init": {
        "rule": "SWC-118", "cwe": "CWE-665", "title": "Unprotected initializer",
        "fix": "initializer 가드(require(!initialized))/_disableInitializers(), 배포 즉시 초기화.",
        "hot": r"initialize|\binit\b"},
    "flashloan": {
        "rule": "TR404-FLASHLOAN", "cwe": "CWE-841", "title": "Flash-loan-enabled privilege",
        "fix": "지분/잔액 기반 권한은 스냅샷(과거 블록)·시간가중으로. 단일 트랜잭션 잔액 신뢰 금지.",
        "hot": r"flash|balanceOf"},
    "amm": {
        "rule": "TR404-ORACLE", "cwe": "CWE-345", "title": "Multi-contract AMM price manipulation",
        "fix": "TWAP·외부 오라클·거래 슬리피지/편차 상한. 얇은 풀의 즉시 준비금 신뢰 금지.",
        "hot": r"swap|reserve|quote|spotPrice"},
    "storage": {
        "rule": "SWC-136", "cwe": "CWE-767", "title": "Private data read from storage",
        "fix": "온체인 스토리지는 공개다. 비밀/키/암호를 평문으로 저장하지 말 것(오프체인 커밋/해시).",
        "hot": r"private"},
    "griefing_dos": {
        "rule": "SWC-113", "cwe": "CWE-703", "title": "DoS via unexpected revert (griefing)",
        "fix": "push 송금(transfer/send) 대신 pull-payment(withdraw 패턴). 외부 호출 실패가 핵심 상태 전이를 막지 않게 분리.",
        "hot": r"\.transfer\s*\(|\.send\s*\("},
    "callback_inconsistency": {
        "rule": "TR404-CALLBACK", "cwe": "CWE-807", "title": "Trusting an untrusted callback's return",
        "fix": "외부(특히 msg.sender) 콜백 반환을 신뢰해 분기·상태전이하지 말 것. 같은 값을 재호출로 두 번 믿지 말고, 결과를 캐시·검증하거나 신뢰 경계를 명확히.",
        "hot": r"\)\s*\.\s*\w+\s*\("},
    "forced_ether": {
        "rule": "SWC-132", "cwe": "CWE-667", "title": "Unexpected ether balance (forced via selfdestruct)",
        "fix": "address(this).balance 를 로직 불변식으로 신뢰하지 말 것. selfdestruct/코인베이스로 강제 입금될 수 있다.",
        "hot": r"balance"},
    "lockup_bypass": {
        "rule": "SWC-105", "cwe": "CWE-284", "title": "Token lockup bypass via transferFrom",
        "fix": "락업/제한을 transfer 뿐 아니라 transferFrom(그리고 _update/_transfer 훅 등 모든 이전 경로)에 일관 적용.",
        "hot": r"transferFrom"},
    "access_gate_bypass": {
        "rule": "SWC-105", "cwe": "CWE-284", "title": "Access gate bypass (msg.sender/extcodesize/tx.origin)",
        "fix": "extcodesize·tx.origin·msg.sender 기반 게이트는 우회 가능(생성자 호출·7702 등). 실제 권한/서명 기반 검증을 쓸 것.",
        "hot": r"extcodesize|tx\.origin|keccak256"},
    "code_puzzle": {
        "rule": "TR404-CODEGEN", "cwe": "CWE-1188", "title": "Attacker-supplied code/solver accepted",
        "fix": "외부에서 등록하는 코드/solver 의 동작·크기·불변식을 검증하거나 신뢰 경계를 명확히 할 것.",
        "hot": r"solver|create\s*\("},
    "generic": {
        "rule": "TR404-EXPLOIT", "cwe": "CWE-284", "title": "Exploitable asset loss / privilege change",
        "fix": "관찰된 자산 손실·권한 변경 경로를 재현 PoC로 확인 후 근본 원인(접근제어/CEI/검증)을 수정.",
        "hot": r"\.call\s*\{\s*value|\bowner\s*=|\badmin\s*="},
}


# 규칙별 수정 코드 스니펫(제안 diff). 실제 코드에 맞춘 것은 아니고 패턴 가이드.
FIX_DIFF = {
    "SWC-107": (
        "-        (bool ok,) = msg.sender.call{value: amount}(\"\");\n"
        "-        balances[msg.sender] -= amount;   // 상태 갱신이 call 뒤 → 재진입\n"
        "+        balances[msg.sender] -= amount;   // Checks-Effects-Interactions\n"
        "+        (bool ok,) = msg.sender.call{value: amount}(\"\");\n"
        "+        // 또는 함수에 nonReentrant 뮤텍스 적용"),
    "SWC-105": (
        "-    function adminWithdraw(address to, uint256 amt) external {\n"
        "+    function adminWithdraw(address to, uint256 amt) external onlyOwner {\n"
        "         (bool ok,) = to.call{value: amt}(\"\"); require(ok);\n"
        "     }"),
    "SWC-101": (
        "-        unchecked { balanceOf[msg.sender] -= amount; }  // 언더플로\n"
        "+        require(balanceOf[msg.sender] >= amount, \"insufficient\");\n"
        "+        balanceOf[msg.sender] -= amount;  // 0.8 기본 검사 유지"),
    "TR404-ORACLE": (
        "-        uint256 price = pool.spotPrice();   // 단일 블록 조작 가능\n"
        "+        uint256 price = oracle.consult(TWAP_WINDOW);  // 시간가중 평균\n"
        "+        require(block.timestamp - oracle.updatedAt() < MAX_STALE, \"stale\");"),
    "SWC-112": (
        "-        (bool ok,) = module.delegatecall(data);  // module 이 인자(임의)\n"
        "+        require(module == TRUSTED_LIB, \"untrusted module\");\n"
        "+        (bool ok,) = TRUSTED_LIB.delegatecall(data);"),
    "SWC-120": (
        "-        uint256 r = uint256(keccak256(abi.encodePacked(\n"
        "-            block.timestamp, block.prevrandao))) % N;  // 예측 가능\n"
        "+        uint256 r = vrf.randomWord(requestId) % N;  // Chainlink VRF / commit-reveal"),
    "SWC-118": (
        "-    function initialize() external { admin = msg.sender; }  // 무방비\n"
        "+    bool private _initialized;\n"
        "+    function initialize() external {\n"
        "+        require(!_initialized, \"already initialized\"); _initialized = true;\n"
        "+        admin = msg.sender;\n"
        "+    }   // 또는 생성자에서 _disableInitializers()"),
    "TR404-FLASHLOAN": (
        "-        require(gov.balanceOf(msg.sender) * 2 > gov.totalSupply());  // 순간 잔액\n"
        "+        require(gov.getPastVotes(msg.sender, block.number - 1) * 2\n"
        "+                > gov.totalSupply(), \"snapshot\");  // 과거 블록 스냅샷"),
    "TR404-EXPLOIT": (
        "// 관찰된 자산 손실/권한 변경 경로에 접근 제어·CEI·입력 검증을 적용하고\n"
        "// 재현 PoC 로 재검증하십시오."),
    "SWC-136": (
        "-    bytes32 private password;   // 온체인 스토리지는 공개 — 평문 노출\n"
        "+    bytes32 private passwordHash;              // keccak256(secret) 만 저장\n"
        "+    function unlock(bytes32 s) external {\n"
        "+        require(keccak256(abi.encode(s)) == passwordHash);\n"
        "+    }"),
    "TR404-CALLBACK": (
        "-        if (!b.isLastFloor(_floor)) {         // 콜백을 두 번 신뢰\n"
        "-            floor = _floor; top = b.isLastFloor(floor);\n"
        "-        }\n"
        "+        bool last = b.isLastFloor(_floor);    // 한 번만 호출해 캐시\n"
        "+        require(!last, \"already last\");       // 신뢰 경계 명확화\n"
        "+        floor = _floor; top = last;           // 재호출로 재신뢰 금지"),
    "SWC-113": (
        "-        payable(king).transfer(msg.value);  // king 이 revert 하면 영구 락(DoS)\n"
        "-        king = msg.sender;\n"
        "+        pendingReturns[king] += msg.value;   // pull-payment: 실패해도 상태 전이 진행\n"
        "+        king = msg.sender;\n"
        "+    }\n"
        "+    function withdraw() external {\n"
        "+        uint256 amt = pendingReturns[msg.sender]; pendingReturns[msg.sender] = 0;\n"
        "+        (bool ok,) = msg.sender.call{value: amt}(\"\"); require(ok);"),
}


def classify(strategy, family_hint=None):
    """전략/계열 라벨을 표준 분류로 매핑한다."""
    s = strategy or ""
    if s.startswith("proxy") or s.startswith("storage-collision"):
        return CLASS["delegatecall_hijack"]
    if s.startswith("storage"):
        return CLASS["storage"]
    if s.startswith("multiblock"):
        return CLASS["weak_randomness"]
    if s.startswith("king-dos") or s.startswith("griefing"):
        return CLASS["griefing_dos"]
    if s.startswith("callback") or s.startswith("shop"):
        return CLASS["callback_inconsistency"]
    if s.startswith("force"):
        return CLASS["forced_ether"]
    if s.startswith("lockup"):
        return CLASS["lockup_bypass"]
    if s.startswith("gas-griefing"):
        return CLASS["griefing_dos"]
    if s.startswith("gatekeeper"):
        return CLASS["access_gate_bypass"]
    if s.startswith("magic-number"):
        return CLASS["code_puzzle"]
    if s.startswith("higher-order") or s.startswith("switch"):
        return CLASS["access_gate_bypass"]
    if s.startswith("array-underflow"):
        return CLASS["storage"]
    if s.startswith("dex-drain") or s.startswith("dex2-drain"):
        return CLASS["amm"]
    if s.startswith("stake-accounting"):
        return CLASS["access_control"]
    if s.startswith("uninitialized"):
        return CLASS["unprotected_init"]
    if s.startswith("puzzle-wallet"):
        return CLASS["delegatecall_hijack"]
    if s.startswith("good-samaritan"):
        return CLASS["callback_inconsistency"]
    if s.startswith("eip7702"):
        return CLASS["reentrancy"]
    if s.startswith("amm-manip"):
        return CLASS["amm"]
    if s.startswith("flashloan"):
        return CLASS["flashloan"]
    if s.startswith("reentrancy"):
        return CLASS["reentrancy"]
    base = s.split(" ")[0].split(":")[0]
    if base in CLASS:
        return CLASS[base]
    if family_hint in CLASS:
        return CLASS[family_hint]
    return CLASS["generic"]


def find_location(eng, src, contract, cls):
    """SARIF 위치용: 컨트랙트 선언 라인과, 계열 핫스팟 토큰이 처음 나오는 라인."""
    lines = src.splitlines()
    decl = 1
    for i, ln in enumerate(lines, 1):
        if re.search(r"\bcontract\s+" + re.escape(contract) + r"\b", ln):
            decl = i
            break
    hot = decl
    body_start = decl
    pat = cls.get("hot")
    if pat:
        for i in range(body_start - 1, len(lines)):
            if re.search(pat, lines[i]):
                hot = i + 1
                break
    return decl, hot


def analyze_source(eng, src, contract, invariants, seed_eth, seed):
    """한 컨트랙트를 분석한다. prove_sources 를 직접 호출(엔진 전량: 템플릿+퍼저)."""
    manifest = eng._default_manifest()
    manifest["target"]["name"] = contract
    manifest["deploy"]["value_wei"] = str(int(seed_eth * 10**18))
    cargs = synth_ctor_args(eng, src, contract)
    if cargs is None:
        return {"name": contract, "proven": False,
                "error": "constructor needs string/bytes/array args (auto-deploy unsupported)",
                "steps": [{"step": "scan", "scores": {}}]}
    manifest["deploy"]["constructor_args"] = cargs
    do_verify = bool(invariants)
    t0 = time.time()
    try:
        res = eng.prove_sources(contract, src, invariants or None, manifest, do_verify=do_verify)
    except Exception as e:
        return {"name": contract, "proven": False, "error": str(e)[:300],
                "ms": int((time.time() - t0) * 1000)}
    return res


def build_report(findings, args, total_analyzed=None):
    proven = [f for f in findings if f["res"].get("proven")]
    heur = [f for f in findings if (not f["res"].get("proven"))
            and (f["severity"] == "MEDIUM" or f["res"].get("heuristics"))]
    clean = [f for f in findings if f["severity"] in ("INFO",) and not f["res"].get("proven")]
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    report = {
        "tool": "TRUST404 Track04 · Autonomous Exploit Prover",
        "version": "0.2",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": args.seed,
        "engine": "solc 0.8.24 · in-memory EVM (py-evm) · templates+fuzzer",
        "summary": {
            "contracts_analyzed": total_analyzed if total_analyzed is not None else len(findings),
            "reported": len(findings),
            "proven_vulnerabilities": len(proven),
            "heuristic_flags": len(heur),
            "clean": len(clean),
            "severity_counts": counts,
        },
        "findings": [],
    }
    for f in findings:
        r = f["res"]
        scores = (r.get("steps") or [{}])[0].get("scores") or {}
        cls = f.get("cls") or CLASS["generic"]
        report["findings"].append({
            "contract": f["contract"],
            "file": f["file"],
            "line": f.get("line"),
            "severity": f["severity"],
            "proven": bool(r.get("proven")),
            "heuristic": bool(r.get("heuristics")),
            "why": (r.get("heuristics") or [{}])[0].get("why", ""),
            "strategy": r.get("strategy"),
            "rule": cls["rule"],
            "cwe": cls["cwe"],
            "title": cls["title"],
            "remediation": cls["fix"],
            "fix_diff": FIX_DIFF.get(cls["rule"], ""),
            "broken": r.get("firstViolated") or "",
            "evidence": f["evidence"],
            "drained_eth": f.get("drained_eth"),
            "scanner_scores": {k: v for k, v in scores.items() if v},
            "poc_file": f.get("poc_file"),
            "mode": r.get("mode"),
            "ms": r.get("ms"),
            "error": r.get("error"),
        })
    return report


def render_md(report):
    s = report["summary"]
    badge = {"CRITICAL": "🟥 CRITICAL", "HIGH": "🟧 HIGH", "MEDIUM": "🟨 MEDIUM",
             "LOW": "🟦 LOW", "INFO": "⬜ INFO"}
    L = []
    L.append("# 스마트컨트랙트 감사 리포트")
    L.append("")
    L.append(f"> {report['tool']} · v{report['version']} · {report['generated_at']}")
    L.append(f"> 엔진: {report['engine']} · seed={report['seed']}")
    L.append("")
    cc = s["severity_counts"]
    L.append("## 요약")
    L.append("")
    L.append(f"- 분석한 컨트랙트: **{s['contracts_analyzed']}** (리포트 표기: {s.get('reported', s['contracts_analyzed'])})")
    L.append(f"- **증명된 취약점: {s['proven_vulnerabilities']}** "
             f"(🟥 {cc['CRITICAL']} · 🟧 {cc['HIGH']})")
    L.append(f"- 휴리스틱 플래그(미증명): {s['heuristic_flags']} · 정상: {s['clean']}")
    L.append("")
    L.append("| 컨트랙트 | 심각도 | 판정 | 계열/전략 | SWC / CWE | 근거 |")
    L.append("|---|---|---|---|---|---|")
    def sev_key(f): return (-SEV_ORDER.get(f["severity"], 0), not f["proven"])
    for f in sorted(report["findings"], key=sev_key):
        verdict = "PROVEN" if f["proven"] else ("휴리스틱" if (f.get("heuristic") or f["severity"] == "MEDIUM") else "clean")
        strat = f["strategy"] or (", ".join(f["scanner_scores"].keys()) or ("정적 휴리스틱" if f.get("heuristic") else "—"))
        ev = (f["evidence"] or "").replace("|", "\\|")
        L.append(f"| `{f['contract']}` | {badge.get(f['severity'],f['severity'])} | {verdict} | {strat} | {f['rule']} · {f['cwe']} | {ev} |")
    L.append("")
    proven = [f for f in report["findings"] if f["proven"]]
    if proven:
        L.append("## 증명된 취약점 상세")
        L.append("")
        for i, f in enumerate(sorted(proven, key=sev_key), 1):
            L.append(f"### {i}. `{f['contract']}` — {f['title']} — {badge.get(f['severity'],f['severity'])}")
            L.append("")
            L.append(f"- 위치: `{f['file']}:{f.get('line')}`")
            L.append(f"- 분류: **{f['rule']} · {f['cwe']}**")
            L.append(f"- 전략: **{f['strategy']}** · 모드: {f['mode']}")
            L.append(f"- 깨진 속성/효과: **{f['broken']}**")
            if f.get("drained_eth") is not None:
                L.append(f"- 관찰된 자금 이동: **{f['drained_eth']} ETH**")
            if f.get("poc_file"):
                L.append(f"- PoC: `{f['poc_file']}`")
            L.append(f"- 수정 가이드: {f['remediation']}")
            if f.get("fix_diff"):
                L.append("")
                L.append("```diff")
                L.append(f["fix_diff"])
                L.append("```")
            L.append("")
    heur = [f for f in report["findings"] if (not f["proven"]) and (f.get("heuristic") or f["severity"] == "MEDIUM")]
    if heur:
        L.append("## 휴리스틱 플래그 (동적 미증명 — 수동 확인 권장)")
        L.append("")
        for f in heur:
            if f.get("heuristic"):
                L.append(f"### `{f['contract']}` — {f['title']} — {badge.get(f['severity'],f['severity'])}")
                L.append(f"- 위치: `{f['file']}:{f.get('line')}` · 분류: **{f['rule']} · {f['cwe']}**")
                if f.get("why"): L.append(f"- 근거: {f['why']}")
                if f.get("remediation"): L.append(f"- 수정 가이드: {f['remediation']}")
                if f.get("fix_diff"):
                    L.append(""); L.append("```diff"); L.append(f["fix_diff"]); L.append("```")
                L.append("")
            else:
                L.append(f"- `{f['contract']}` — 정적 신호: {', '.join(f['scanner_scores'].keys())}")
        L.append("")
    L.append("---")
    L.append("_모든 PoC는 격리된 in-memory EVM(네트워크 차단)에서 방어 연구·자동 검증"
             " 목적으로만 실행됩니다._")
    return "\n".join(L) + "\n"


def render_sarif(report):
    """SARIF 2.1.0 — GitHub code scanning / IDE 로 바로 업로드 가능."""
    sev_level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    sec_sev = {"CRITICAL": "9.0", "HIGH": "7.5", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "1.0"}
    rules = {}
    results = []
    for f in report["findings"]:
        rid = f["rule"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f["title"].replace(" ", ""),
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f["title"] + " — " + f["remediation"]},
                "helpUri": ("https://swcregistry.io/docs/" + rid) if rid.startswith("SWC-")
                           else "https://cwe.mitre.org/data/definitions/" + f["cwe"].split("-")[-1] + ".html",
                "help": {"text": f["remediation"]},
                "properties": {"tags": ["security", f["cwe"]], "security-severity": sec_sev.get(f["severity"], "5.0")},
            }
        uri = f["file"].replace("\\", "/")
        results.append({
            "ruleId": rid,
            "level": sev_level.get(f["severity"], "warning"),
            "message": {"text": f"[{f['severity']}] {f['contract']}: {f['title']} — "
                                + (f["evidence"] or f["broken"] or "")
                                + (f"  (PoC: {f['poc_file']})" if f.get("poc_file") else "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": max(1, int(f.get("line") or 1))}}}],
            "properties": {"proven": f["proven"], "strategy": f["strategy"], "cwe": f["cwe"],
                           "severity": f["severity"]},
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "TRUST404-ExploitProver",
                "informationUri": "https://trust404-prover.vercel.app",
                "version": report["version"],
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def contract_priority(eng, src, contract):
    """대규모 프로젝트 타깃 선별용 우선순위 — 값을 보유/이동하거나 권한·위험
    프리미티브를 쓰는 컨트랙트를 먼저 분석한다."""
    body = eng._contract_bodies(eng._strip_comments(src)).get(contract, "")
    score = 0
    if re.search(r"\.call\s*\{\s*value", body): score += 3
    if "delegatecall" in body: score += 3
    if re.search(r"\bpayable\b", body): score += 2
    if re.search(r"\b(owner|admin)\b", body): score += 2
    if "selfdestruct" in body: score += 2
    if "transferFrom" in body and "balanceOf" in body: score += 1
    return score


def gather_files(path):
    p = Path(path)
    if p.is_file():
        return [p]
    if p.is_dir():
        skip = ("/lib/", "/node_modules/", "/out/", "/.git/", "/test/", "/tests/")
        return sorted(f for f in p.rglob("*.sol")
                      if not any(sk in str(f).replace("\\", "/") + "/" for sk in skip))
    raise SystemExit(f"error: path not found: {path}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="audit", description="TRUST404 Track04 auditor CLI")
    ap.add_argument("path", help=".sol file or a directory of contracts")
    ap.add_argument("--out", default="audit", help="output directory (default: audit)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--seed-eth", type=float, default=10.0, help="ETH seeded into each target (effect mode)")
    ap.add_argument("--invariants", help="optional Invariants.sol to prove custom properties")
    ap.add_argument("--only", help="only analyze this contract name")
    ap.add_argument("--quick", action="store_true", help="빠른 스캔 — 퍼저 예산 축소")
    ap.add_argument("--max-contracts", type=int, default=0,
                    help="분석할 최대 컨트랙트 수(0=무제한, 우선순위 높은 순)")
    ap.add_argument("--fail-on", choices=["none", "proven", "high", "critical"], default="none")
    ap.add_argument("--include-safe", action="store_true", help="also list clean contracts in JSON")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    eng = load_engine()
    if args.quick:
        os.environ["TRUST404_FUZZ_BUDGET"] = "120"
        os.environ.setdefault("TRUST404_MAX_SECONDS", "4")   # 배치: 라운드 심화 시간 상한 축소
    else:
        os.environ.setdefault("TRUST404_MAX_SECONDS", "12")  # 단일 감사: 더 끈질기게
    inv_src = Path(args.invariants).read_text(encoding="utf-8") if args.invariants else None
    files = gather_files(args.path)
    outdir = Path(args.out)
    (outdir / "exploits").mkdir(parents=True, exist_ok=True)

    def log(*a):
        if not args.quiet:
            print(*a, file=sys.stderr)

    # 후보 수집 → 우선순위 정렬 → (선택) 상한 → 분석
    cands = []
    for fp in files:
        try:
            src = fp.read_text(encoding="utf-8")
        except Exception as e:
            log(f"skip {fp}: {e}"); continue
        for c in concrete_contracts(src, eng):
            if args.only and c != args.only:
                continue
            cands.append((fp, src, c))
    cands.sort(key=lambda t: contract_priority(eng, t[1], t[2]), reverse=True)
    if args.max_contracts > 0:
        cands = cands[:args.max_contracts]

    findings = []
    if True:
        for fp, src, c in cands:
            log(f"analyzing {fp}:{c} …")
            res = analyze_source(eng, src, c, inv_src, args.seed_eth, args.seed)
            sev, evidence, is_finding = severity_for(res)
            # 동적 미성립 시: 정적 휴리스틱(예: EIP-7702 receiver-callback 재진입)을 소견으로 승격
            heur_cls = None
            if not res.get("proven"):
                try:
                    allh = eng.static_findings(src) if hasattr(eng, "static_findings") else []
                    bodies = eng._contract_bodies(eng._strip_comments(src)) if hasattr(eng, "_contract_bodies") else {}
                    body = bodies.get(c, src)
                    hs = [h for h in allh if (h.get("core") in body or h.get("function") in body)]
                except Exception:
                    hs = []
                if hs:
                    res["heuristics"] = hs
                    h0 = hs[0]
                    sev = h0.get("severity", "HIGH"); is_finding = True
                    evidence = h0.get("why") or h0.get("title")
                    heur_cls = {"rule": h0["rule"], "cwe": h0["cwe"], "title": h0["title"],
                                "fix": h0.get("fix", ""),
                                "hot": r"onERC721Received|checkOnERC721Received|tx\.origin"}
            drained = None
            try:
                bb = res.get("balance_before_wei"); ba = res.get("balance_after_wei")
                if bb is not None and ba is not None and int(bb) > int(ba):
                    drained = round((int(bb) - int(ba)) / 1e18, 4)
            except Exception:
                pass
            poc_file = None
            if res.get("proven") and res.get("exploit_src"):
                poc_file = str(outdir / "exploits" / f"{c}.sol")
                Path(poc_file).write_text(res["exploit_src"], encoding="utf-8")
            scores = (res.get("steps") or [{}])[0].get("scores") or {}
            pos = {k: v for k, v in scores.items() if v > 0}
            fam_hint = max(pos, key=pos.get) if pos else None
            cls = heur_cls or classify(res.get("strategy"), fam_hint)
            if cls is CLASS["generic"] and "inflated" in (res.get("firstViolated") or ""):
                cls = CLASS["integer_underflow"]   # 토큰 잔액 오버·언더플로 (기타 계열 아닐 때만)
            decl_ln, hot_ln = find_location(eng, src, c, cls)
            findings.append({"contract": c, "file": str(fp), "severity": sev,
                             "evidence": evidence, "res": res, "poc_file": poc_file,
                             "drained_eth": drained, "cls": cls,
                             "line": hot_ln, "decl_line": decl_ln})

    if not args.include_safe:
        findings_out = [f for f in findings if not (f["severity"] == "INFO" and not f["res"].get("proven"))]
    else:
        findings_out = findings
    # 요약 카운트는 표시 대상 기준
    shown = findings_out if findings_out else findings
    report = build_report(shown, args, total_analyzed=len(findings))
    (outdir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (outdir / "report.md").write_text(render_md(report), encoding="utf-8")
    (outdir / "report.sarif").write_text(json.dumps(render_sarif(report), ensure_ascii=False, indent=2), encoding="utf-8")

    s = report["summary"]
    print(f"analyzed={s['contracts_analyzed']} proven={s['proven_vulnerabilities']} "
          f"critical={s['severity_counts']['CRITICAL']} high={s['severity_counts']['HIGH']} "
          f"heuristic={s['heuristic_flags']} → {outdir}/report.md")

    worst = max((SEV_ORDER[f["severity"]] for f in shown), default=0)
    proven_n = s["proven_vulnerabilities"]
    if args.fail_on == "proven" and proven_n > 0:
        return EXIT_FINDINGS
    if args.fail_on == "high" and worst >= SEV_ORDER["HIGH"]:
        return EXIT_FINDINGS
    if args.fail_on == "critical" and worst >= SEV_ORDER["CRITICAL"]:
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # pragma: no cover
        sys.stderr.write(f"internal error: {e}\n")
        sys.exit(EXIT_ERROR)
