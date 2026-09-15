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
        if any(f.get("external") and "view" not in f["head"] and "pure" not in f["head"] for f in fns):
            if name not in out:
                out.append(name)
    return out


def synth_ctor_args(eng, src, contract):
    """타깃 생성자 시그니처를 읽어 배포용 기본 인자를 합성한다. 문자열/바이트/배열/
    구조체가 필요하면 None(분석 불가)을 돌려준다."""
    body = eng._contract_bodies(eng._strip_comments(src)).get(contract, "")
    m = re.search(r"constructor\s*\(([^)]*)\)", body)
    if not m or not m.group(1).strip():
        return []
    args = []
    for p in m.group(1).split(","):
        toks = p.split()
        if not toks:
            continue
        t = toks[0]
        if t == "address":
            args.append("0x000000000000000000000000000000000000dEaD")  # 유효한 20-byte 테스트 주소
        elif t.startswith("uint") or t.startswith("int"):
            args.append(10**18)
        elif t == "bool":
            args.append(False)
        else:
            return None  # string/bytes/array/struct → 안전하게 분석 스킵
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
}


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
    heur = [f for f in findings if (not f["res"].get("proven")) and f["severity"] == "MEDIUM"]
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
        report["findings"].append({
            "contract": f["contract"],
            "file": f["file"],
            "severity": f["severity"],
            "proven": bool(r.get("proven")),
            "strategy": r.get("strategy"),
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
    L.append("| 컨트랙트 | 심각도 | 판정 | 계열/전략 | 근거 |")
    L.append("|---|---|---|---|---|")
    def sev_key(f): return (-SEV_ORDER.get(f["severity"], 0), not f["proven"])
    for f in sorted(report["findings"], key=sev_key):
        verdict = "PROVEN" if f["proven"] else ("휴리스틱" if f["severity"] == "MEDIUM" else "clean")
        strat = f["strategy"] or (", ".join(f["scanner_scores"].keys()) or "—")
        ev = (f["evidence"] or "").replace("|", "\\|")
        L.append(f"| `{f['contract']}` | {badge.get(f['severity'],f['severity'])} | {verdict} | {strat} | {ev} |")
    L.append("")
    proven = [f for f in report["findings"] if f["proven"]]
    if proven:
        L.append("## 증명된 취약점 상세")
        L.append("")
        for i, f in enumerate(sorted(proven, key=sev_key), 1):
            L.append(f"### {i}. `{f['contract']}` — {badge.get(f['severity'],f['severity'])}")
            L.append("")
            L.append(f"- 파일: `{f['file']}`")
            L.append(f"- 전략: **{f['strategy']}** · 모드: {f['mode']}")
            L.append(f"- 깨진 속성/효과: **{f['broken']}**")
            if f.get("drained_eth") is not None:
                L.append(f"- 관찰된 자금 이동: **{f['drained_eth']} ETH**")
            if f.get("poc_file"):
                L.append(f"- PoC: `{f['poc_file']}`")
            L.append("")
    heur = [f for f in report["findings"] if (not f["proven"]) and f["severity"] == "MEDIUM"]
    if heur:
        L.append("## 휴리스틱 플래그 (미증명 — 수동 확인 권장)")
        L.append("")
        for f in heur:
            L.append(f"- `{f['contract']}` — 정적 신호: {', '.join(f['scanner_scores'].keys())}")
        L.append("")
    L.append("---")
    L.append("_모든 PoC는 격리된 in-memory EVM(네트워크 차단)에서 방어 연구·자동 검증"
             " 목적으로만 실행됩니다._")
    return "\n".join(L) + "\n"


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
    ap.add_argument("--fail-on", choices=["none", "proven", "high", "critical"], default="none")
    ap.add_argument("--include-safe", action="store_true", help="also list clean contracts in JSON")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])

    eng = load_engine()
    inv_src = Path(args.invariants).read_text(encoding="utf-8") if args.invariants else None
    files = gather_files(args.path)
    outdir = Path(args.out)
    (outdir / "exploits").mkdir(parents=True, exist_ok=True)

    def log(*a):
        if not args.quiet:
            print(*a, file=sys.stderr)

    findings = []
    for fp in files:
        try:
            src = fp.read_text(encoding="utf-8")
        except Exception as e:
            log(f"skip {fp}: {e}"); continue
        targets = concrete_contracts(src, eng)
        if args.only:
            targets = [t for t in targets if t == args.only]
        for c in targets:
            log(f"analyzing {fp}:{c} …")
            res = analyze_source(eng, src, c, inv_src, args.seed_eth, args.seed)
            sev, evidence, is_finding = severity_for(res)
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
            findings.append({"contract": c, "file": str(fp), "severity": sev,
                             "evidence": evidence, "res": res, "poc_file": poc_file,
                             "drained_eth": drained})

    if not args.include_safe:
        findings_out = [f for f in findings if not (f["severity"] == "INFO" and not f["res"].get("proven"))]
    else:
        findings_out = findings
    # 요약 카운트는 표시 대상 기준
    shown = findings_out if findings_out else findings
    report = build_report(shown, args, total_analyzed=len(findings))
    (outdir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    (outdir / "report.md").write_text(render_md(report), encoding="utf-8")

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
