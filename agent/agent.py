#!/usr/bin/env python3
# TRUST404 Track 04 — Autonomous Exploit Prover
# ============================================================================
# 자기검증 루프(Self-validation Loop)가 핵심이다. 타깃/불변식/매니페스트를 읽어
#   탐색 → 생성 → 검증 → (불변식 미위반 시) 더 강한 방법으로 탐색·생성 반복
# 을 --max-attempts / --timeout 예산 안에서 돈다. 후보 생성은 단계별로 격상한다:
#   0) llm(선택) → 1) 계열 템플릿 → 2) 합성(synth) → 3) 범용 퍼저(fuzz)
# 각 후보는 하네스 _prove() 를 재현한 검증기(verify.py)로 실제 불변식 위반을 확인하고,
# 실패하면 다음 후보/단계로 격상해 반복한다. template→synth→fuzz 후보는 실무 감사
# 엔진(api/prove.py)의 iter_engine_candidates 로부터 지연 생성된다.
#
# 검증기는 두 경로를 가진다:
#   - forge 가 있으면 참가 번들의 harness/src/Harness.sol 을 재사용해 forge test 로 검증
#   - 없으면 내장 EVM(solc 0.8.24 + eth-tester/py-evm)으로 동일한 _prove 절차를 재현
# 두 경로 모두 오프라인에서 동작한다(네트워크 차단 샌드박스 전제).
#
# LLM: ANTHROPIC_API_KEY(또는 LLM_API_KEY)가 있으면 1차 후보로 LLM 초안을
# 요청하고, 없거나 실패하면 내장 휴리스틱 템플릿으로 degrade 한다(키 없이도 동작).
#
# 표준 CLI:
#   agent.py --contract <path> --invariants <path> --manifest <path> --out <dir>
#            --timeout <sec> --seed <int> --max-attempts <int>
# 종료코드: 0 발견 · 1 예산 내 미발견 · 2 사용법/내부 오류
# 산출물(--out): Exploit.sol(증명된/최선 후보), attempts.log(단계 격상·시도별 전략·검증
#   결과·유지된 불변식), result.json(증명 여부·위반 불변식·어떻게 위반했는지 설명·시도 수)
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from scanner import scan_target
from strategies import STRATEGY_ORDER, build_exploit, seeded_order
from verify import verify_candidate, verify_full, VerifyUnavailable

try:
    from pathlib import Path as _P
    import sys as _s
    _r = _P(__file__).resolve().parent.parent
    if str(_r) not in _s.path:
        _s.path.insert(0, str(_r))
    from trust404.critique import Critique, format_for_llm
    from trust404.features import extract_features
    from trust404.hkg import lift as hkg_lift
    from trust404.world import plan_world
except Exception:  # package optional at import time
    Critique = None
    format_for_llm = None
    extract_features = None
    hkg_lift = None
    plan_world = None


def _load_engine():
    """api/prove.py 엔진을 경로로 로드(합성·퍼저 후보 생성기 iter_engine_candidates 용).
    설치본/서브모듈 유무와 무관하게 동작하며, 없으면 None 으로 degrade 한다."""
    import importlib.util
    here = Path(__file__).resolve().parent
    for p in (here.parent / "api" / "prove.py", here / "prove.py", Path("api/prove.py")):
        try:
            if p.exists():
                spec = importlib.util.spec_from_file_location("t404engine", p)
                m = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(m)
                return m
        except Exception:
            continue
    return None

EXIT_FOUND = 0
EXIT_NOT_FOUND = 1
EXIT_ERROR = 2


def parse_args(argv):
    p = argparse.ArgumentParser(prog="agent", description="TRUST404 Track04 autonomous exploit prover")
    p.add_argument("--contract", required=True)
    p.add_argument("--invariants", required=True)
    p.add_argument("--manifest", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--max-attempts", type=int, default=24, dest="max_attempts",
                   help="자기검증 루프 예산(후보 수). 템플릿→합성→퍼저 단계를 모두 소비할 수 있게 넉넉히.")
    return p.parse_args(argv)


def die(msg, out_dir=None, log=None):
    sys.stderr.write(f"error: {msg}\n")
    if out_dir is not None and log is not None:
        write_log(out_dir, log)
    sys.exit(EXIT_ERROR)


def write_log(out_dir, lines):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / "attempts.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_exploit(out_dir, source):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / "Exploit.sol").write_text(source, encoding="utf-8")


def load_manifest(path):
    raw = Path(path).read_text(encoding="utf-8")
    m = json.loads(raw)
    if m.get("schema") != "trust404.track04.manifest/0.1":
        raise ValueError(f"unsupported manifest schema: {m.get('schema')!r}")
    return m, raw


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    args = parse_args(argv)
    out_dir = args.out
    started = time.time()
    log = []

    def note(line):
        log.append(line)

    # ── 입력 로드 ────────────────────────────────────────────────────────────
    try:
        contract_src = Path(args.contract).read_text(encoding="utf-8")
        invariants_src = Path(args.invariants).read_text(encoding="utf-8")
        manifest, manifest_raw = load_manifest(args.manifest)
    except Exception as e:
        die(f"failed to load inputs: {e}", out_dir, [f"# fatal: {e}"])

    target_name = manifest["target"]["name"]
    extra_sources = {}
    try:
        from trust404.abi import load_extra_sources
        extra_sources = load_extra_sources(args.manifest, args.contract, manifest)
        if extra_sources:
            note("# extra sources: " + ",".join(sorted(extra_sources)))
    except Exception as e:
        note(f"# extra sources skipped: {str(e)[:80]}")
    note(f"# TRUST404 Track04 agent | target={target_name} seed={args.seed} "
         f"max_attempts={args.max_attempts} timeout={args.timeout}s")

    # ── 정적 분석 → 후보 유형 스코어링 ────────────────────────────────────────
    findings = scan_target(contract_src, invariants_src, manifest)
    scored = sorted(
        STRATEGY_ORDER,
        key=lambda fam: (-findings["scores"].get(fam, 0), fam),
    )
    scored = seeded_order(scored, findings["scores"], args.seed)
    note(f"# scan scores: " + ", ".join(f"{k}={findings['scores'].get(k,0)}" for k in STRATEGY_ORDER))
    note(f"# strategy order: {scored}")
    feats = set()
    if extract_features is not None:
        try:
            blob = contract_src
            if extra_sources:
                blob = contract_src + "\n" + "\n".join(extra_sources.values())
            feats = extract_features(blob, target_name)
            note("# features: " + ",".join(sorted(feats)[:40]))
            if hkg_lift is not None:
                hkg = hkg_lift(feats)
                note("# hkg protocols: " + ",".join(hkg.protocols[:8]))
                note("# hkg causes: " + ",".join(hkg.causes[:8]))
                note("# hkg ranked: " + ",".join(hkg.ranked_primitives[:8]))
            if plan_world is not None:
                wp = plan_world(contract_src, target_name, feats)
                note(f"# world cross={wp.cross_contract} reason={wp.reason[:160]}")
        except Exception as e:
            note(f"# feature extract failed: {str(e)[:80]}")

    # ── 후보 생성기(단계별·지연) 구성 ─────────────────────────────────────────
    # 자기검증 루프의 '탐색·생성' 축. 각 단계는 앞 단계가 검증에 실패했을 때에만
    # 소비되므로, PoC 가 불변식을 위반하지 못하면 더 강한 방법으로 탐색·생성을 반복한다.
    #   0) llm      — (선택) 로컬/원격 LLM 초안
    #   1) template — 계열별 결정론 템플릿(정적 스코어 순)
    #   2) synth    — 재진입/AMM/플래시론/스토리지/프록시/다중블록/스토리지충돌/DoS/콜백 합성
    #   3) fuzz     — 범용 호출 시퀀스 탐색(미공개 타깃 일반화 축)
    def candidate_stream():
        # 0) LLM (로컬 LLM_BASE_URL 또는 API 키가 있을 때만)
        llm_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("LLM_API_KEY")
        llm_base = os.environ.get("LLM_BASE_URL")
        if llm_key or llm_base:
            try:
                from llm import propose_exploit  # optional
                draft = propose_exploit(contract_src, invariants_src, findings, llm_key)
                if draft:
                    note(f"# LLM draft obtained ({'local:'+llm_base if llm_base else 'anthropic'})")
                    yield ("llm", "llm", draft)
            except Exception as e:  # network blocked / parse fail → degrade
                note(f"# LLM unavailable, degrading to heuristics: {str(e)[:120]}")
        else:
            note("# no LLM configured; offline heuristic/synthesis/fuzz mode")
        # 1~3) 엔진(api/prove.py)의 단계별 생성기 — 없으면 로컬 템플릿으로 degrade
        engine = _load_engine()
        if engine is not None and hasattr(engine, "iter_engine_candidates"):
            note("# engine loaded: template → synth → fuzz stages")
            try:
                for stage, label, src in engine.iter_engine_candidates(
                        target_name, contract_src, invariants_src, manifest, do_verify=True):
                    yield (stage, label, src)
            except Exception as e:
                note(f"# engine candidate stream error: {str(e)[:140]}")
        else:
            note("# engine unavailable; local template stage only")
            for fam in scored:
                src = build_exploit(fam, findings)
                if src:
                    yield ("template", fam, src)

    # ── 자기검증 루프 (Self-validation Loop) ──────────────────────────────────
    # 생성 → 검증 → (불변식 미위반 시) 다음 후보로 탐색·생성 반복. 이 루프가 트랙의 핵심.
    last_source = _fallback_stub()
    attempts = 0
    verifier_ok = True
    stages_seen = []
    held_invariants = {}  # 실패한 시도에서 '유지된' 불변식 관찰(피드백)
    critiques = []
    critique_llm_done = False
    for stage, label, source in candidate_stream():
        if attempts >= args.max_attempts:
            note(f"# budget exhausted after {attempts} attempts (max={args.max_attempts})")
            break
        if time.time() - started > args.timeout:
            note(f"# timeout after {attempts} attempts ({int(time.time()-started)}s)")
            break
        if stage not in stages_seen:
            stages_seen.append(stage)
            note(f"# --- stage escalation: {stage} ---")
        attempts += 1
        last_source = source
        # ① 검증(불변식 위반 여부) — 참가 하네스 _prove() 재현
        try:
            result = verify_full(
                target_name=target_name,
                target_src=contract_src,
                invariants_src=invariants_src,
                exploit_src=source,
                manifest=manifest,
                seed=args.seed,
                extra_sources=extra_sources or None,
            )
            proven, first_violated, detail = result.tuple()
        except VerifyUnavailable as e:
            verifier_ok = False
            note(f"attempt {attempts} [{stage}/{label}]: verifier unavailable ({e}); emitting best candidate")
            break
        except Exception as e:
            note(f"attempt {attempts} [{stage}/{label}]: verify error → refine ({str(e)[:140]})")
            continue

        intent_cls = None
        try:
            from trust404.intent import decide, is_success
            pcls = getattr(getattr(result, "profit", None), "classification", None)
            intent_cls = decide(feats, source, proven, pcls)
            if proven and not is_success(intent_cls):
                note(f"attempt {attempts} [{stage}/{label}]: INTENDED_PATH — "
                     f"value moved but not theft (invariants held or swap-only); skip")
                proven = False
                detail = (detail or "") + " intent=intended_path"
        except Exception:
            intent_cls = None

        if proven:
            note(f"attempt {attempts} [{stage}/{label}]: PROVEN — invariant violated: {first_violated}")
            if getattr(result, "profit", None) is not None:
                note(f"# profit {result.profit.classification} extractable_wei={result.profit.extractable_wei}")
            write_exploit(out_dir, source)
            payload = {
                "proven": True, "target": target_name, "stage": stage, "strategy": label,
                "invariant_violated": first_violated,
                "how": _explain(label, first_violated),
                "attempts": attempts, "stages": stages_seen,
                "seed": args.seed, "elapsed_s": round(time.time() - started, 2),
            }
            if getattr(result, "profit", None) is not None:
                payload["profit"] = result.profit.as_dict()
            if intent_cls:
                payload["classification"] = intent_cls
            _write_result(out_dir, payload)
            write_log(out_dir, log)
            print(f"PROVEN target={target_name} strategy={label} violated={first_violated}")
            return EXIT_FOUND
        # ② 실패 → 피드백 기록(어느 불변식이 유지됐는지) 후 다음 후보/단계로 반복
        held_invariants[label] = detail
        note(f"attempt {attempts} [{stage}/{label}]: NOT PROVEN — invariants held ({detail}); "
             f"→ escalate search/generation")
        if Critique is not None:
            critiques.append(Critique(
                stage=stage, label=label, held=str(detail)[:400],
                source_head=(source or "")[:400],
                features=sorted(feats)[:24],
            ))
        # PoCo/A1: 실패를 LLM 재시도의 탐색 신호로 (키가 있을 때만, 1회)
        if (not critique_llm_done and format_for_llm is not None and critiques
                and (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("LLM_API_KEY")
                     or os.environ.get("LLM_BASE_URL"))):
            critique_llm_done = True
            try:
                from llm import propose_exploit
                ctext = format_for_llm(
                    critiques, findings.get("invariant_predicates") or [])
                draft = propose_exploit(
                    contract_src, invariants_src, findings,
                    os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("LLM_API_KEY"),
                    critique_text=ctext)
                if draft:
                    note("# critique-conditioned LLM retry queued")
                    # inject by running immediately as extra attempt
                    if attempts < args.max_attempts:
                        attempts += 1
                        last_source = draft
                        proven2, fv2, d2 = verify_candidate(
                            target_name=target_name, target_src=contract_src,
                            invariants_src=invariants_src, exploit_src=draft,
                            manifest=manifest, seed=args.seed,
                            extra_sources=extra_sources or None)
                        if proven2:
                            note(f"attempt {attempts} [llm/critique]: PROVEN — {fv2}")
                            write_exploit(out_dir, draft)
                            _write_result(out_dir, {
                                "proven": True, "target": target_name, "stage": "llm",
                                "strategy": "llm-critique", "invariant_violated": fv2,
                                "how": _explain("llm-critique", fv2),
                                "attempts": attempts, "stages": stages_seen + ["llm"],
                                "seed": args.seed,
                                "elapsed_s": round(time.time() - started, 2),
                                "critiques": [c.as_dict() for c in critiques],
                            })
                            write_log(out_dir, log)
                            print(f"PROVEN target={target_name} strategy=llm-critique violated={fv2}")
                            return EXIT_FOUND
                        held_invariants["llm-critique"] = d2
                        note(f"attempt {attempts} [llm/critique]: NOT PROVEN ({d2})")
            except Exception as e:
                note(f"# critique LLM retry skipped: {str(e)[:120]}")

    # ── 예산 내 미발견 ────────────────────────────────────────────────────────
    write_exploit(out_dir, last_source)
    _write_result(out_dir, {
        "proven": False, "target": target_name,
        "attempts": attempts, "stages": stages_seen,
        "verifier_available": verifier_ok,
        "feedback": held_invariants,
        "critiques": [c.as_dict() for c in critiques] if critiques else [],
        "features": sorted(feats),
        "seed": args.seed, "elapsed_s": round(time.time() - started, 2),
    })
    write_log(out_dir, log)
    if not verifier_ok:
        print(f"INCONCLUSIVE target={target_name} (verifier unavailable)")
        return EXIT_ERROR
    print(f"NOT_PROVEN target={target_name} within budget")
    return EXIT_NOT_FOUND


def _write_result(out_dir, obj):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / "result.json").write_text(
        json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def _explain(label, first_violated):
    """어느 불변식을 '어떻게' 위반했는지에 대한 사람용 설명(출력 규약)."""
    base = (label or "").split(":")[0].split(" ")[0]
    how = {
        "reentrancy": "외부 호출 뒤 상태 갱신(CEI 위반)을 재진입으로 악용해",
        "reentrancy-fuzz": "예치→인출 재진입을 합성해",
        "access_control": "접근 제어가 없는 특권 함수를 직접 호출해",
        "integer_underflow": "정수 언더플로로 잔액/회계를 조작해",
        "oracle_manipulation": "단일 블록 spot price 를 조작해",
        "amm-manip": "얇은 AMM 풀의 즉시 준비금을 조작(플래시론식)해",
        "flashloan": "시스템 내부 플래시론으로 순간 잔액 게이트를 통과해",
        "delegatecall_hijack": "delegatecall 로 특권 슬롯을 덮어써",
        "proxy": "fallback→delegatecall 배선으로 특권 슬롯을 덮어써",
        "storage-collision": "delegatecall 스토리지 충돌(2단계)로 라이브러리 포인터를 덮어써",
        "unprotected_init": "미보호 initializer 를 먼저 호출해 특권을 선점해",
        "weak_randomness": "예측 가능한 블록 엔트로피를 복제해",
        "multiblock": "블록을 넘기며 예측 결과로 반복 호출해",
        "storage": "private 슬롯 값을 스토리지에서 읽어",
        "king-dos": "revert 하는 receive 로 특권 역할을 영구 락(그리핑 DoS)해",
        "callback-inconsistency": "외부 콜백을 false→true 로 조작해",
    }.get(base, "생성된 PoC 실행으로")
    return f"{how} 불변식 '{first_violated}' 을(를) 위반함."


def _fallback_stub():
    return (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n\n"
        "// No known-pattern candidate matched this target.\n"
        "contract Exploit {\n"
        "    function run(address) external payable {}\n"
        "    receive() external payable {}\n"
        "}\n"
    )


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:  # pragma: no cover
        sys.stderr.write(f"internal error: {e}\n")
        sys.exit(EXIT_ERROR)
