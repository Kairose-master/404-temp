#!/usr/bin/env python3
# TRUST404 Track 04 — Autonomous Exploit Prover
# ============================================================================
# 타깃 컨트랙트가 주어지면 (1) 정적 분석으로 취약 유형 후보를 스코어링하고
# (2) 유형별 템플릿으로 Exploit.sol 을 결정론적으로 생성한 뒤 (3) 하네스
# _prove() 파이프라인을 재현한 검증기로 실제 불변식이 깨지는지 확인하는
# 생성-검증(generate & verify) 루프를 --max-attempts / --timeout 예산 안에서 돈다.
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
# 산출물(--out): Exploit.sol(최선 후보), attempts.log(시도별 번호·전략·결과·깨진 술어)
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from scanner import scan_target
from strategies import STRATEGY_ORDER, build_exploit, seeded_order
from verify import verify_candidate, VerifyUnavailable

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
    p.add_argument("--max-attempts", type=int, default=5, dest="max_attempts")
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

    # ── LLM 1차 후보(선택) ────────────────────────────────────────────────────
    llm_key = os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("LLM_API_KEY")
    candidates = []  # list of (strategy_label, exploit_source)
    if llm_key:
        try:
            from llm import propose_exploit  # optional
            draft = propose_exploit(contract_src, invariants_src, findings, llm_key)
            if draft:
                candidates.append(("llm", draft))
                note("# LLM draft obtained (temperature=0)")
        except Exception as e:  # network blocked / parse fail → degrade
            note(f"# LLM unavailable, degrading to heuristics: {str(e)[:120]}")
    else:
        note("# no LLM key; offline heuristic mode")

    # ── 휴리스틱 후보(전략 우선순위 순) ───────────────────────────────────────
    for fam in scored:
        src = build_exploit(fam, findings)
        if src:
            candidates.append((fam, src))

    if not candidates:
        note("# no candidate strategy matched the target")
        write_exploit(out_dir, _fallback_stub())
        write_log(out_dir, log)
        return EXIT_NOT_FOUND

    # ── 생성-검증 루프 ────────────────────────────────────────────────────────
    last_source = candidates[0][1]
    attempts = 0
    verifier_ok = True
    for label, source in candidates:
        if attempts >= args.max_attempts:
            note(f"# budget exhausted after {attempts} attempts (max={args.max_attempts})")
            break
        if time.time() - started > args.timeout:
            note(f"# timeout after {attempts} attempts ({int(time.time()-started)}s)")
            break
        attempts += 1
        last_source = source
        try:
            proven, first_violated, detail = verify_candidate(
                target_name=target_name,
                target_src=contract_src,
                invariants_src=invariants_src,
                exploit_src=source,
                manifest=manifest,
                seed=args.seed,
            )
        except VerifyUnavailable as e:
            verifier_ok = False
            note(f"attempt {attempts} [{label}]: verifier unavailable ({e}); emitting best candidate")
            break
        except Exception as e:
            note(f"attempt {attempts} [{label}]: verify error: {str(e)[:160]}")
            continue

        if proven:
            note(f"attempt {attempts} [{label}]: PROVEN — invariant violated: {first_violated}")
            write_exploit(out_dir, source)
            write_log(out_dir, log)
            print(f"PROVEN target={target_name} strategy={label} violated={first_violated}")
            return EXIT_FOUND
        else:
            note(f"attempt {attempts} [{label}]: NOT PROVEN — invariants held ({detail})")

    # ── 미발견 ────────────────────────────────────────────────────────────────
    write_exploit(out_dir, last_source)
    write_log(out_dir, log)
    if not verifier_ok:
        # 검증기를 못 돌린 경우에도 후보는 남기되, 증명은 하지 못했으므로 1로 종료
        print(f"UNVERIFIED target={target_name} (verifier unavailable) — best candidate written")
    else:
        print(f"NOT_PROVEN target={target_name} within budget")
    return EXIT_NOT_FOUND


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
