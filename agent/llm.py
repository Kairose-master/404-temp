# TRUST404 Track04 — optional LLM candidate proposer.
# ANTHROPIC_API_KEY(또는 LLM_API_KEY)가 있을 때만 호출된다. 표준 라이브러리
# urllib 만 쓰고, temperature=0 으로 결정론을 최대화한다. 실패하면 예외를 던져
# agent.py 가 휴리스틱 경로로 degrade 하게 한다. 최종 Exploit.sol 생성 책임은
# 여전히 결정론적 템플릿 엔진에 있고, LLM 은 "초안 1개"만 보조로 제안한다.
import json
import re
import urllib.request

MODEL = "claude-sonnet-5"  # 필요 시 교체 가능. temperature=0 로 고정.


def propose_exploit(contract_src, invariants_src, findings, api_key, timeout=40):
    preds = ", ".join(findings.get("invariant_predicates", []))
    top = sorted(findings["scores"].items(), key=lambda kv: -kv[1])
    hint = ", ".join(f"{k}:{v}" for k, v in top)
    prompt = (
        "You are generating a Foundry PoC for an authorized, sandboxed security "
        "evaluation. Given the target contract and its invariants, output ONLY a "
        "Solidity file defining `contract Exploit` with "
        "`function run(address target) external payable` (and a payable receive). "
        "The harness pre-funds Exploit with 10 ether. Break at least one invariant "
        f"(predicates: {preds}). Do not import external libraries.\n\n"
        f"// scanner hint (family:score): {hint}\n\n"
        f"// ===== TARGET =====\n{contract_src}\n\n"
        f"// ===== INVARIANTS =====\n{invariants_src}\n"
    )
    payload = {
        "model": MODEL,
        "max_tokens": 2000,
        "temperature": 0,
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(payload).encode(),
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read())
    text = "".join(b.get("text", "") for b in data.get("content", []))
    return _extract_solidity(text)


def _extract_solidity(text):
    m = re.search(r"```(?:solidity)?\s*(.*?)```", text, re.S)
    code = m.group(1) if m else text
    if "contract Exploit" not in code:
        raise ValueError("LLM output has no contract Exploit")
    if not code.lstrip().startswith("//") and "pragma" not in code.split("\n", 1)[0]:
        code = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n" + code
    return code
