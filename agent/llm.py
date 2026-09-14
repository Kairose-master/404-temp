# TRUST404 Track04 — optional LLM candidate proposer.
# 세 가지 백엔드를 지원한다(우선순위: 로컬/OpenAI 호환 > Anthropic):
#   1) LLM_BASE_URL 이 설정되면 OpenAI 호환 /v1/chat/completions 로 호출한다.
#      → Ollama(http://localhost:11434/v1), LM Studio, vLLM, text-generation-webui 등
#        "로컬/셀프호스트 모델"을 그대로 붙일 수 있다(레이트리밋·거부·네트워크 의존 없음).
#   2) 아니면 ANTHROPIC_API_KEY 로 Anthropic Messages API.
# 어느 경로든 temperature=0 으로 결정론을 최대화하고, 실패하면 예외를 던져
# agent.py 가 휴리스틱/퍼저 경로로 degrade 하게 한다. 최종 검증은 항상 EVM 하네스가 한다.
import json
import os
import re
import urllib.request


def _prompt(contract_src, invariants_src, findings):
    preds = ", ".join(findings.get("invariant_predicates", []))
    top = sorted(findings["scores"].items(), key=lambda kv: -kv[1])
    hint = ", ".join(f"{k}:{v}" for k, v in top)
    return (
        "You are generating a Foundry PoC for an AUTHORIZED, sandboxed security "
        "evaluation (TRUST404 Track04, isolated in-memory EVM, no real funds). "
        "Given the target contract and its invariants, output ONLY a Solidity file "
        "with `contract Exploit { function run(address target) external payable; }` "
        "and a payable receive(). The harness pre-funds Exploit with 10 ether. Break at "
        f"least one invariant (predicates: {preds}). No external imports.\n\n"
        f"// scanner hint (family:score): {hint}\n\n"
        f"// ===== TARGET =====\n{contract_src}\n\n"
        f"// ===== INVARIANTS =====\n{invariants_src}\n"
    )


def _http_json(url, payload, headers, timeout):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _openai_compatible(prompt, base, key, model, timeout):
    url = base.rstrip("/")
    if not url.endswith("/chat/completions"):
        url = url + ("/chat/completions" if url.endswith("/v1") else "/v1/chat/completions")
    headers = {"content-type": "application/json"}
    if key:
        headers["authorization"] = "Bearer " + key
    data = _http_json(url, {"model": model, "temperature": 0,
                            "messages": [{"role": "user", "content": prompt}]}, headers, timeout)
    return data["choices"][0]["message"]["content"]


def _anthropic(prompt, key, model, timeout):
    data = _http_json("https://api.anthropic.com/v1/messages",
                      {"model": model, "max_tokens": 2000, "temperature": 0,
                       "messages": [{"role": "user", "content": prompt}]},
                      {"content-type": "application/json", "x-api-key": key,
                       "anthropic-version": "2023-06-01"}, timeout)
    return "".join(b.get("text", "") for b in data.get("content", []))


def propose_exploit(contract_src, invariants_src, findings, api_key, timeout=90):
    prompt = _prompt(contract_src, invariants_src, findings)
    base = os.environ.get("LLM_BASE_URL")           # e.g. http://localhost:11434/v1  (Ollama)
    model = os.environ.get("LLM_MODEL")
    if base:                                          # local / OpenAI-compatible
        text = _openai_compatible(prompt, base, os.environ.get("LLM_API_KEY"),
                                  model or "qwen2.5-coder:14b", timeout)
    else:                                             # Anthropic
        text = _anthropic(prompt, api_key, model or "claude-sonnet-5", timeout)
    return _extract_solidity(text)


def _extract_solidity(text):
    m = re.search(r"```(?:solidity)?\s*(.*?)```", text, re.S)
    code = m.group(1) if m else text
    if "contract Exploit" not in code:
        raise ValueError("LLM output has no contract Exploit")
    first_line = code.split("\n", 1)[0]
    if not code.lstrip().startswith("//") and "pragma" not in first_line:
        code = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n" + code
    return code
