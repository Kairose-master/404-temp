#!/bin/bash
# TRUST404 Track04 — SessionStart hook.
# Claude Code on the web 세션에서 `forge test` 로 익스플로잇을 실제로 돌릴 수
# 있도록 Foundry(forge) 와 에이전트용 파이썬 의존성을 준비한다.
# forge-std 는 저장소에 벤더링돼 있어(lib/forge-std) 별도 다운로드가 필요 없다.
set -uo pipefail

# 원격(웹) 세션에서만 실행. 로컬은 각자 환경을 쓰게 둔다.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

echo "[trust404] session-start: preparing Foundry + agent deps"

# 1) Foundry (forge). 이미 있으면 건너뜀(컨테이너 캐시 활용, 멱등).
if command -v forge >/dev/null 2>&1; then
  echo "[trust404] forge already present: $(forge --version 2>/dev/null | head -1)"
else
  echo "[trust404] installing foundry via foundryup ..."
  if curl -fsSL https://foundry.paradigm.xyz | bash; then
    export PATH="$HOME/.foundry/bin:$PATH"
    if foundryup; then
      echo "[trust404] foundry installed: $(forge --version 2>/dev/null | head -1)"
    else
      echo "[trust404] WARN: foundryup failed (network policy may block the download host)."
    fi
  else
    echo "[trust404] WARN: could not fetch foundryup installer (network policy may block github/foundry hosts)."
    echo "[trust404]       Enable an egress policy that allows github.com to install Foundry,"
    echo "[trust404]       or run the agent's built-in EVM verifier instead (no forge needed)."
  fi
fi

# forge 를 PATH 에 영구 등록(설치됐을 경우).
if [ -d "$HOME/.foundry/bin" ]; then
  echo "export PATH=\"$HOME/.foundry/bin:\$PATH\"" >> "$CLAUDE_ENV_FILE"
fi

# 2) 에이전트의 내장 EVM 검증기용 파이썬 의존성 + solc 0.8.24 (forge 없이도 동작).
if [ -f agent/requirements.txt ]; then
  echo "[trust404] installing python deps for the agent ..."
  pip install -q -r agent/requirements.txt || echo "[trust404] WARN: pip install failed"
  python3 -c "import solcx; solcx.install_solc('0.8.24')" 2>/dev/null \
    && echo "[trust404] solc 0.8.24 ready" || echo "[trust404] WARN: solc install failed"
fi

echo "[trust404] session-start done. Run:  forge test -vv   (or: python3 agent/agent.py ...)"
exit 0
