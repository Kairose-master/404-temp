#!/bin/sh
# TRUST404 Track04 — 컨테이너 진입점. 기본은 트랙 CLI(agent.py),
# `web` 은 브라우저 콘솔, `audit` 은 실무 감사 CLI로 라우팅한다.
set -eu
if [ "${1:-}" = "web" ]; then
  shift
  exec python /work/scripts/serve.py --host 0.0.0.0 "$@"
fi
if [ "$#" -eq 0 ]; then
  printf '%s\n' 'TRUST404: docker compose up --build → http://localhost:8000' \
    'CLI: docker run --rm track04 --help' \
    'Audit: docker run --rm track04 audit --help'
  exec python /work/agent/agent.py --help
fi
if [ "$1" = "audit" ]; then
  shift
  exec python /work/agent/audit.py "$@"
fi
exec python /work/agent/agent.py "$@"
