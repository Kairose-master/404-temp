#!/bin/sh
# TRUST404 Track04 — 컨테이너 진입점. 기본은 트랙 CLI(agent.py),
# 첫 인자가 `audit` 이면 실무 감사 CLI(audit.py) 로 라우팅한다.
if [ "$1" = "audit" ]; then
  shift
  exec python /work/agent/audit.py "$@"
fi
exec python /work/agent/agent.py "$@"
