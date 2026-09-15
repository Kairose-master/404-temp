# TRUST404 Track04 — Autonomous Exploit Prover
# 결정론 채점을 위해 solc 0.8.24 를 이미지에 미리 설치(오프라인 검증). forge 는
# 선택적 경로이며 기본 검증기는 내장 EVM(eth-tester/py-evm)이라 네트워크 없이 동작.
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    SOLCX_BINARY_PATH=/opt/solc \
    PIP_NO_CACHE_DIR=1

WORKDIR /work

COPY agent/requirements.txt /work/agent/requirements.txt
RUN pip install -r /work/agent/requirements.txt

# solc 0.8.24 를 빌드 시점에 받아 이미지에 고정(채점 샌드박스는 네트워크 차단).
RUN python -c "import solcx; solcx.install_solc('0.8.24')"

COPY agent /work/agent
COPY harness /work/harness
COPY api /work/api

ENV TRUST404_HARNESS_DIR=/work/harness

# 기본: 트랙 CLI(agent.py). `audit <경로>` 서브커맨드로 실무 감사 CLI 실행.
#   docker run --rm -v "$PWD:/scan" IMAGE audit /scan --out /scan/audit
ENTRYPOINT ["/work/agent/docker-entry.sh"]
