# TRUST404 Track04 — Autonomous Exploit Prover
# Pins: Python 3.11 bookworm, solc 0.8.24, Foundry 1.7.1, vendored forge-std.
# Build has network; the scoring sandbox does not.
FROM python:3.11.13-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    SOLCX_BINARY_PATH=/opt/solc \
    PIP_NO_CACHE_DIR=1 \
    FOUNDRY_DIR=/opt/foundry \
    PATH="/opt/foundry/bin:${PATH}" \
    TRUST404_HARNESS_DIR=/work/harness \
    TRUST404_FORGE_STD=/work/lib/forge-std

WORKDIR /work

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Foundry 1.7.1 — same minor the track bundle names.
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup --install 1.7.1 \
    && mkdir -p /opt/foundry/bin \
    && cp /root/.foundry/bin/forge /root/.foundry/bin/cast /opt/foundry/bin/ \
    && forge --version

COPY agent/requirements.txt /work/agent/requirements.txt
RUN pip install -r /work/agent/requirements.txt \
    && python -c "import solcx; solcx.install_solc('0.8.24')"

COPY agent /work/agent
COPY harness /work/harness
COPY api /work/api
COPY trust404 /work/trust404
COPY lib /work/lib
COPY targets /work/targets

RUN python -m compileall -q /work/agent /work/api /work/trust404

# Default CLI is still py-evm (offline, no forge needed at the call site).
# Forge path: TRUST404_VERIFIER=forge
ENTRYPOINT ["/work/agent/docker-entry.sh"]
