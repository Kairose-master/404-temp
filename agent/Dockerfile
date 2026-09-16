# TRUST404 Track04 — Autonomous Exploit Prover
# Pins: Python 3.11.13 bookworm, solc 0.8.24, Foundry v1.7.1 binaries, vendored forge-std.
# Build has network; the scoring sandbox does not.
FROM python:3.11.13-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    SOLCX_BINARY_PATH=/opt/solc \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/foundry/bin:${PATH}" \
    TRUST404_HARNESS_DIR=/work/harness \
    TRUST404_FORGE_STD=/work/lib/forge-std

WORKDIR /work

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Official v1.7.1 tarball — foundryup + FOUNDRY_DIR would install into a
# different path than we copied from, and `--install 1.7.1` (no v) is rejected.
ARG TARGETARCH=amd64
RUN mkdir -p /opt/foundry/bin \
    && arch="$TARGETARCH" \
    && if [ "$arch" = "arm64" ] || [ "$arch" = "aarch64" ]; then arch=arm64; else arch=amd64; fi \
    && curl -fsSL "https://github.com/foundry-rs/foundry/releases/download/v1.7.1/foundry_v1.7.1_linux_${arch}.tar.gz" \
       | tar -xz --no-same-owner -C /opt/foundry/bin \
    && chmod +x /opt/foundry/bin/forge /opt/foundry/bin/cast \
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

RUN chmod +x /work/agent/docker-entry.sh \
    && python -m compileall -q /work/agent /work/api /work/trust404

# Default CLI is still py-evm. Forge path: TRUST404_VERIFIER=forge
ENTRYPOINT ["/work/agent/docker-entry.sh"]
