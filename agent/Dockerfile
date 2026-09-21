# TRUST404 Track04 — Autonomous Exploit Prover
# Pins: Python 3.11.13 bookworm, representative solc releases, Foundry v1.7.1,
# and vendored forge-std.
# Build has network; the scoring sandbox does not.
FROM python:3.11.13-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    SOLCX_BINARY_PATH=/opt/solc \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/foundry/bin:${PATH}" \
    TRUST404_HARNESS_DIR=/work/harness \
    TRUST404_FORGE_STD=/work/lib/forge-std \
    TRUST404_VERIFIER=forge \
    TRUST404_ENABLE_LLM=0

WORKDIR /work

# These are the patch releases selected by api/prove.py for each Solidity minor,
# plus the public fixture compiler. Private targets can add an exact release at
# build time with --build-arg EXTRA_SOLC_VERSIONS="0.8.20 ...".
ARG EXTRA_SOLC_VERSIONS=""

# solcx's pinned Linux solc binaries are x86-64. Do not claim ARM support
# just because a Foundry ARM tarball exists. ARM hosts can build/run amd64.
RUN test "$(dpkg --print-architecture)" = amd64 \
    || (echo 'Use docker build --platform linux/amd64 for this image.' >&2; exit 1)

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install directly into the one runtime path; no foundryup/home-directory mismatch.
# Separate download and extraction so a failed download cannot be hidden by a pipe.
RUN mkdir -p /opt/foundry/bin \
    && curl -fsSL --retry 3 \
       https://github.com/foundry-rs/foundry/releases/download/v1.7.1/foundry_v1.7.1_linux_amd64.tar.gz \
       -o /tmp/foundry.tar.gz \
    && tar -xzf /tmp/foundry.tar.gz --no-same-owner -C /opt/foundry/bin \
    && rm /tmp/foundry.tar.gz \
    && chmod +x /opt/foundry/bin/forge /opt/foundry/bin/cast \
    && forge --version

COPY agent/requirements.txt agent/install_solc_versions.py /work/agent/
# solcx does not create a custom SOLCX_BINARY_PATH directory.
RUN mkdir -p "$SOLCX_BINARY_PATH" \
    && pip install -r /work/agent/requirements.txt

# Keep compiler releases in separate layers: a transient failure for one
# download does not invalidate the releases that already succeeded.
RUN python /work/agent/install_solc_versions.py 0.4.26
RUN python /work/agent/install_solc_versions.py 0.5.17
RUN python /work/agent/install_solc_versions.py 0.6.12
RUN python /work/agent/install_solc_versions.py 0.7.6
RUN python /work/agent/install_solc_versions.py 0.8.24
RUN python /work/agent/install_solc_versions.py 0.8.28
RUN python /work/agent/install_solc_versions.py $EXTRA_SOLC_VERSIONS

RUN for version in 0.4.26 0.5.17 0.6.12 0.7.6 0.8.24 0.8.28 $EXTRA_SOLC_VERSIONS; do \
         "/opt/solc/solc-v${version}" --version >/dev/null || exit 1; \
       done

COPY agent /work/agent
COPY harness /work/harness
COPY api /work/api
COPY trust404 /work/trust404
COPY lib /work/lib
COPY targets /work/targets

RUN chmod +x /work/agent/docker-entry.sh \
    && python -m compileall -q /work/agent /work/api /work/trust404

# Both backends use /opt/solc via solcx. verify.py passes the exact local
# executable to Forge with --use; an empty ~/.svm cache needs no download.
# The submitted container defaults to the official Foundry verifier and keeps
# remote LLM generation disabled for deterministic, network-free scoring.
ENTRYPOINT ["/work/agent/docker-entry.sh"]
