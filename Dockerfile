# docker.io/library/python:3.11-slim, resolved 2026-08-01.
# Keep both stages on the same immutable base so a tag move cannot silently
# change the worker runtime between builds.
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93 AS builder

WORKDIR /src
COPY . /src/006AI-Firmware-Security-Agent
COPY --from=shared . /src/000shared-llm-core

RUN python -m pip wheel --no-cache-dir \
    --wheel-dir /wheels \
    /src/000shared-llm-core \
    /src/006AI-Firmware-Security-Agent


FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MPLCONFIGDIR=/tmp/matplotlib

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binwalk \
        ca-certificates \
        squashfs-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
RUN python -m pip install --no-cache-dir --no-deps /wheels/*.whl \
    && rm -rf /wheels \
    && useradd --create-home --uid 10001 firmware

USER firmware
WORKDIR /work

ENTRYPOINT ["firmware-agent"]
CMD ["--help"]
