FROM python:3.11-slim AS builder

WORKDIR /src
COPY . /src/006AI-Firmware-Security-Agent
COPY --from=shared . /src/000shared-llm-core

RUN python -m pip wheel --no-cache-dir \
    --wheel-dir /wheels \
    /src/000shared-llm-core \
    /src/006AI-Firmware-Security-Agent


FROM python:3.11-slim AS runtime

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
