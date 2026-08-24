FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
    clang \
    libc6-dev \
    libclang-rt-dev \
    && rm -rf /var/lib/apt/lists/*

COPY api/requirements.txt /tmp/requirements.txt

RUN python -m pip install \
    --no-cache-dir \
    --requirement /tmp/requirements.txt

RUN groupadd --system --gid 10001 kavach \
    && useradd \
        --system \
        --uid 10001 \
        --gid 10001 \
        --no-create-home \
        --shell /usr/sbin/nologin \
        appuser

COPY --chown=10001:10001 api /app/api
COPY --chown=10001:10001 harness /app/harness
COPY --chown=10001:10001 patch_candidates /app/patch_candidates
COPY --chown=10001:10001 semgrep_rules /app/semgrep_rules
COPY --chown=10001:10001 website /app/website
COPY --chown=10001:10001 approvals /app/approvals

RUN mkdir -p /app/build /app/reports \
    && chown -R 10001:10001 /app/build /app/reports

USER 10001:10001

EXPOSE 8000

HEALTHCHECK \
    --interval=30s \
    --timeout=5s \
    --start-period=10s \
    --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"

    CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]