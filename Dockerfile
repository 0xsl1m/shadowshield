# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY requirements/build.lock requirements/build.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: \
        --require-hashes -r requirements/build.lock
COPY src ./src
RUN python -m build --wheel --no-isolation

FROM python:3.14-slim@sha256:ce40764625a4ff50df3548277632e7f96c4e77fe75fa848aae9885476e7df5a4 AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Apply OS security updates at build time: the digest-pinned base image lags
# Debian security point releases, and the CI Trivy gate rejects fixable
# HIGH/CRITICAL CVEs. Everything else in this image stays lockfile-pinned.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN addgroup --system shadowshield \
    && adduser --system --ingroup shadowshield --home /nonexistent shadowshield \
    && mkdir -p /var/lib/shadowshield \
    && chown shadowshield:shadowshield /var/lib/shadowshield
COPY requirements/container.lock /tmp/container.lock
COPY --from=builder /build/dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir --only-binary=:all: \
        --require-hashes -r /tmp/container.lock \
    && python -m pip install --no-cache-dir --no-deps /tmp/*.whl \
    && python -m pip check \
    && rm -f /tmp/*.whl /tmp/container.lock

USER shadowshield
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2)"]

CMD ["shadowshield", "serve", "--control", "--host", "0.0.0.0", "--port", "8000"]
