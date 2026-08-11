# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89
FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY requirements/build.lock requirements/build.lock
RUN python -m pip install --no-cache-dir --only-binary=:all: \
        --require-hashes -r requirements/build.lock
COPY src ./src
RUN python -m build --wheel --no-isolation

FROM python:3.14-slim@sha256:cea0e6040540fb2b965b6e7fb5ffa00871e632eef63719f0ea54bca189ce14a6 AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

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
