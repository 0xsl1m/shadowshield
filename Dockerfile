# syntax=docker/dockerfile:1
FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS builder

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir build \
    && python -m build --wheel

FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN addgroup --system shadowshield \
    && adduser --system --ingroup shadowshield --home /nonexistent shadowshield \
    && mkdir -p /var/lib/shadowshield \
    && chown shadowshield:shadowshield /var/lib/shadowshield
COPY --from=builder /build/dist/*.whl /tmp/
RUN python -m pip install --no-cache-dir /tmp/*.whl "fastapi>=0.110" "uvicorn>=0.29" \
    && rm -f /tmp/*.whl

USER shadowshield
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=2)"]

CMD ["shadowshield", "serve", "--control", "--host", "0.0.0.0", "--port", "8000"]
