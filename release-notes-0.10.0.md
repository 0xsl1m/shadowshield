# ShadowShield 0.10.0

## Highlights

- **Engine-enforced shadow mode** — a payload-preserving observation lane enforced by the engine, not the proxy layer. Shadow mode observes and logs without ever mutating or blocking the stream.
- **Isolated API-key resolution** — upstream keys are resolved with `include_environment=False` and fail closed when no explicit key is configured; ambient environment keys can no longer leak into upstream requests.
- **New guarded routes** — Anthropic `/v1/messages` and OpenAI `/v1/responses` proxies with protocol-native extraction of messages, tool calls, tool results, and streamed events.
- **Extraction-completeness guards** — malformed or over-limit structured payloads fail closed instead of passing unscanned.

## Breaking changes

- **Fail-open → fail-closed reversal** — scanner failures, invalid JSON on guarded routes, oversized bodies/SSE events, and tail-attack patterns now return **403/503** instead of passing traffic through. See CHANGELOG for the full condition matrix.

## Limits

- Request body cap: **1 MiB** (256 KiB per SSE event).

## Also in this release

- `/health` request accounting (proxied-request counter).
- Log-hygiene fix: detector-failure paths no longer log payload content.
- Build toolchain: `build` 1.6.0 (lockfile regenerated), Docker base `python:3.14-slim` digest refresh.

**Full changelog and migration notes:** see `CHANGELOG.md` in the repository.
