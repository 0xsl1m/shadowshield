# ShadowShield — Upgrade Opportunities Assessment

**Version reviewed:** 0.5.1 · **Date:** 2026-06-16 · **Scope:** full library + server/dashboard

This is a grounded read of the current codebase (`src/shadowshield/`), not a wishlist. Each
opportunity notes *why it matters*, *where it lands in the code*, and a rough **impact × effort**
score. A companion control-dashboard prototype ships alongside this document.

---

## Where ShadowShield stands today

The core is genuinely strong and unusually disciplined for an OSS guard:

- **One symmetric engine** (`core/engine.py`) for input and output, with a shared `ScanContext`
  built once (normalize + decode) and reused across detectors — the right architecture.
- **Layered detection** — nine always-on detectors (prompt-injection w/ multilingual signatures,
  jailbreak, encoding/obfuscation, exfiltration, PII, anomaly, canary, alignment, LLM self-check)
  plus two opt-in recall layers (DeBERTa transformer, vector similarity). Aggregated with a
  weighted noisy-or so one strong signal is never averaged away.
- **Active response** — sanitize / isolate (spotlight + datamark) / block, in a deliberate order.
- **Fail-safe everywhere** — a detector that raises drops its own contribution (`_safe_scan`);
  judges run in a bounded thread pool with hard timeouts; oversized inputs are truncated and flagged.
- **Proven** — eval harness with honest FP reporting; bundled 75-example set scores 100% recall /
  0% FP at p50 ≈ 0.2 ms (verified on this machine).
- **Clean ops hygiene** — Pydantic-validated config, strict mypy, ruff, 132 tests, redacting audit log.

So the upgrades below are about **reach, production-readiness, and operability** — not fixing a
broken core. The single biggest *product* gap is the control surface: the shipped dashboard is one
textarea posting to `/scan`. That's what the prototype addresses.

---

## Priority matrix

| # | Opportunity | Impact | Effort | Layer |
|---|---|:--:|:--:|---|
| 1 | Full control dashboard (live feed, metrics, config, eval) | High | Med | server/UI |
| 2 | Server hardening: auth, CORS, server-side rate limit | High | Low | server |
| 3 | Streaming / incremental output scanning | High | Med | engine |
| 4 | Metrics & observability export (Prometheus / OTel) | High | Med | utils/server |
| 5 | MCP guard server (shield agentic tool calls natively) | High | Med | integrations |
| 6 | Persist vector self-hardening index across restarts | Med | Low | detectors/vector |
| 7 | Reverse-proxy / gateway mode | Med | Med | server |
| 8 | More integrations: Anthropic, LiteLLM, LlamaIndex, ASGI | Med | Med | middleware |
| 9 | Config hot-reload + JSON-Schema export for tooling | Med | Low | core/config |
| 10 | Span coverage + score calibration | Med | Med | detectors |
| 11 | Docker image + compose + Helm chart | Med | Low | packaging |
| 12 | Parallelize cheap detectors (opt-in) | Low | Low | engine |

---

## Detection & engine

**Streaming / incremental output scanning (#3, high).** `Engine.evaluate` scans a whole string.
Modern apps stream tokens, so today you either buffer the entire completion before scanning (adds
latency, defeats streaming) or scan nothing. A `StreamScanner` that accepts chunks, maintains a
rolling window + carry-over for split signatures/secrets, and emits an early BLOCK mid-stream would
be the highest-value engine addition. Secret-leak and canary detection especially benefit — you want
to cut the stream the instant a key appears, not after it's all sent.

**Span coverage & score calibration (#10, med).** Threats carry `span`, but several detectors leave
it `None` (e.g. the exfiltration finding in a live scan). The dashboard highlights matched spans, so
filling these in pays off immediately in the UI and in audit quality. Separately, detector scores are
hand-tuned constants; a small calibration pass (Platt/iso on the eval set) would make the aggregate
score a more honest probability and let `block_threshold` mean the same thing across detectors.

**Self-hardening persistence (#6, med, cheap).** `Shield.harden()` teaches the vector index a
confirmed attack — but the index lives in memory and dies on restart. Persisting it (JSONL of
embeddings or attack strings) so learned attacks survive a redeploy turns a nice demo into a real
feedback loop, especially paired with canary-confirmed breaches.

**Parallelize cheap detectors (#12, low).** `_run_cheap_detectors` is a sequential loop; the engine
already owns a thread pool (used only for judges). At p50 ≈ 0.2 ms the cheap tiers don't need it, but
once the transformer layer is on, an opt-in parallel fan-out would help tail latency. Low priority —
measure first.

---

## Production-readiness & operability

**Server hardening (#2, high, cheap).** `server.py` says it plainly: "an unauthenticated control
plane — put it behind your own auth/network boundary." For a security product that's a sharp edge.
Add optional API-key/bearer auth, configurable CORS, and a server-side rate limit (the library has a
rate limiter; the HTTP layer doesn't use it). This is a small change with outsized trust impact, and
it's a prerequisite for shipping the dashboard as anything but localhost-only.

**Metrics & observability export (#4, high).** Today the only output is a JSONL audit file / structlog
to stderr. Production wants a `/metrics` Prometheus endpoint (scan count, block rate, per-detector hit
rate, latency histogram, FP counter) and optional OpenTelemetry spans. This is also the data backend
the dashboard's analytics tab consumes, so build it once and both consumers win.

**Config hot-reload + JSON-Schema export (#9, med, cheap).** The config is already Pydantic, so
`ShieldConfig.model_json_schema()` gives you a schema for free — emit it (`shadowshield schema`) to
drive form generation and validate YAML in CI/editors. Add a SIGHUP/endpoint reload so operators can
retune thresholds without dropping the process.

**Packaging (#11, med, cheap).** A published Docker image, a compose file (server + optional
Prometheus/Grafana), and a minimal Helm chart would make "run the shield as a service" a one-liner.

---

## Reach: integrations & deployment shapes

**MCP guard server (#5, high).** ShadowShield is explicitly agent-focused (tool-call guarding,
canaries, alignment audit). Exposing it as an **MCP server** — so any MCP client routes tool calls
and tool results through `scan_tool_call` / `scan_tool_result` — meets the agentic ecosystem where it
now lives and is a strong differentiator. High strategic value.

**Reverse-proxy / gateway mode (#7, med).** A mode where ShadowShield sits in front of an
OpenAI-compatible endpoint and transparently guards every request/response lets non-Python and
closed-source stacks adopt it with zero code change — the broadest possible reach.

**More middleware (#8, med).** Current adapters: OpenAI-compatible + LangChain. The obvious gaps are
the **Anthropic SDK**, **LiteLLM** (covers dozens of providers at once — best bang for buck),
**LlamaIndex/Haystack** for RAG (where indirect injection lives), and a generic **ASGI middleware** so
any FastAPI/Starlette app can wrap itself.

---

## The dashboard (companion prototype)

The shipped `GET /` is a single textarea. The four capabilities you asked for map cleanly onto the
engine's existing data:

1. **Live scanning + threat feed** — `/scan` already returns full `ScanResult` dicts with threats,
   categories, severity, decision, and (where present) spans. The prototype adds a rolling in-memory
   event ring so recent scans render as a feed with drill-down.
2. **Metrics & analytics** — aggregated counters over the event ring: scan volume, block/sanitize/flag
   rates, per-detector hit rate, decision and severity breakdowns, latency p50/p95. Inline SVG charts,
   no CDN (a security tool should run air-gapped).
3. **Config control panel** — read the live `ShieldConfig`, toggle detectors, switch mode, tune
   `block_threshold` and per-detector weights, and push changes to a hot-swapped shield instance.
4. **Benchmark & eval runner** — trigger `evaluate_shield(load_builtin())` from the UI and render
   recall / FPR / precision / F1 / latency and per-category flag rates.

**Build recommendation (chosen): enhanced embedded HTML/JS, single self-contained page, no external
CDN, inline SVG charts.** Rationale: it preserves ShadowShield's defining "tiny core, heavy stuff is an
extra" ethos, keeps the dashboard usable in air-gapped/regulated environments (no third-party script
fetch), and adds zero build tooling. A React SPA would be more maintainable at large scope but breaks
the dependency-light promise and complicates the "one `shadowshield serve`" story. If the dashboard
later grows beyond ~1.5k lines of JS, revisit a small Preact/htm build that still vendors locally.

> The prototype intentionally keeps all new server state **in-memory and opt-in**, and the mutation
> endpoints (config/detector toggles) are the reason recommendation #2 (auth) should land before any
> non-localhost deployment.

---

## Suggested sequencing

1. **Now (this work):** control dashboard + the supporting metrics/config/eval endpoints.
2. **Next, cheap & high-trust:** server auth/CORS/rate-limit (#2), config JSON-Schema + hot-reload (#9),
   vector persistence (#6), Docker/compose (#11).
3. **Then, high-reach:** streaming scanner (#3), Prometheus/OTel (#4), MCP guard server (#5).
4. **Ongoing:** integration breadth (#8), span/calibration polish (#10), proxy mode (#7).
