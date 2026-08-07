# ShadowShield — Comprehensive Upgrade Plan

**Baseline:** v0.6.3 · **Date:** 2026-08-05
**Sources:** 2026-08-05 audit report, `docs/UPGRADE_OPPORTUNITIES.md` (items still open),
`docs/PRODUCTION_READINESS.md` (open operator items), `docs/NEXT_STEPS.md` (closed).

---

## Context: what's already done

The June 2026 upgrade cycle shipped the dashboard, auth/hardened intake, Prometheus
metrics, protection-floor policy, MCP guard, reporter SDK, OWASP map, and adversarial
benchmarks. The 2026-08-05 audit re-verified: 320 tests pass, ruff/mypy-strict clean,
86% branch coverage, zero known dependency CVEs, no committed secrets.

So this plan targets the **remaining** gaps — one medium security finding, structural
quality debt, and the high-reach features that were deliberately deferred.

**Guiding constraints (carry forward):**
- Tiny core, heavy stuff is an extra — no new mandatory dependencies.
- Fail-closed everywhere; a security control must never be remotely turn-off-able.
- Honest benchmarks — every recall/FPR claim must be reproducible via `benchmark`.
- Zero breaking changes before 1.0 without a deprecation cycle.

---

## Phase 0 — Audit remediation (1–2 days, do first)

Small, safe, ships as **v0.6.4** (patch).

| # | Item | File(s) | Detail |
|---|---|---|---|
| 0.1 | **M-1: fail-closed policy API** | `core/policy.py`, `test_policy.py` | `apply_bundle` rejects when `verifier is None` unless `allow_unsigned=True` is passed explicitly. Keep signature backward-compatible via keyword-only flag; update docstring claim to match code. Add tests: unsigned-rejected-by-default, explicit opt-in path. |
| 0.2 | **L-3: reporter scheme enforcement** | `reporter.py`, `test_telemetry.py` | Refuse (or loudly warn + require opt-in flag on) `http://` endpoints when an `api_key` is set. Log once when the drop counter starts climbing. |
| 0.3 | **L-4: span merge in sanitizer** | `responders/sanitizer.py`, `test_responders.py` | Merge overlapping/adjacent spans before right-to-left replacement; emit one `[redacted:…]` per merged span. |
| 0.4 | **L-6: housekeeping** | `requirements/README` note | Document the `pip-audit --no-deps` invocation for `container.lock` so local audits reproduce CI. |

**Gate:** full suite + ruff + mypy green; changelog entry; patch release.

---

## Phase 1 — Structural quality (3–5 days, v0.7.0)

| # | Item | Effort | Detail |
|---|---|---|---|
| 1.1 | **L-2: split `control.py`** (1,448 lines) | Med | Extract `control/auth.py` (credential resolution + startup validation), `control/policy_api.py` (policy endpoints + anti-replay state), `control/metrics.py` (Prometheus + event ring), `control/dashboard.py` (HTML). `control.py` keeps `create_control_app` as thin composition. Public imports unchanged. |
| 1.2 | **L-1: close coverage gaps** | Med | Unit tests with fakes for `middleware/langchain.py` (0% → ≥80%), `plugins/manager.py` (33% → ≥85%), `middleware/base.py` (57% → ≥85%). Focus on error/edge paths, not happy paths. AgentDojo adapter stays low (needs API keys) — document why. |
| 1.3 | **Config hot-reload** | Low | `POST /api/reload` (admin-authed) re-reading a YAML file through the protection floor, so operators retune thresholds without a restart. Builds on existing policy machinery. |
| 1.4 | **Vector self-hardening persistence** | Low | Persist `Shield.harden()` learned attacks (JSONL of embeddings/strings under a configurable path) so the feedback loop survives redeploys. Opt-in; content handling documented (attack strings are adversary content — treat as tainted on load). |

**Gate:** coverage total ≥ 88%, no file > 800 lines in `control/`, reload + persistence round-trip tests.

---

## Phase 2 — Detection depth (1–2 weeks, v0.8.0)

The honest Beta label (blind ASR 22–30%) is the project's credibility anchor;
this phase moves the number and proves it.

| # | Item | Effort | Detail |
|---|---|---|---|
| 2.1 | **Streaming scanner** (the highest-value engine gap, open since June) | High | `StreamScanner`: accepts chunks, rolling window + carry-over for split signatures/secrets, early BLOCK mid-stream. Canary/secret-leak cut the stream the instant a marker appears. Async + sync APIs; backpressure bounded; integrates with engine decision/policy unchanged. |
| 2.2 | **Score calibration** | Med | Platt/isotonic calibration of detector scores on the eval set so `block_threshold` means the same thing across detectors. Ship calibration artifact + `benchmark --calibrated` comparison; publish before/after honestly. |
| 2.3 | **Expand blind benchmark corpus** | Med | Grow v1–v3 blind sets (target 2× size), add multilingual + indirect-injection (tool-result) splits. Wire AgentDojo adapter into a reproducible CI-runnable harness (nightly, not per-PR). |
| 2.4 | **Parallel cheap-detector fan-out (opt-in)** | Low | Reuse the existing engine thread pool; measure first — only ship if p95 improves with transformer layer on. |

**Gate:** published benchmark delta (target: blind ASR ↓ ≥5 pts at fixed FPR); streaming early-block latency benchmark in docs.

---

## Phase 3 — Reach (2–3 weeks, v0.9.0)

| # | Item | Effort | Detail |
|---|---|---|---|
| 3.1 | **Reverse-proxy / gateway mode** | Med-High | `shadowshield proxy --upstream https://api.openai.com` — transparently guards requests/responses for any OpenAI-compatible endpoint. Zero-code adoption for non-Python stacks; the broadest-reach feature. Streaming proxy must pair with Phase 2.1. |
| 3.2 | **Middleware breadth** | Med | Anthropic SDK adapter, **LiteLLM** (best bang-for-buck: dozens of providers), generic ASGI middleware for FastAPI/Starlette apps. Each lazy-imported, each with fake-client tests. |
| 3.3 | **RAG / indirect-injection adapters** | Med | LlamaIndex/Haystack retriever wrappers that scan retrieved chunks — where indirect injection actually enters. |
| 3.4 | **Helm chart** | Low | Minimal chart over the existing hardened image (read-only, cap-drop, digest pin carried over). |

**Gate:** each integration ships with an example in `examples/` + a docs page; proxy mode gets an end-to-end test with a mock upstream.

---

## Phase 4 — Scale & 1.0 hardening (v1.0.0)

| # | Item | Detail |
|---|---|---|
| 4.1 | **External state backends** | Counters, rate limits, event feed, and policy state behind pluggable interfaces (Redis/Postgres adapters as extras). Closes the "Scale/HA: process-local" readiness gap. |
| 4.2 | **API freeze + stability policy** | Audit public API surface (`__all__`), mark internals, commit to semver; write the deprecation policy. |
| 4.3 | **Performance regression suite** | p50/p95 scan latency benchmarks in CI with a regression budget (current baseline: p50 ≈ 0.2 ms cheap tiers). |
| 4.4 | **Docs pass** | Architecture guide, security-model refresh, migration notes from 0.x. |

**1.0 gate:** all PRODUCTION_READINESS rows "Ready", blind ASR/FPR targets published and met, no open audit findings.

---

## Sequencing & effort summary

```
Phase 0 (v0.6.4)   ██        1–2 days     audit fixes — start here
Phase 1 (v0.7.0)   ████      3–5 days     structure + coverage
Phase 2 (v0.8.0)   ████████  1–2 weeks    streaming + calibration + benchmarks
Phase 3 (v0.9.0)   ████████  2–3 weeks    proxy + integrations
Phase 4 (v1.0.0)   ████      1–2 weeks    scale + freeze
```

Dependencies: 2.1 (streaming) → 3.1 (proxy streaming); 1.1 (control split) before 4.1;
2.2 (calibration) before 2.3 (new benchmark numbers must use calibrated scores).

## Explicitly out of scope

- Multi-tenant SaaS backend — stays gated behind design-partner pre-sell (per GOVERNANCE/SAAS_STRATEGY).
- React SPA dashboard — only revisit if embedded dashboard exceeds ~1.5k lines of JS.
- New mandatory runtime dependencies — every capability above lands as an extra or stdlib-only.
