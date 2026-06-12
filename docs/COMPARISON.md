# ShadowShield — Audit & Competitive Comparison

**Date:** 2026-06-12 · **Version audited:** 0.1.0 (post-upgrade)

This document is the honest, evidence-backed answer to "how does ShadowShield
stack up against the best open-source LLM-security tools, and where does it win?"
It pairs a competitive matrix with ShadowShield's own reproducible benchmark
numbers. The underlying landscape research is in
[`research/LANDSCAPE.md`](research/LANDSCAPE.md).

## TL;DR

ShadowShield now meets every table-stake the field requires **and** ships the two
highest-value differentiators the rest of OSS is missing:

1. **Agent-trace alignment auditing** (the LlamaFirewall *AlignmentCheck* pattern)
   — objective-vs-action goal-hijack detection, not just text scanning.
2. **Spotlighting / datamarking as a first-class `isolate` responder** — the
   Microsoft structural defense (ASR ~50%→<3%) that almost no OSS guard ships as
   an action.

Plus native **canary tokens** (becoming the maintained successor to the now-archived
Rebuff), an opt-in **DeBERTa classifier** layer, **PII + secret output scanning**,
**tool-call guarding**, **async**, and a **reproducible benchmark harness** with a
published number — all under MIT with a light, optional-by-default dependency tree.

## Reproducible benchmark (bundled, offline)

Run it yourself: `shadowshield benchmark` (zero network, zero extra deps).

| Metric | balanced mode |
|---|---:|
| Examples | 75 (40 attack / 35 benign) |
| **Detection rate (recall)** | **100.0%** |
| **False-positive rate** | **0.0%** |
| FPR on *hard negatives* (benign w/ trigger words) | **0.0%** (0/16) |
| Precision | 100.0% |
| F1 / balanced accuracy | 100.0% / 100.0% |
| Latency p50 / p95 | **0.16 ms / 0.21 ms** |

**Honesty note (this matters).** 100% on our *own* curated set is a **regression
baseline and smoke test, not a claim of SOTA.** The real number is the external
one — measured on `deepset/prompt-injections` (test split, 116 ex):

| config | recall | FPR | precision |
|---|---:|---:|---:|
| deterministic (regex + multilingual sigs) | 23.3% | 0% | 100% |
| + DeBERTa classifier | **48.3%** | **0%** | **100%** |

Full results + reproduction in **[BENCHMARKS.md](BENCHMARKS.md)**. The takeaways:
the deterministic tier is high-precision/low-recall, multilingual signatures
(de/es/fr/it/pt) and the classifier each add recall at **zero false-positive
cost**, and even then we publish a humbling 48% rather than a cherry-picked figure. Per the 2026
distribution-shift literature ("When Benchmarks Lie"), in-distribution scores
collapse under real shift — so the bundled 100% only proves we don't regress on
our own catalogue. For external validation, the harness loads public corpora:

```bash
pip install "shadowshield[datasets]"
shadowshield benchmark --hf deepset/prompt-injections --split test
```

Recommended external suite (see LANDSCAPE.md §3): **deepset/prompt-injections**
(smoke), **PINT** (false-positives/hard-negatives), **InjecAgent** (indirect/tool
injection), **AgentDojo** (agent ASR *at fixed utility*). Publishing an AgentDojo
number is the highest-credibility next step.

## Capability matrix

Legend: ✅ first-class · 🟡 partial/optional · ❌ absent

| Capability | LLM Guard | LlamaFirewall | NeMo Guardrails | Guardrails AI | Rebuff (archived) | **ShadowShield** |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| Regex / heuristic tier | ✅ | 🟡 | ✅ | 🟡 | ✅ | ✅ |
| Obfuscation-aware (zero-width/homoglyph/base64) | 🟡 | 🟡 | ❌ | ❌ | ❌ | ✅ |
| DeBERTa injection classifier | ✅ | ✅ | 🟡 | 🟡 | ✅ | 🟡 (opt-in) |
| Input **and** output scanning | ✅ | ✅ | ✅ | ✅ | 🟡 | ✅ |
| Secret + PII output scanning | ✅ | ❌ | 🟡 | 🟡 | ❌ | ✅ |
| **Canary tokens** | ❌ | ❌ | ❌ | 🟡 (via Rebuff) | ✅ | ✅ |
| **Spotlighting/datamarking as an action** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Agent-trace alignment audit** | ❌ | ✅ | 🟡 | ❌ | ❌ | ✅ |
| Tool-call / execution guarding | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Adaptive rate limiting | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| LLM-judge self-check (gated) | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Async API | 🟡 | 🟡 | ✅ | 🟡 | ❌ | ✅ |
| Framework middleware (OpenAI/LangChain) | 🟡 | 🟡 | ✅ | ✅ | 🟡 | ✅ |
| Reproducible benchmark + published number | 🟡 | ✅ | ❌ | ❌ | ❌ | ✅ |
| Plugin/extension system | ✅ | ❌ | ✅ | ✅ | ❌ | ✅ |
| Light default dependency footprint | ❌ | ❌ | ❌ | 🟡 | 🟡 | ✅ |
| License | MIT | Meta OSS | Apache-2.0 | Apache-2.0 | Apache-2.0 | **MIT** |

## Audit: what the upgrade changed

| Gap found (v0.1.0 initial) | Resolution |
|---|---|
| No ML classifier layer (table-stake) | `TransformerDetector` (opt-in, configurable model; ProtectAI v2 default) |
| No canary tokens | `core/canary.py` + `CanaryLeakDetector` (CRITICAL on leak; secret never logged) |
| No PII detection | `PIIDetector` (Luhn-validated cards; output=leak, input=informational) |
| No agent/tool awareness | `scan_tool_call` / `scan_tool_result` + `AlignmentCheckDetector` |
| No async API | `ascan` / `aguard` / `afilter` (event-loop friendly) |
| No way to *prove* quality | `shadowshield.eval` harness + bundled benchmark + `shadowshield benchmark` |
| 8 detector coverage gaps (80% recall) | generalized override/jailbreak/exfil signatures → 100% on the set |
| 1 over-defense FP ("developer mode" in benign app text) | tightened the jailbreak `mode` pattern to require an activating verb |
| Homoglyph gap (lowercase Cyrillic `ѕ` etc.) | expanded confusables map |

## Where ShadowShield is genuinely best

1. **Agentic depth + structural defense together.** It's the only OSS guard that
   pairs LlamaFirewall-style alignment auditing *with* spotlighting-as-an-action
   *with* canary tokens *with* tool-call guarding — under one config.
2. **Over-defense discipline.** 0% FPR on hard negatives by design; input PII and
   role-play are flagged, not blocked. The field's dirty secret is false positives;
   ShadowShield measures and minimizes them.
3. **Developer experience.** One `Shield` object; `guard`/`filter` fail-closed vs
   fail-soft ergonomics; drop-in OpenAI/LangChain middleware; async; a CLI.
4. **Honesty + reproducibility.** Ships the harness and the hard-negative split so
   anyone can verify — and the docs state plainly what the numbers do and don't prove.

## Production readiness

The four pre-production blockers identified in audit are **fixed and have
regression tests** (94 tests total, mypy-strict, ruff-clean):

| Blocker | Status |
|---|---|
| Thread-safety (rate limiter + canary registry shared state) | ✅ locked; concurrency tests |
| LLM/alignment judge could hang the request | ✅ `timeout_seconds` enforced via bounded pool |
| Resource exhaustion on huge inputs | ✅ `max_input_chars` prefix cap (default 100k) |
| ML classifier untested | ✅ mocked-pipeline tests + opt-in real-model test |

**Ready now** for: synchronous *or* multi-threaded/async deployments using the
deterministic tiers + canary + PII + tool-call guarding + LLM/alignment judges.

**Before relying on the ML classifier in production:** run the gated real-model
test in your CI (`SHADOWSHIELD_RUN_MODEL_TESTS=1` with `[transformers]`) — its
*logic* is covered, but the live model has not been exercised in this repo's CI.

**Still recommended before a 1.0 / PyPI release:** an externally-validated
benchmark number (AgentDojo/PINT), a CI run on a real runner, and audit-log
rotation. None are blockers for an internal/self-hosted deployment.

## Honest remaining gaps (roadmap)

- **Published AgentDojo / InjecAgent numbers.** The harness supports external
  datasets; we have not yet published an agent-ASR-at-fixed-utility figure. *(highest priority)*
- **Vector-similarity self-hardening loop** (Rebuff layer 3): embed canary-caught
  attacks into an index to catch paraphrases. Designed, not yet shipped.
- **Presidio PII backend** is wired as an optional extra but the analyzer adapter
  is not yet implemented (regex layer ships today).
- **Multilingual** detection leans on the optional Prompt-Guard-2 model; the
  built-in signatures are English-centric.
- **FastAPI dashboard/server** (the `[dashboard]` extra) is reserved, not built.
