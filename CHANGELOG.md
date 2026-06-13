# Changelog

All notable changes to ShadowShield are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] — 2026-06-13

### Added
- **Landing page** at **https://shadowshield.xyz** (`site/`, deployed on Vercel) —
  a self-contained "technical broadsheet" page with the honest external benchmark
  as the hero figure; ships security headers via `site/vercel.json`.

### Changed
- Project **Homepage** metadata (PyPI + GitHub) now points to `shadowshield.xyz`.

## [0.5.0] — 2026-06-13

PyPI launch, HTTP server, Presidio PII backend, and CI hardening.

### Added
- **Published to PyPI** — `pip install shadowshield`. Releases publish
  automatically via GitHub **Trusted Publishing** (OIDC, no stored tokens); see
  `docs/RELEASING.md`.
- **FastAPI server + dashboard** (`[dashboard]` extra) — `shadowshield serve` /
  `shadowshield.server.create_app`. Endpoints: `GET /health`, `POST /scan`,
  `POST /guard`, and a minimal live `GET /` dashboard.
- **Presidio PII backend** — the `pii` detector now takes a `backend` option
  (`regex` | `presidio` | `both`). Presidio adds NER + checksum recognizers; it
  fails safe back to the regex layer when the `[pii]` extra isn't installed.

### Changed
- CI actions bumped to Node-24-compatible majors (checkout@v5, setup-python@v6,
  artifact@v5) — clears the deprecation warning.
- Added a `.pre-commit-config.yaml` mirroring the CI core job.

### Notes
- Test count 121 → **132** (+ server + PII-backend coverage).

## [0.4.0] — 2026-06-12

Vector-similarity tier, self-hardening, AgentDojo adapter, and split CI.

### Added
- **Vector-similarity detector** (`VectorSimilarityDetector`, `[vectors]` extra) —
  embeds input and matches it against a bundled multilingual attack corpus via
  cosine similarity, catching *paraphrases* and *translations* the regex misses.
  Opt-in via `Shield(use_vectors=True)`. Default model:
  `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`.
- **Self-hardening** — `Shield.harden(text)` / `VectorSimilarityDetector.add_attack`
  append confirmed attacks to the live index (the Rebuff loop, now maintained).
- **AgentDojo defense adapter** — `shadowshield.integrations.make_agentdojo_defense`
  exposes ShadowShield as an AgentDojo `PipelineElement` (scans tool outputs, aborts
  on injection), plus a standalone `scan_messages_for_injection` helper.

### Measured (deepset/prompt-injections test split — the full layer ladder)
All at **0% false positives / 100% precision**:
regex 18.3% → +multilingual 23.3% → **+vector 25.0%** → +classifier 48.3%.

### Changed
- **CI split** into a fast `core` job (lint/type/test, no heavy ML — seconds) and a
  separate `ml-integration` job that exercises the classifier + vector tiers against
  real models. PRs get fast feedback; the badge isn't blocked by model downloads.

### Notes
- Test count 111 → **121** (+2 skipped real-model integration tests).

## [0.3.0] — 2026-06-12

Multilingual detection + measured external benchmarks.

### Added
- **Multilingual injection signatures** — override / extraction / persona-
  reassignment templates in **German, Spanish, French, Italian, and Portuguese**,
  folded into the prompt-injection detector (so they also get decoded-payload and
  obfuscation handling). Most OSS guards are English-only at the signature tier.
- `docs/BENCHMARKS.md` — reproducible, honestly-reported results.

### Measured (on `deepset/prompt-injections`, test split — see BENCHMARKS.md)
- Deterministic tiers: **18.3% → 23.3%** recall after multilingual signatures, at
  **0% false positives / 100% precision**.
- With the DeBERTa classifier: **48.3%** recall, **0% FPR**, 100% precision.
- Every layer adds recall without eroding the zero-over-defense property. The ML
  classifier code path is now validated end-to-end against a real model + real data.

### Notes
- For stronger non-English ML coverage, set
  `use_transformer="meta-llama/Llama-Prompt-Guard-2-22M"` (multilingual; **gated** —
  requires HuggingFace login). The default ProtectAI model needs no token.
- Test count 94 → **111** (+1 skipped real-model).

## [0.2.0] — 2026-06-12

The "be the best OSS guard" upgrade — driven by a competitive audit of LLM Guard,
LlamaFirewall, NeMo Guardrails, Guardrails AI, and Rebuff (see
`docs/COMPARISON.md` and `docs/research/LANDSCAPE.md`).

### Added
- **Agent-trace alignment audit** (`AlignmentCheckDetector`) — objective-vs-action
  goal-hijack detection, the LlamaFirewall *AlignmentCheck* pattern. Set an
  objective via `session(objective=...)` and a judge via `Shield(alignment_judge=...)`.
- **Canary tokens** (`shield.issue_canary()` + `CanaryLeakDetector`) — detect
  *successful* injections / prompt exfiltration. Maintained successor to the now-
  archived Rebuff.
- **Tool-call guarding** — `scan_tool_call()` / `scan_tool_result()` treat agent
  actions and (untrusted) tool outputs as first-class scan targets.
- **Optional DeBERTa classifier** (`TransformerDetector`, `[transformers]` extra) —
  the ML detection layer; configurable model (ProtectAI v2 default).
- **PII detection** (`PIIDetector`) — emails, SSNs, phones, IPs, and Luhn-validated
  credit cards; output-side leak protection, input-side informational.
- **Async API** — `ascan` / `aguard` / `afilter`.
- **Eval/benchmark harness** (`shadowshield.eval`) + bundled offline benchmark
  (with NotInject-style hard negatives) + `shadowshield benchmark` CLI.

### Improved
- Detector coverage raised from **80% → 100%** detection on the bundled benchmark
  at **0% false positives** (incl. hard negatives): generalized override/jailbreak/
  exfiltration signatures, expanded homoglyph map, and tightened the "developer
  mode" jailbreak pattern to remove a benign false positive.
- New extras: `transformers`, `pii` (Presidio), `datasets`.

### Hardened (pre-production blockers)
- **Thread-safety:** the rate limiter and canary registry now guard their shared
  state with locks — safe under the async API's worker threads (a racy limiter
  would silently fail open).
- **Judge timeouts enforced:** `llm_check.timeout_seconds` is now applied to both
  the LLM self-check and the alignment judge via a bounded thread pool — a hung
  judge can no longer block the request path (it degrades to a fail-safe note).
- **Input-size guard:** new `max_input_chars` (default 100k) caps scanned bytes;
  oversized payloads are scanned as a truncated prefix and flagged, preventing
  resource exhaustion from multi-megabyte inputs.
- **ML classifier test coverage:** `TransformerDetector` now has mocked-pipeline
  tests (label mapping, threshold, shapes, ImportError) plus an opt-in real-model
  integration test (`SHADOWSHIELD_RUN_MODEL_TESTS=1`).
- Test count 77 → **94** (+1 skipped real-model).

## [0.1.0] — 2026-06-12

Initial public release. ShadowShield unifies *Sentinel* (detection) and
*ShadowClaw* (active defense) into one defense-in-depth framework.

### Added
- **Unified engine** (`core/engine.py`) — one detection→decision→response pass for
  both model input and output, with a weighted noisy-or aggregator.
- **`Shield`** with `scan` / `guard` (fail-closed) / `filter` (fail-soft) /
  `isolate`, the `@protect` decorator, and stateful `session()` context manager.
- **Detectors:** `prompt_injection` (flagship), `jailbreak`, `encoding_obfuscation`,
  `data_exfiltration` (+ output-side secret-leak blocking), `anomaly`, and an
  optional gated `llm_self_check`.
- **Responders:** `sanitizer` (span redaction + carrier stripping), `blocker`
  (safe fallbacks), `isolator` (spotlighting/datamarking), and an adaptive
  per-identity `rate_limiter`.
- **Normalization** that defeats zero-width, bidi, homoglyph, and base64/hex
  obfuscation before matching.
- **Modes** (`strict` / `balanced` / `permissive`), YAML config, per-detector
  weights, and a global kill-switch.
- **Middleware:** OpenAI-compatible `ShieldedChatClient`, LangChain
  `shield_runnable` / `ShieldedChatModel`, and module-level `protect`.
- **Plugin system** via the `shadowshield.plugins` entry-point group.
- **CLI** (`shadowshield scan | detectors | init`) and a redacting JSONL audit log
  routed to stderr.
- 60 unit/integration tests covering the attack catalogue; strict typing; MIT.

[0.5.1]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.5.1
[0.5.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.5.0
[0.4.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.4.0
[0.3.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.3.0
[0.2.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.2.0
[0.1.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.1.0
