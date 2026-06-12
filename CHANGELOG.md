# Changelog

All notable changes to ShadowShield are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.2.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.2.0
[0.1.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.1.0
