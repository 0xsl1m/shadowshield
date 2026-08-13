# Changelog

All notable changes to ShadowShield are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.1] - 2026-08-13

### Fixed — proxy rollout safety (#27)

- **Fail-open on scanner exceptions**: a detector exception in the proxy's
  request/response/stream scan paths previously propagated as a 500 to the
  caller's LLM request. Now logged (`shadowshield.proxy.scan_error`) and
  treated as no-verdict — a guard bug can no longer take down wired harnesses.
- **Shadow logging at proxy scope**: permissive mode now emits
  `shadowshield.proxy.request_flagged` / `response_flagged` for every
  non-terminal finding, so a shadow deployment can see what enforcing modes
  *would* do before flipping to `balanced`.

### Fixed — MCP integration packaging

- New `[mcp]` extra (`pip install "shadowshield[mcp]"`): `build_mcp_server`
  previously had no declared dependency and broke on `mcp` 2.0 (FastMCP moved).
  Pinned to `mcp>=1.0,<2` until the integration is ported to the 2.0 API.

## [0.8.0] - 2026-08-10

### Added — Chinese (Simplified) signatures (#9, first external contribution)

- Four zh-CN signatures in `PromptInjectionDetector` (override ×2, role
  reassignment, system-prompt extraction) with a matching prefilter group —
  the first CJK coverage at the deterministic tier. Split-override design
  avoids the `忘记你的密码提示词` ("forget your password hint") false positive;
  9 attack samples + 9 hard negatives. Thanks @01luyicheng.

### Added — classifier tranche (2026-08-09)

- `TransformerDetector(segment_spans=True)` — sentence-level segmentation with
  per-segment classification, emitting span-carrying threats so the sanitizer
  redacts *just the attacking sentences* while legitimate tool data survives.
  Whole-text classification remains as the evasion-resistant backstop
  (span-less threat when the aggregate is hostile but no segment crosses).
  New `segment_threshold` knob; 6 new unit tests.
- `scripts/classifier_calib.py` — offline, zero-API-cost calibration harness:
  InjecAgent residual coverage, benign FP at threshold grid, and AgentDojo
  trajectory replay with per-suite checkpoints.

### Fixed — AgentDojo adapter (2026-08-09)

- **The adapter never saw tool-output text**: AgentDojo 0.1.35 serializes
  content blocks as `{"type": "text", "content": ...}` but `_message_text`
  read only the `text` key, so the defense scanned empty strings. The
  published 2026-08-07/08 deterministic-arm AgentDojo numbers measured this
  no-op; corrected numbers are in docs/INDUSTRY_BENCHMARKS.md §2.
- Abort only on **block** decisions: sanitize-level findings (low-severity
  PII in benign docs) no longer interrupt clean trajectories.
- Content-hash scan cache: agent loops re-present full history every
  iteration; scanning was quadratic in trajectory length (workspace traces
  stalled), now each unique tool output is scanned once.
- New `tests/test_agentdojo_adapter.py` (8 tests).

### Benchmarks — classifier tranche results (2026-08-09)

- **InjecAgent sanitize-clf arm: ASR-all 18.8% → 0.1%** (DH 0.2%, DS 0.0%) at
  76.9% valid rate — vs sanitize 8.1% / 88.2% and redact 0% / 25.2%.
- **AgentDojo classifier arm: ASR 0% on banking, travel, slack; 1.8% on
  workspace** (baselines 50.7/27.1/61.9/18.8%). No utility failure involved a
  defense abort (`error=None` on every failing trace; deltas are small-n
  trajectory variance).
- Deterministic arm re-measured with the fixed adapter (banking): 46.5% ASR
  (baseline 50.7%) at 62.5% utility (baseline 56.2%).

### Fixed

- AgentDojo defense adapter compatibility with agentdojo ≥ 0.1.33
  (`PipelineElement` → `BasePipelineElement`, with fallback for older releases).

### Added

- `scripts/agentdojo_bench.py` — dev runner for AgentDojo suites with chunked
  per-task execution, `--no-defense` baseline arm, and a tunable `--max-iters`
  tool-loop cap (default 15).
- Runner flags: `--transformer-model` (classifier arm), `--pipeline-name`
  (cache isolation across adapter revisions), and InjecAgent
  `--defense-mode sanitize-clf`.

### Benchmarks

- Industry-standard matrix (2026-08-08, docs/INDUSTRY_BENCHMARKS.md):
  LLMail-Inject **96.75% catch / 0% FPR** (2,000 real attack submissions);
  NotInject 0% block-FPR over-defense; BIPIA three-task dual-predicate eval;
  AgentDojo travel/slack full suites + workspace stratified sample (ASR unmoved,
  zero utility cost, replicating banking); **InjecAgent three-arm study —
  sanitize mode cuts ASR 18.8% → 8.1% at statistically identical utility**
  (88.2% vs 88.7%); four-tier performance suite (deterministic p50 0.25 ms,
  374 scans/s, 0.2 MB RSS).
- New dev runners: `scripts/injecagent_bench.py` (three defense arms,
  chunked/resumable), `scripts/bipia_bench.py`, `scripts/industry_classify_bench.py`,
  `scripts/perf_bench.py`.
- Gated `meta-llama/Llama-Prompt-Guard-2-22M` head-to-head (2026-08-08): 25.0%
  recall / 0% FPR on deepset, 62.1% / 6.9% on v4, p50 106 ms — beaten on every
  quality metric by the non-gated proventra fine-tune; its edge is footprint and
  ~2.5× latency. This closes the last "honest remaining gap" in
  docs/COMPARISON.md. See docs/BENCHMARKS.md §4.
- mDeBERTa multilingual classifier (`proventra/mdeberta-v3-base-prompt-injection`,
  non-gated): **85.0% recall / 0% FPR** on deepset/prompt-injections (vs 48.3% /
  0% for the default English DeBERTa); 100% recall / 41.4% FPR on the v4
  generalization set. See docs/BENCHMARKS.md §4.
- First AgentDojo publication (banking v1.2, `important_instructions` attack,
  gpt-4o-mini): **ASR 52.1% defended vs 50.7% baseline; utility 62.5% vs 56.3%**
  — zero utility cost, and the measured semantic-pretext ceiling that gates the
  classifier tranche. See docs/BENCHMARKS.md §5.

## [0.7.0] — 2026-08-06

Comprehensive audit remediation plus streaming, calibration, parallel, gateway,
and middleware-breadth features from the
[2026-08-05 upgrade plan](docs/UPGRADE_PLAN_2026-08-05.md). Highlights:
mid-flight stream cutting, a zero-code OpenAI-compatible gateway, Anthropic /
LiteLLM / ASGI / RAG middleware, config hot-reload, and a hardened Helm chart.

### Security
- **Fail-closed policy bundles (M-1).** `apply_bundle` now rejects unsigned
  bundles when no verifier is configured, unless the caller explicitly opts in
  with `allow_unsigned=True`. Deployments that previously applied unsigned
  bundles silently must opt in — a deliberate behavior change.
- The telemetry reporter now requires an HTTPS endpoint unless
  `allow_insecure_endpoint=True` (or a custom transport) is set, and warns via
  structlog on queue overflow and delivery failure.
- The sanitizer now merges overlapping/adjacent redaction spans so combined
  categories are reported correctly (`category_a|category_b`).
- Fixed a latent hang in the shared request-body-limit middleware: after the
  buffered body was fully replayed it fabricated endless empty bodies, so
  Starlette's `StreamingResponse` disconnect listener spun forever. The replay
  channel now delegates to the real receive channel once the body is delivered.

### Streaming and scoring
- Added `StreamScanner` (`Shield.stream_scanner(...)`): incremental scanning of
  streamed completions with bounded memory, a carry-over window so signatures
  split across chunk boundaries still match, and early-block semantics — the
  first BLOCK/ESCALATE is terminal and returned immediately so callers can cut
  the stream mid-flight. See `examples/streaming_scan.py`.
- Added isotonic score calibration: `IsotonicCalibrator` (strict, tainted-safe
  artifact loading), `fit_isotonic` (PAV), `fit_from_examples`, an engine
  `calibrator` hook, a `benchmark --calibration PATH` raw-vs-calibrated view,
  and a new `shadowshield calibrate` subcommand.
- Added opt-in parallel detector fan-out (`parallel_detectors: true`): cheap
  detectors run on a bounded thread pool with per-detector context copies;
  findings, ordering, truncation, and error accounting are identical to the
  sequential path. Measured ~3x wall-clock speedup with three 20 ms detectors.

### Gateway and middleware breadth
- Added **gateway mode**: `shadowshield proxy --upstream URL` runs an
  OpenAI-compatible reverse proxy (`shadowshield.proxy.create_proxy_app`) that
  scans chat messages pre-flight (403 short-circuit, upstream never called),
  scans non-streaming completions post-flight, and cuts malicious SSE streams
  mid-flight with an OpenAI-conventional `finish_reason="content_filter"`
  chunk. Proxy auth keys are never forwarded upstream; auth, body limits,
  concurrency caps, and security headers reuse the shared middleware.
- Added `ShieldedAnthropicClient` (`middleware.anthropic`) guarding
  `messages.create` including the `system` parameter and response text blocks.
- Added `shielded_completion` / `ShieldedLiteLLM` (`middleware.litellm`)
  wrapping LiteLLM's functional surface (explicit callables work too — no
  LiteLLM import required).
- Added `ShieldASGIMiddleware` (`middleware.asgi`): pure-ASGI, framework-free
  middleware that guards JSON chat traffic on configurable prefixes in both
  directions (SSE passes through; use the proxy for mid-stream cuts).
- Added RAG guardrails (`middleware.rag`): `scan_retrieved_chunks` with
  drop/keep/raise policies and a retrieval fan-out bound, plus duck-typed
  `ShieldedLlamaIndexRetriever` and `ShieldedHaystackRetriever` wrappers.
  See `examples/rag_guard.py`.

### Control plane and detectors
- Split the 1,448-line `control.py` into the `control` package (`app`, `state`,
  `policy_state`, `models`, `migrate`) with no public API change.
- Added config hot-reload: `ShieldState.reload_from_yaml()` (floor-clamped,
  degradation-capped, fail-closed) and an authenticated `POST /api/reload`
  endpoint wired through `create_control_app`/`serve_control` `config_file`.
- Added optional vector-detector attack persistence
  (`VectorSimilarityDetector(..., persistence_path=...)`): bounded JSONL store
  (10k attacks / 10k chars each), malformed-line tolerant, I/O-failure safe.

### Evaluation and benchmarks
- Added blind generalization snapshot `generalization_benchmark_v4.jsonl`
  (58 examples, 29/29 split, hash-pinned, frozen balanced-mode result
  tp/fp/tn/fn = 17/2/27/12); `load_generalization("v4"|"all")` and CLI choices
  updated. Blind v2/v3 remain untouched.
- Added LangChain-middleware and plugin test coverage (86% -> 89%+).

### Deployment
- Added a Helm chart (`deploy/helm/shadowshield/`) mirroring the compose
  hardening: digest-pinned image (install fails without it), read-only root
  filesystem, all capabilities dropped, no privilege escalation, non-root,
  seccomp, bounded /tmp emptyDir, required external secrets, policy-state PVC,
  resource limits, health probes.

### Supply chain and CI
- Added a strict, dynamically discovered CI matrix that resolves and audits every
  declared optional dependency stack, including development and combined `all`
  graphs, so new extras cannot silently bypass vulnerability scanning.
- Documented the lockfile auditing workflow (`pip-audit --no-deps
  --disable-pip`) in `requirements/README.md`.

## [0.6.3] — 2026-07-25

Post-launch reliability, request-intake, observability, performance, and
reproducible-release hardening. Detection signatures, thresholds, and frozen
benchmark behavior remain unchanged.

### Security and stability
- Fixed the documented session guard path so clean and blocked input/output turns
  are recorded exactly once before return or re-raise, restoring multi-turn and
  alignment-trace protection.
- Coalesced request-body frames into one bounded buffer, capped fragmentation,
  and added a total 15-second read deadline so authenticated slow/chunked bodies
  cannot hold every scan-admission slot indefinitely; protected non-preflight
  `OPTIONS` requests now authenticate before body or admission work.
- Made detector failures visible through bounded, content-free result metadata,
  audit/control events, benchmark integrity, and Prometheus counters. Strict mode
  now blocks on a detector error; other modes can opt into the same behavior.
- Kept authenticated 0.6.2 durable policy state restorable after the additive
  detector-error policy field, and made copied example environments fail before
  starting with known placeholder credentials.

### Performance and evaluation
- Cached immutable effective detector configuration in each engine, fast-rejected
  markdown-beacon parsing when no image opener exists, removed a million-call
  inner-loop `max()` hotspot, and avoided duplicate control-metric sorting.
  Audit prototypes measured roughly 5–12% faster short/ordinary scans and an
  additional ~8.6% improvement on 1 KiB anomaly-heavy paths, with generated and
  corpus-wide decision equivalence.
- Benchmark runs now warm detectors outside the latency clock, surface readiness
  and runtime failures, exit nonzero when evidence is unreliable, and report
  class-conditional per-category confusion metrics with 95% Wilson intervals.
  Public/frozen rows remain regression-only and were not used for tuning.

### Supply chain and CI
- Hash-locked the release build and production-container dependency graphs,
  pinned the Dockerfile frontend, removed the unused mandatory `tiktoken`
  dependency, audited both locks, and require byte-identical double builds.
- Upgraded maintained GitHub Actions to their SHA-pinned Node 24 generations and
  bounded every workflow job with an enforced timeout; strict project typing is
  isolated from incompatible syntax in optional third-party stubs.
- Container publication now refuses conflicting version/commit tags and existing
  release assets, while safely resuming only from an exact matching digest with
  verified revision/version labels and trusted exact-source provenance.

## [0.6.2] — 2026-07-25

Production hardening for failure recovery, durable state, release provenance,
repository governance, and honest blind evaluation.

### Security
- Replaced the predictable durable-policy temporary filename with an exclusive
  same-directory file, rejected final symlinks and non-regular state files, and
  added descriptor/revision checks around reads, migrations, backups, and atomic
  replacement. New POSIX state remains mode `0600`; existing POSIX modes are
  preserved.
- Removed inline event/style mutation from the site, enforced a hash-only CSP,
  expanded browser feature denial, isolated the opener, and added a permanent
  canonical `www`-to-apex redirect with static policy regression tests.
- Enabled Dependabot vulnerability updates and extended CodeQL scanning, while
  repository policy now rejects GitHub Actions that are not pinned by full SHA.

### Stability
- Coalesced concurrent failed Transformer and Vector initialization generations.
  The original loader receives its original exception, every waiter receives a
  fresh traceback-bounded exception, and a later request can retry safely.
- Added 16-caller failure-wave regressions covering single-load publication,
  unique exceptions, bounded tracebacks, readiness, and recovery, plus dedicated
  regressions for exceptions that sabotage copying, construction, or stringification.

### Supply chain and release safety
- Release containers now carry signed SLSA provenance and a signed CycloneDX
  SBOM in GHCR. The workflow reads both bundles back from OCI and constrains the
  repository, workflow, hosted runner, and exact source commit before completing.
- Python and container publication now accept only stable non-prerelease tags
  whose package version, checkout SHA, `main` ancestry, and exact-SHA green CI run
  all agree. The manual PyPI publication path was removed.
- Added digest-pinned Actionlint as a CI gate and bounded privileged release jobs.

### Evaluation
- Added the independently authored, integrity-pinned 40-row blind v3 snapshot and
  exposed `--generalization {v1,v2,v3,all}` (90 rows in `all`).
- The unchanged core scores v3 at 6/6/14/14 (TP/FP/TN/FN) and all snapshots at
  10/9/36/35. A frozen higher-recall candidate failed the predeclared FPR and
  balanced-accuracy gates and was discarded in full; no holdout-driven tuning ships.

## [0.6.1] — 2026-07-25

Production follow-through: concurrency correctness, key separation, honest
generalization benchmarks, readiness, and container supply-chain gates.

### Security
- Added an independent `SHADOWSHIELD_POLICY_STATE_KEY`. Production durable state
  now fails closed unless this key is explicit, at least 32 bytes, and distinct
  from scan, administrator, and policy-signing credentials.
- Bounded policy-state files before decoding/parsing and require a canonical
  lowercase SHA-256 MAC. Legacy signing-key state authentication remains available
  only under explicit local insecure mode; production never silently migrates it.
- Added `shadowshield migrate-policy-state` for a stopped, verified, backed-up,
  atomic 0.6.0-to-0.6.1 durable-state re-key. Oversized accepted policies are now
  rejected before they can write state that would fail the next startup.
- Digest-pinned the Python container base, added weekly dependency/Docker/Action
  updates, and made CI reject fixable high/critical image vulnerabilities while
  retaining a CycloneDX SBOM artifact.
- Added a release gate that scans before pushing the exact GHCR image and attaches
  its immutable digest plus SBOM to the GitHub Release; production Compose now
  requires that `image@sha256` reference instead of rebuilding mutable inputs.
  Publication also gates on an anonymous pull of that digest.

### Stability
- Made Transformer model loading single-flight and retryable after failed
  initialization; made Vector model/index publication atomic and synchronized
  concurrent self-hardening without holding the mutation lock during inference.
- Serialized Reporter flushes, bounded each flush to its entry snapshot, added
  finite opt-in retries, and added idempotent close/context-manager lifecycle
  accounting so racing records are sent or counted as dropped, never stranded.
- Added separate `/health` liveness and `/ready` readiness endpoints. Readiness
  never downloads models; explicit detector warmup supports fail-fast startup.

### Detection and evaluation
- Fixed high-confidence roleplay extraction, named-persona, forged-role-frame,
  system/developer-message override, and model-directed developer-mode cases while
  removing two broad false positives. The curated adversarial set moves from
  15/2/16/3 to 18/0/18/0 (TP/FP/TN/FN).
- Added two independently authored blind semantic snapshots and
  `shadowshield benchmark --generalization {v1,v2,all}`. Their intentionally
  difficult results remain visible: v1 recall 26.7% / FPR 13.3%; v2 recall 0% /
  FPR 10%. The public deepset core result is unchanged at 23.3% recall / 0% FPR.

## [0.6.0] — 2026-07-25

Operability, agentic guarding, and an open-core foundation.

### Added
- **Full control dashboard** (`shadowshield serve --control`) — a self-contained,
  no-CDN single-page console: live scan + threat feed, metrics/analytics (inline SVG),
  a config control panel (toggle detectors, switch mode, tune thresholds/weights,
  hot-swapped into the running shield), and a one-click benchmark runner.
- **Server hardening** — fail-closed API-key/Bearer auth, independent scan/admin
  credentials, configurable CORS, pre-parse body limits, bounded concurrency,
  browser security headers, and hidden framework schemas.
- **Content-free default audit events** — redacted logs now use a strict metadata
  allowlist and omit payload previews, matches, detector messages/metadata, and raw
  identities.
- **Prometheus `/metrics`** endpoint on the control server (monotonic scan/decision/
  severity/detector counters + latency quantile gauges).
- **Pull-based policy with a protection floor** (`shadowshield.core.policy`) — signed
  bundle verification, clamp-to-floor (always-on detectors, threshold ceiling), a
  degradation cap, authenticated and crash-durable anti-replay/last-known-good state,
  and fail-safe behavior. Exposed at `GET/POST /api/policy`.
- **Content-free reporter SDK** (`shadowshield.reporter`, `core.telemetry`) — opt-in,
  bounded, non-blocking export of scan *metadata* with no payload leakage by construction
  (identity/canary hashed, no `matched`/`preview`).
- **MCP tool-guard integration** (`shadowshield.integrations.ToolGuard`,
  `build_mcp_server`) — transport-agnostic allow/block verdicts for tool calls and
  untrusted tool results.
- **`shadowshield schema`** — emit the config JSON Schema for editor/CI validation.
- **`shadowshield owasp`** + `core.coverage` — honest OWASP LLM Top 10 (2025) coverage
  map (covered / partial / out-of-scope).
- **Adversarial benchmark** — `shadowshield benchmark --adversarial` over a harder bundled
  set (obfuscated/multilingual/indirect attacks + tricky hard negatives); publishes
  deliberately sub-100% numbers.
- **Span coverage** added to the exfiltration, jailbreak, and canary detectors.
- **GOVERNANCE.md** — public MIT-forever commitment for the engine.
- **Production container** — multi-stage, non-root image plus a read-only,
  capability-dropped, resource-bounded Compose service with mandatory independent
  scan/admin/policy secrets, durable policy state, and rotated logs.
- **Release gates** — Python 3.10–3.14 CI, an 80% coverage floor, declared-dependency
  audit, installed-wheel smoke test, real-model integration, and hardened-container
  startup/auth/body-limit smoke test. Third-party Actions are SHA-pinned.
- Strategy/research docs under `docs/`: UPGRADE_OPPORTUNITIES, MARKET_LANDSCAPE,
  SAAS_STRATEGY, PLAN_REVIEW, REPORTER_SDK_SPEC, OWASP_LLM_TOP10, NEXT_STEPS,
  PRODUCTION_READINESS.

### Notes
- Test count grew with suites for auth, control, policy, telemetry, spans, MCP, CLI, and
  the adversarial set. The multi-tenant SaaS backend remains intentionally unbuilt,
  gated behind design-partner validation (see docs/SAAS_STRATEGY.md).
- Findings, decoded segments, telemetry/event fields, rate-limit identity state, and
  judge work are bounded. Oversized input now blocks instead of releasing an
  unscanned suffix, and markdown-beacon parsing is linear without boundary bypasses.

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

[0.8.1]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.8.1
[0.8.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.8.0
[0.7.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.7.0
[0.6.3]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.6.3
[0.6.2]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.6.2
[0.6.1]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.6.1
[0.6.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.6.0
[0.5.1]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.5.1
[0.5.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.5.0
[0.4.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.4.0
[0.3.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.3.0
[0.2.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.2.0
[0.1.0]: https://github.com/0xsl1m/shadowshield/releases/tag/v0.1.0
