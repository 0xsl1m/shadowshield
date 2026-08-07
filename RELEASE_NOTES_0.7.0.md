ShadowShield 0.7.0 — comprehensive audit remediation plus streaming, calibration, parallel, gateway, and middleware-breadth features from the [2026-08-05 upgrade plan](docs/UPGRADE_PLAN_2026-08-05.md).

## Highlights

- **Gateway mode (zero code changes).** `shadowshield proxy --upstream https://api.openai.com` puts the shield in front of any OpenAI-compatible endpoint: chat messages scanned pre-flight (blocked requests return an OpenAI-style `403` and never reach the upstream), completions scanned post-flight, and malicious **SSE streams cut mid-flight** with a conventional `finish_reason="content_filter"` chunk. Embed in-process instead with the new pure-ASGI `ShieldASGIMiddleware`.
- **StreamScanner.** Scan a completion *while it streams* — bounded memory, carry-over window so split signatures still match, terminal BLOCK/ESCALATE returned the moment the stream must stop (`shield.stream_scanner()`).
- **Middleware breadth.** `ShieldedAnthropicClient` (incl. `system` prompt and text blocks), `shielded_completion`/`ShieldedLiteLLM`, and RAG guardrails: `scan_retrieved_chunks` with drop/keep/raise policies plus duck-typed LlamaIndex/Haystack retriever wrappers.
- **Score calibration.** Isotonic calibration (`IsotonicCalibrator`, `fit_isotonic`, `fit_from_examples`), engine hook, `benchmark --calibration PATH` raw-vs-calibrated view, and a new `shadowshield calibrate` command.
- **Opt-in parallel detector fan-out** (`parallel_detectors: true`): identical verdicts/ordering/error accounting; measured ~3x wall-clock speedup with three 20 ms detectors.
- **Operations.** Control-plane package split, config hot-reload (`POST /api/reload`), vector-detector attack persistence, and a hardened Helm chart (`deploy/helm/shadowshield/`) mirroring the compose hardening.
- **Blind benchmark v4.** New 58-example snapshot (indirect tool-result, multilingual, semantic-pretext): 58.6% recall / 6.9% FPR balanced; 148-row aggregate 36.5% / 14.9% — gaps remain public by design.

## Security fixes

- **M-1 (behavior change): unsigned policy bundles now fail closed.** `apply_bundle` rejects unsigned bundles when no verifier is configured unless the caller explicitly passes `allow_unsigned=True`. Deployments relying on silent unsigned bundles must opt in.
- Telemetry reporter requires an HTTPS endpoint unless `allow_insecure_endpoint=True` (or a custom transport); queue-overflow and delivery-failure warnings added.
- Sanitizer merges overlapping/adjacent redaction spans (categories reported as `a|b`).
- Fixed a request-body replay hang in the shared HTTP middleware that stalled `StreamingResponse` disconnect listeners with fabricated empty bodies.

## Verification

433 tests passing (2 opt-in model tests skipped), 88% coverage, ruff + strict mypy clean (67 source files). Container image digest and SBOM are attached to this release by the container-release workflow.
