# Production readiness roadmap

**Baseline:** ShadowShield 0.6.0 · **Audit date:** 2026-07-25

This roadmap is the release gate for the Python library and the optional HTTP
control plane. A checked item is implemented and locally verified; unchecked
items require an explicit operator or maintainer decision before public launch.

## Current readiness

| Area | State | Evidence / remaining action |
|---|---|---|
| Correctness | Ready | Full unit/integration suite; strict mypy; Ruff lint and format |
| Packaging | Ready | Isolated sdist/wheel build, Twine metadata check, installed-wheel CI smoke test |
| Runtime security | Ready with configuration | API-key/Bearer auth, restricted CORS, protection floor, non-root read-only container |
| Supply chain | Ready | PyPI OIDC publishing and CI dependency audit |
| Observability | Ready for single process | Content-free telemetry, Prometheus endpoint, bounded in-memory event feed |
| Detection quality | Beta | Adversarial baseline: 83.3% recall, 11.1% FPR; tune in shadow mode before enforcement |
| Scale / HA | Not yet | Counters, events, configuration, and rate limits are process-local |
| Streaming | Not yet | Outputs must be buffered before scanning |

## P0 — release blockers (completed)

- [x] Repair control-plane syntax and restore test collection.
- [x] Make optional-dependency tests and typing deterministic with or without MCP installed.
- [x] Enforce an 80% branch-aware coverage floor (current local result: 85%).
- [x] Test every declared Python runtime, 3.10 through 3.14, in CI.
- [x] Build and validate both distribution formats and smoke-test the installed wheel.
- [x] Audit declared dependencies in CI (local audit: no known vulnerabilities).
- [x] Ship a non-root, health-checked, read-only Docker deployment with mandatory Compose auth.

## P1 — launch procedure (operator-owned)

- [ ] Set a high-entropy `SHADOWSHIELD_API_KEY`; terminate TLS at a trusted ingress.
- [ ] Set an explicit CORS allowlist or leave CORS disabled.
- [ ] Run the adversarial and application-specific eval sets in permissive/shadow mode.
- [ ] Choose thresholds from measured false-positive cost; record the accepted baseline.
- [ ] Connect Prometheus and content-free telemetry; alert on error, block-rate, and latency shifts.
- [ ] Load-test representative payload sizes and concurrency on the target instance class.
- [ ] Pin the image by digest, scan it, generate/store an SBOM, and rehearse rollback.
- [ ] Protect the PyPI GitHub Environment with required reviewers before publishing.

## P2 — next engineering milestones

1. Add a rolling-window streaming scanner that blocks before unsafe output is emitted.
2. Move rate limits, event history, and metrics aggregation to shared external stores for multi-worker HA.
3. Add readiness/startup probes that validate optional model assets when ML detectors are enabled.
4. Publish signed container images, provenance attestations, and an SBOM from the release workflow.
5. Calibrate detector scores on a larger independently sourced corpus and publish confidence intervals.
6. Add soak, concurrency, and fault-injection tests for reporters, judges, and hot policy updates.

## Go / no-go gates

Go for a library release when CI, package validation, dependency audit, and the
built-in benchmark are green. Go for a single-instance control-plane deployment
only after every P1 item is complete. Multi-worker or streamed-response
deployments are no-go until the corresponding P2 state-sharing and streaming
controls land.
