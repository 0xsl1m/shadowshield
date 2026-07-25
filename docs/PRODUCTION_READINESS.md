# Production readiness roadmap

**Baseline:** ShadowShield 0.6.1 · **Audit date:** 2026-07-25

This roadmap is the release gate for the Python library and the optional HTTP
control plane. A checked item is implemented and locally verified; unchecked
items require an explicit operator or maintainer decision before public launch.

## Current readiness

| Area | State | Evidence / remaining action |
|---|---|---|
| Correctness | Ready | Full unit/integration suite; strict mypy; Ruff lint and format |
| Packaging | Ready | Isolated sdist/wheel build, Twine metadata check, installed-wheel CI smoke test |
| Runtime security | Ready with configuration | Early API-key/Bearer auth, body limits, restricted CORS, immutable protection floor, non-root read-only container |
| Supply chain | Ready | Digest-pinned base, SHA-pinned Actions, PyPI OIDC, pre-push image vulnerability gate, anonymously verified GHCR digest, release-attached CycloneDX SBOM |
| Observability | Ready for single process | Content-free telemetry, Prometheus endpoint, bounded in-memory event feed |
| Detection quality | Beta | Curated adversarial: 100%/0% FPR; blind v1: 26.7%/13.3%; blind v2: 0%/10%; deepset core: 23.3%/0% |
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
- [x] Bound HTTP bodies, decoded segments, findings, event pages, and rate-limit identity state.
- [x] Reject unauthenticated requests before parsing and fail closed on exposed keyless startup.
- [x] Keep control-plane events and default audit logs content-free by structural allowlist.
- [x] Block oversized inputs rather than returning an unscanned suffix as safe text.
- [x] Regress the markdown-beacon ReDoS and bound hung-judge admission.
- [x] Gate every PR on an authenticated, non-root, read-only container smoke test.
- [x] Split scan/admin credentials and authenticate, fsync, and strictly validate durable
  signed last-known-good policy state.
- [x] Bound scan concurrency and ensure permanently hung judges cannot block shutdown.
- [x] Pin every third-party GitHub Action to a reviewed commit SHA.
- [x] Separate policy-state authentication from policy signing and reject all
  pairwise-equal production credentials.
- [x] Add a verified offline 0.6.0 policy-state migration and reject state that
  would exceed the bounded restart parser before changing the live policy.
- [x] Add non-loading readiness probes and explicit fail-fast detector warmup.
- [x] Make Transformer loading and Vector mutation single-flight/transactional.
- [x] Bound Reporter flush/retry/close lifecycle under concurrency.
- [x] Pin the base image by digest, gate the exact release image on Trivy, publish
  it to GHCR, verify an anonymous digest pull, and attach its immutable digest
  plus CycloneDX SBOM to the release.

## P1 — launch procedure (operator-owned)

- [ ] Set independent high-entropy `SHADOWSHIELD_API_KEY`,
  `SHADOWSHIELD_ADMIN_KEY`, `SHADOWSHIELD_POLICY_KEY`, and
  `SHADOWSHIELD_POLICY_STATE_KEY` values; terminate TLS at a trusted ingress.
- [ ] When upgrading a 0.6.0 durable volume, stop all writers, snapshot the
  volume, run `shadowshield migrate-policy-state`, retain its verified backup,
  and confirm the restored policy/version before accepting traffic.
- [ ] Set an explicit CORS allowlist or leave CORS disabled.
- [ ] Run the adversarial and application-specific eval sets in permissive/shadow mode.
- [ ] Choose thresholds from measured false-positive cost; record the accepted baseline.
- [ ] Connect Prometheus and content-free telemetry; alert on error, block-rate, and latency shifts.
- [ ] Load-test representative payload sizes and concurrency on the target instance class.
- [ ] Record the deployed image digest and CI SBOM, then rehearse backup/restore
  and rollback against the target environment.
- [ ] Protect the PyPI GitHub Environment with required reviewers before publishing.

## P2 — next engineering milestones

1. Add a rolling-window streaming scanner that blocks before unsafe output is emitted.
2. Move rate limits, event history, and metrics aggregation to shared external stores for multi-worker HA.
3. Publish signed container images and provenance attestations from the release workflow.
4. Calibrate detector scores on a larger independently sourced corpus and publish confidence intervals.
5. Add multi-hour soak and network fault-injection tests for reporters, judges, and hot policy updates.
6. Split the current administrator credential into narrower observe and mutation scopes.
7. Design cross-process model/index coordination and durable Reporter spooling.

## Go / no-go gates

Go for a library release when CI, package validation, dependency audit, and the
built-in benchmark are green. Go for a single-instance control-plane deployment
only after every P1 item is complete. Multi-worker or streamed-response
deployments are no-go until the corresponding P2 state-sharing and streaming
controls land.
