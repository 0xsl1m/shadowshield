# Governance & Licensing Commitment

## The engine is MIT, and stays MIT

The ShadowShield **engine** — everything under `src/shadowshield/` (detectors, responders,
engine, config, CLI, the single-node control dashboard, the reporter SDK, the policy /
protection-floor logic) — is licensed under the [MIT License](LICENSE) and **will remain
under MIT**. We will not relicense the engine to a source-available license (BSL, SSPL,
Elastic License, or similar).

This is a deliberate, public commitment. The recent history of the space — Elastic →
OpenSearch, HashiCorp → OpenTofu, Redis → Valkey — shows that relicensing a previously
permissive core to a source-available license reliably triggers a community fork and a
durable loss of trust that a later reversion does not undo. For a security tool, trust is
the product. We would rather forgo a licensing "hedge" than spend that trust.

If a copyleft hedge against hyperscaler resale ever becomes genuinely necessary, the
**only** lever we will consider is **AGPLv3** — an OSI-approved, still-open-source license
(the path Grafana took) — and never a non-OSI source-available flip.

## What may be commercial

A future hosted, multi-tenant **control plane** (centralized audit retention and search,
cross-service dashboards, alerting, RBAC/SSO, fleet policy push, compliance reporting) may
be offered as a separate, proprietary commercial product. That is the open-core boundary
(à la GitLab EE / Grafana Enterprise): the value is captured at the multi-tenant
control-plane edge, **not** by restricting the engine. The engine never depends on the
commercial product, and everything you need to run ShadowShield in production stays MIT and
self-hostable.

## Security posture commitments

- **No telemetry by default.** The reporter SDK is opt-in; nothing phones home unless you
  attach it. When attached, it emits content-free metadata only (see
  [docs/REPORTER_SDK_SPEC.md](docs/REPORTER_SDK_SPEC.md)).
- **No remote kill switch.** Pushed policy can never disable protection below a
  locally-set floor (see `shadowshield.core.policy`).
- **Honest benchmarks.** We publish false-positive rates next to detection rates, and ship
  deliberately difficult public generalization snapshots whose misses remain visible.
  Public/frozen sets are regression gates only; new detector candidates require separately
  sourced development data and a fresh sealed evaluation.
