# Spec — Reporter SDK, Content-Free Telemetry & Protection-Floor Config

**Date:** 2026-06-16 · **Status:** design spec (build the OSS-side now; backend gated) · **Parents:** [SAAS_STRATEGY.md](SAAS_STRATEGY.md) · [PLAN_REVIEW.md](PLAN_REVIEW.md)

These three pieces are the cheap, reversible builds the review endorsed *now* — they serve the OSS
project on their own **and** become the SaaS backplane later, without committing to multi-tenant
infra. `/metrics` (the Prometheus endpoint) already shipped in `control.py`. This spec covers the
remaining two: the **content-free reporter SDK** and **pull-based config with a protection floor**.

Design rule throughout: **safety and privacy are enforced by types/schema, not by configuration.**
The review's two scariest findings — telemetry leaking payloads, and a pushed policy disabling
protection fleet-wide — are both "config got it wrong" failure classes. We remove the config as the
control and make the safe behavior structural.

---

## 1. Content-free telemetry schema

### Goal
A shield can emit *metadata* about scans to an external collector such that **no field can carry raw
payload content by construction.** "We never see your payloads" must be a property of the type, not a
promise about a redaction flag.

### Closed leak surface (implemented)
The in-memory event dict in `control.py` now uses the same content-free boundary as exported
telemetry: no matched substring, raw identity, payload preview, or detector message is retained.
It stores only bounded threat metadata, payload length, and whether an identity was supplied.

### Proposed type (separate from the local event)
A distinct, export-only dataclass — call it `TelemetryEvent` — with **only** these fields:

| Field | Type | Notes |
|---|---|---|
| `schema_version` | `int` | bump on any field change |
| `ts` | `float` | unix seconds |
| `direction` | `"input" \| "output"` | |
| `decision` | enum value | allow/flag/sanitize/block/escalate |
| `severity` | enum label | none…critical |
| `score` | `float` | rounded |
| `blocked` | `bool` | |
| `latency_ms` | `float` | |
| `identity_hash` | `str \| None` | `sha256(tenant_salt + identity)`, never raw |
| `threats` | `list[ThreatMeta]` | see below |
| `text_len` | `int` | length only — never the text |
| `text_sha256` | `str \| None` | optional dedup hash, off by default |

`ThreatMeta` (per finding) carries **only**: `category`, `detector`, `severity`, `score`,
`span_len` (int, not the substring), `span_offset` (int), and `canary_id_hash` (`str | None` —
a hash of the canary identifier, never its value). **No `matched`, no decoded payload, no message
interpolated with user text.**

### Enforcement
- `TelemetryEvent`/`ThreatMeta` are frozen dataclasses with typed fields — there is no `str` field
  that can hold arbitrary payload text. A reviewer (or a unit test) can verify the leak surface by
  reading the type.
- A single `to_telemetry(result, *, tenant_salt) -> TelemetryEvent` mapper is the **only** sanctioned
  path from a `ScanResult` to an exportable event. The mapper drops `matched`, hashes identity and
  canary ids, and copies span *lengths/offsets* not content.
- A test asserts that for a `ScanResult` whose payload contains a known secret, the serialized
  `TelemetryEvent` JSON does **not** contain that secret (a property test over random payloads).

### Reporter SDK (OSS side)
A small, dependency-light `Reporter`:

- `Reporter(endpoint, api_key, *, tenant_salt, sample_rate=1.0, max_batch=200,
  queue_max=10_000)`.
- `attach_reporter(shield, reporter)` observes every scan and enqueues a `TelemetryEvent`.
  Enqueue is **non-blocking**; application lifecycle code or a scheduler calls `flush()` to
  batch and POST. The current implementation intentionally owns no background thread.
- **Fail-open for the app, fail-closed for data:** if the collector is down, drop from a bounded
  queue (never block the request path, never grow memory). If `tenant_salt` is unset, refuse to send
  `identity_hash` at all.
- Opt-in only. Off unless a reporter is explicitly attached or `SHADOWSHIELD_REPORT_URL` is set.
- **Heartbeat for the adoption North Star:** an optional, anonymous, opt-out daily heartbeat
  (`{anon_install_id, version, num_services_seen}`) so "orgs running in ≥2 services" is measurable
  without payload data. Document it plainly; make opt-out a one-liner.

---

## 2. Pull-based config with a protection floor

### Goal
Let the (future) control plane push policy to a fleet **without** ever being able to turn protection
off — even if the policy service or its signing key is compromised.

### Threat model (the review's #1 failure mode)
A compromised signing key or control plane pushes a bundle setting `block_threshold = 1.0` and
`enabled = false` for every detector, fleet-wide, on the next poll. A security control with a
vendor-operated kill switch is not a security control.

### Design
1. **Local protection floor (engine-enforced, not policy-supplied).** The shield is constructed with
   a `ProtectionFloor` that a pushed policy **cannot** weaken:
   - a set of **always-on detectors** (default: `prompt_injection`, `canary_leak`) that no bundle can
     disable;
   - a **max block_threshold ceiling** a bundle may not exceed (e.g. ≤ 0.80);
   - a **max degradation delta** — a bundle may not lower aggregate protection more than X vs. the
     shield's *local baseline* config.
   The floor lives in local config / env, set by the *customer*, not the control plane.
2. **Signed bundles, verified locally.** Bundles are signed (detached signature, asymmetric key);
   the shield ships with the publisher's public key and verifies before applying. An unsigned or
   badly-signed bundle is rejected.
3. **Clamp, don't trust.** On applying a bundle, the engine **intersects** it with the floor: any
   field that would breach the floor is clamped to the floor value, and the event is recorded.
4. **Fail-safe, never fail-open.** If a bundle fails signature/floor checks, the shield **keeps its
   last-known-good config** and emits a high-severity `policy_rejected` telemetry event + local log.
   It never falls back to "no protection."
5. **Auditable.** Every applied bundle is logged with its hash, signer key fingerprint, and the
   clamped diff. `GET /api/policy` on the local control server shows the active bundle + provenance.
6. **Pull, not push.** Shields poll on an interval (default 60s, jittered); the control plane never
   needs inbound access to customer infra.

### Sketch
```python
@dataclass(frozen=True)
class ProtectionFloor:
    always_on: frozenset[str] = frozenset({"prompt_injection", "canary_leak"})
    max_block_threshold: float = 0.80
    max_degradation_delta: float = 0.20  # vs local baseline

def apply_bundle(local: ShieldConfig, floor: ProtectionFloor,
                 bundle: PolicyBundle, pubkey: bytes) -> ShieldConfig:
    if not verify_signature(bundle, pubkey):
        raise PolicyRejected("bad signature")           # -> keep last-known-good
    candidate = merge(local, bundle.config)
    clamped = clamp_to_floor(candidate, floor)          # always-on, ceiling, delta
    if breaches_delta(local, clamped, floor):
        raise PolicyRejected("degrades protection beyond floor")
    return clamped
```

### Tests to ship with it
- A bundle that disables `prompt_injection` → detector stays on (clamped), `policy_rejected` or
  clamp event recorded.
- A bundle with `block_threshold = 1.0` → clamped to `max_block_threshold`.
- A bundle with a bad/missing signature → rejected, last-known-good retained, never fail-open.
- A floor-breaching delta → rejected.

---

## Build order (and what stays gated)

**Now (OSS, reversible, no backend):**
1. `TelemetryEvent`/`ThreatMeta` types + `to_telemetry()` mapper + the no-leak property test.
2. `Reporter` + `shield_with_reporter()` + bounded async queue; anonymous heartbeat.
3. `ProtectionFloor` + `apply_bundle()` clamp/verify logic + tests (the *consumer* side of policy —
   safe to build before any server pushes anything).
4. ✅ Already shipped: `/metrics` Prometheus endpoint.

**Gated behind the design-partner pre-sell (do NOT build yet):**
5. The hosted ingestion API, multi-tenant store, policy signing service, compliance-report
   generator, dashboards, RBAC/SSO.

This sequence means the OSS gains real, useful capabilities (export metadata to *any* collector,
floor-protected config) immediately, while the multi-tenant SaaS stays gated on validated demand —
exactly the discipline the review demanded. None of (1)–(4) commits us to the SaaS; all of them make
the SaaS cheaper and safer to build if the pre-sell clears.
