# ShadowShield — Multi-Model Plan Review (Synthesis)

**Date:** 2026-06-16 · **Inputs reviewed:** SAAS_STRATEGY.md, MARKET_LANDSCAPE.md, UPGRADE_OPPORTUNITIES.md, prototype code
**Panel:** four independent reviewers across three models —
(1) VC / moat skeptic [opus], (2) Principal security engineer [sonnet],
(3) Pre-mortem / devil's advocate [opus], (4) Pragmatic AppSec buyer [haiku].

This synthesis records where the panel **agreed**, where it **disagreed**, the **severity-ranked risks**,
and the **concrete changes** to make. It is deliberately critical — the reviewers were told to find what's wrong.

---

## Headline

The engine and the open-core *instinct* are sound; the panel's confidence in the **specific SaaS plan as written
is low**, and it converges hard on one correction: **the chosen wedge (centralized audit + search) is the weakest
link**, and it should be re-sequenced behind **compliance reporting** and/or **fleet policy push** — validated with
paying design partners *before* any backend is built. Two reviewers independently reached "sell the wedge before
building it" as the single highest-value next move.

---

## Strong consensus (all or most reviewers)

1. **The audit-search wedge is squeezed on three sides — free (self-hosted OSS), bundled (incumbent platforms),
   and already-bought (the customer's SIEM/Datadog).** The buyer reviewer was blunt: "Datadog answers that in 5
   seconds for the cost I'm already paying." All four flag this; the strategy doc itself names it then leads with
   the wedge anyway.
2. **Re-sequence the wedge.** The buyer ranked willingness-to-pay: **compliance reporting #1** (OWASP/ISO 42001/EU
   AI Act Art. 15 attestations that save the CISO audit hours), **fleet policy push #2** ("tune one detector across
   12 services at 2am without a deploy"), **audit-search #3**, alerting #4. VC and pre-mortem both independently
   nominate **fleet policy push** as the more defensible wedge because it's an *active control a passive SIEM and a
   single-vendor platform can't replicate across a heterogeneous fleet*.
3. **Prove adoption with deployed installs, not stars.** The docs cite competitors' star counts but never
   ShadowShield's own traction. VC: "that silence is damning." Instrument an anonymous reporter heartbeat and treat
   "orgs running in ≥2 services" as the only North Star; gate backend work on it.
4. **Sell before you build.** Get 3-5 design partners running the OSS to commit *money or signed LOIs against a
   specific paid capability* before building multi-tenant infra. One quarter of pre-selling is the cheapest test of
   the most expensive assumption.
5. **MIT-forever pledge for the engine.** Pre-commit publicly; AGPL is the only sanctioned copyleft hedge, never a
   permissive→source-available flip. Removes the panic-relicense failure mode before it can occur.
6. **The privacy claim is not airtight as designed** (see risks). "We never see payloads" must be true *by schema
   construction*, not by a config flag.
7. **Benchmarks must be presented honestly and defended proactively.** "100% recall / 0% FP" on the bundled 75-set
   reads as a production claim and will be attacked with HarmBench/JailbreakBench. Publish adversarial numbers
   yourself; commission an external red-team before monetizing.

---

## Key disagreement (worth your judgment)

**What should the wedge be — and the trap inside the answer.**

- The panel pushes toward **fleet policy push** as the most defensible, hardest-to-bundle wedge (active control,
  cross-vendor).
- BUT the security reviewer names **fleet policy push as simultaneously the single most dangerous failure mode**: a
  compromised signing key could push a bundle that disables protection across every customer's fleet at once.

So the most *commercially* compelling wedge is also the most *security-critical* one. These must be solved together:
if you lead with policy push, the protection-floor hardening (below) is a prerequisite, not a follow-up.
Compliance reporting is the lower-risk lead that the buyer would pay for *today* and that no SIEM auto-generates —
it may be the better *first* paid feature, with policy push as the expansion once hardened.

---

## Severity-ranked risks

| # | Risk | Severity | Raised by | Mitigation |
|---|---|:--:|---|---|
| 1 | **Fleet policy push can disable protection fleet-wide** if signing key/control plane is compromised | Critical | Security | Engine enforces a minimum detector baseline that policy *cannot* override; cap per-scan degradation delta; alert + revert to last-known-good on suspicious bundles; air-gap signing from ingestion; automated key rotation |
| 2 | **Wrong wedge** — audit-search isn't willing-to-pay; loses to SIEM + bundle | Critical | All four | Re-sequence to compliance reporting / policy push; pre-sell to design partners before building |
| 3 | **No proven OSS adoption funnel** — SaaS thesis rests on a multi-service wall few may reach | High | VC, Pre-mortem | Instrument deployed installs; North Star = orgs in ≥2 services; gate backend on it |
| 4 | **Privacy leaks in telemetry schema** — `matched`/`span` snippets, raw `identity`, un-redacted `preview`, canary values | High | Security, Buyer | Field-level schema enforcement: drop or store length-only spans, hash identity (per-tenant salt), redact preview through same pipeline, canary-ID hash only |
| 5 | **Incumbent + model-vendor pincer** — platforms bundle equivalent free; OpenAI/Anthropic ship native guardrails making 3rd-party guards feel redundant for first-party traffic | High | VC, Pre-mortem | Anchor on the cross-vendor / multi-model / agent-fleet seam no single platform or model owner controls |
| 6 | **Multi-tenant telemetry store is a tier-1 attack target** (metadata alone reveals who's under attack) | High | Security | Per-tenant keys, server-derived tenant IDs (not client-supplied), formal ingestion threat model, breach plan before first paid customer |
| 7 | **Resourcing trilemma** — one small team can't do OSS + multi-tenant SaaS + enterprise sales | High | VC, Pre-mortem | Don't start backend until ≥3 paying design partners; ring-fence guaranteed weekly engine-maintenance time |
| 8 | **Trust blow** — a public bypass or a telemetry breach ends a security brand | High | Pre-mortem, Security | External red-team + public bug bounty before monetizing; adversarial benchmarks published proactively |
| 9 | **Enterprise table-stakes missing** — SOC2 Type II, latency SLA, on-prem control plane, transparent pricing, data export | Med-High | Buyer | Treat as launch requirements for the paid tier, not later; publish a price floor + variable metric (don't be "contact sales only") |

---

## Concrete changes to the plan (actionable)

**Strategy / sequencing**
1. **Lead the SaaS with compliance reporting** (buyer's #1, lowest security risk), position **fleet policy push** as
   the expansion wedge, demote audit-search to a supporting feature.
2. **Insert a "pre-sell" gate:** one quarter, zero backend, collect money/LOIs from 3-5 design partners against a
   *named* capability. Re-found the product on whatever actually clears that bar.
3. **Add a deployed-adoption North Star** (orgs running OSS in ≥2 services via anonymous heartbeat) and make backend
   construction explicitly conditional on it.
4. **Publish an MIT-forever commitment** for the engine in the repo.
5. **Reframe the moat** from "audit dashboard" to "vendor-neutral control across heterogeneous (OSS + hosted +
   multi-cloud) agent fleets" — the seam incumbents and model vendors structurally can't own.

**Engineering (before any backend)**
6. **Harden policy bundles against protection-disable:** enforce a non-overridable minimum baseline in the engine,
   cap degradation delta, cryptographically audit every applied bundle, revert-on-suspicion (fail-safe, not
   fail-open). *Prerequisite for shipping policy push at all.*
7. **Make "no payloads" a schema guarantee:** remove or store length-only `matched`/`span`, hash `identity` with a
   per-tenant salt, run `preview` through redaction (or drop it), canary telemetry carries only a hashed ID.
8. **Specify tenant isolation up front:** server-derived tenant IDs, per-tenant encryption keys, documented
   ingestion-API threat model — decided before the first event is written.

**Credibility / GTM**
9. **Publish adversarial benchmarks** (HarmBench/JailbreakBench/TensorTrust) with the honest gaps, alongside the
   in-bundle numbers; commission an external red-team and stand up a bug bounty before monetizing.
10. **Ship enterprise table-stakes as launch criteria:** SOC2 Type II, published p50/p95/p99 latency (esp. policy
    fetch <10ms), a drop-in on-prem/self-managed control plane (Docker/Helm), transparent price floor + metric, and
    a full data-export path.

---

## Verdicts

| Reviewer | Verdict | Confidence |
|---|---|:--:|
| VC / moat | **Pass-unless-X** — needs hard adoption metrics + ≥2 paying design partners on a wedge that beats SIEM & bundle | 4/5 |
| Security | **Sound concept, needs rework** in policy-signing, telemetry schema, tenant isolation before backend | 4/5 |
| Pre-mortem | Most likely death = **wrong wedge + incumbent free-bundling**; de-risk by pre-selling the wedge | — |
| Buyer | **Adopt OSS only** for now; flips to "adopt + pay" on SOC2 + worked compliance report + a design-partner case study | — |

**Synthesized bottom line:** keep building the OSS engine and its credibility (this is the real asset and the moat),
publish the MIT-forever pledge, and **do not build the multi-tenant backend yet**. Spend the next quarter pre-selling
a re-sequenced wedge (compliance reporting first, policy push second) to design partners, and instrument deployed
adoption. The cheap, reversible steps that serve both OSS and a future SaaS — the redacted reporter SDK (built to the
hardened schema above), `/metrics` export, and pull-based config with a protection-floor — are the right next builds.
