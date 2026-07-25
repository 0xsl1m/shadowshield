# ShadowShield — Market Landscape & Positioning

**Date:** 2026-06-16 · **Status:** strategy input, not a commitment · **Companion:** [SAAS_STRATEGY.md](SAAS_STRATEGY.md)

Researched across competitor products, 2024–2026 funding/M&A, market sizing, open-core
monetization comps, and buyer/compliance drivers. Sources are listed at the end; figures
carry their dates because this market moves monthly.

---

## Executive summary

1. **The independent vendor tier just disappeared.** Through 2025 nearly every standalone
   AI-security pure-play was acquired into a platform: Robust Intelligence (Cisco, 2024),
   Protect AI (Palo Alto, Jul 2025, est. $650–700M), Lakera (Check Point, Sep 2025, ~$300M),
   Prompt Security (SentinelOne, Aug 2025, ~$250M), CalypsoAI (F5, Sep 2025, $180M), Aporia
   (Coralogix, Dec 2024). That validates the category — and leaves a **gap for a credible,
   independent, open-source guardrail** that isn't bundled into one vendor's security cloud.

2. **The open-source field is thinner than it looks.** The most-cited OSS guards are either
   single-vendor funnels (LLM Guard / Rebuff → now Palo Alto; Rebuff archived May 2025),
   eval/red-team tools rather than runtime guards (promptfoo — being acquired by OpenAI;
   Giskard), classifiers without a full engine (Meta Prompt Guard 2), or dormant (Vigil).
   Few combine layered runtime detection **+** active response **+** agent-awareness in one
   MIT package. That is ShadowShield's lane.

3. **The buyer is the CISO, and the trigger is compliance + agents.** AI risk is now the #1
   security priority, but only ~41% of organizations have runtime guardrails and only ~21%
   can secure the AI agents they've already deployed. The forcing functions are OWASP LLM
   Top 10 (prompt injection = LLM01, two editions running), the EU AI Act (GPAI obligations
   live Aug 2025; high-risk Aug 2026), NIST AI RMF + GenAI Profile, and ISO/IEC 42001.

4. **The money is in the control plane, not the filter.** The OSS engine wins adoption; the
   paid product is org-wide visibility, retention, governance, and fleet policy — the same
   open-core boundary Grafana/GitLab/Sentry monetize. (Detailed in the companion doc.)

---

## The consolidation wave (why timing favors an independent)

| Target | Acquirer | Announced | Price | Folded into |
|---|---|---|---|---|
| Robust Intelligence | Cisco | Aug 2024 | undisclosed | Cisco AI Defense |
| Aporia | Coralogix | Dec 2024 | ~$50M (reported) | Coralogix AI Center |
| Protect AI (owns LLM Guard, Rebuff) | Palo Alto Networks | Apr 2025 (closed Jul 2025) | est. $650–700M (Jefferies; undisclosed officially) | Prisma AIRS |
| Prompt Security | SentinelOne | Aug 2025 | ~$250M | Singularity |
| CalypsoAI | F5 | Sep 2025 | $180M | F5 AI Guardrails / AI Red Team |
| Lakera | Check Point | Sep 2025 | ~$300M | Check Point AI CoE |
| promptfoo (eval/red-team) | OpenAI | Mar 2026 (announced) | undisclosed | — |

**Read:** buyers are large platform vendors absorbing AI security into their suites. Customers
who don't want to standardize on Palo Alto / Cisco / Check Point / SentinelOne — or who want a
self-hostable, auditable, vendor-neutral layer — now have **fewer independent options**, and
almost none that are genuinely open source with a full engine. The strategic narrative writes
itself: *"the open, independent AI-security layer in a market that just got swallowed by the
incumbents."*

---

## Competitive landscape

### Open-source

| Project | Type | Input/Output | Agent / tool-call aware | Active response | License | Note |
|---|---|---|---|---|---|---|
| **ShadowShield** | Runtime guard | Both | Yes (tool guard, canary, alignment audit) | sanitize/isolate/block | MIT | Layered; spotlighting as an action |
| LLM Guard | Runtime guard | Both | Limited | redact/block | MIT | Now Palo Alto; ~2.5k★ |
| NeMo Guardrails | Programmable rails | Both | Yes (Colang flows) | block | Apache-2.0 | ~5.6k★; heavier, DSL |
| Guardrails AI | Validator framework | Both | Limited | fix/reask/block | Apache-2.0 | ~6.6k★; Hub validators |
| Meta Prompt Guard 2 / LlamaFirewall | Classifier + orchestrator | Both | Yes (AlignmentCheck) | block | MIT code / Llama license (models) | Strong, but model-license strings attached |
| Rebuff | PI detector | Input | No | detect | Apache-2.0 | **Archived May 2025** |
| Vigil | PI/jailbreak scanner | Both | No | detect | — | Alpha, dormant |
| promptfoo | Eval / red-team | n/a | tests agents | n/a (offline) | MIT | ~13k★; **OpenAI acquiring 2026** |
| Giskard | Eval / red-team | n/a | tests agents | n/a (offline) | Apache-2.0 | Hub = paid |

### Commercial (mostly now inside platforms)

| Vendor | Focus | Deployment | Now part of |
|---|---|---|---|
| Lakera Guard | Runtime guard, <50ms, 100+ langs | SaaS / self-host | Check Point |
| Protect AI | Model scan + red team + runtime | Platform | Palo Alto (Prisma AIRS) |
| Prompt Security | Runtime + MCP gateway | SaaS / on-prem / browser | SentinelOne |
| HiddenLayer | Model scan + AIDR runtime | Platform | Independent |
| Robust Intelligence | AI firewall + algorithmic red team | Platform | Cisco AI Defense |
| Arthur Shield | LLM firewall + agent governance | SaaS / on-prem | Independent |
| CalypsoAI | Inference defense + agentic red team | Platform | F5 |
| WhyLabs/LangKit | Observability/metrics | SaaS / OSS | Independent |

**Differentiation that actually matters** (per practitioner/analyst commentary): inline
**latency** (200–300ms budget; Lakera advertises <50ms), **false-positive rate** (2025 target
<2%; high FPR is the #1 reason teams rip guardrails out), **agent support** (the 2026
battleground — tool-call validation, scope/budget enforcement), and **benchmarked, empirical
accuracy** over marketing claims. ShadowShield already leans into FPR honesty (0% FP on hard
negatives in-bundle) and agent-awareness — those should be the headline, with published,
reproducible benchmarks as the proof.

---

## Market size (mind the definitions)

The category labels vary ~10x; cite carefully.

- **AI TRiSM** (closest match to "securing AI / guardrails") — **$2.34B (2024) → $7.44B by 2030,
  21.6% CAGR** (Grand View Research, Apr 2025). *Most credible, well-defined figure.*
- **LLM Security Platforms** — $2.37B (2024) → $17.7B by 2033, 21.4% CAGR (GrowthMarketReports;
  secondary).
- **AI in cybersecurity** (AI used *for* security — a different, larger market) — $25.35B (2024)
  → $93.75B by 2030 (Grand View). **Do not conflate** with securing-AI.
- **Avoid** the market.us "AI Guardrails $109.9B by 2034 / 65.8% CAGR" outlier and SEO-press
  reports (openpr, precedenceresearch, snsinsider) — implausible methodology.
- Context: Gartner pegs worldwide infosec spend at ~$213B (2025) → ~$244B (2026); Gartner
  originated AI TRiSM but publishes no public dollar TAM.

**Takeaway:** a real, fast-growing (~21% CAGR) but still **early** market — guardrail adoption
is only ~41%. Early enough that an open-source standard can still define the category.

---

## Buyer / ICP & compliance triggers

- **Budget owner:** the **CISO** sets the agenda (AI risk = #1 2025 priority); execution sits with
  **AppSec / product security** and **ML/AI-platform / MLOps**. AI risk often lacks a single
  owner — which slows deals but rewards a tool that's easy to adopt bottom-up (the OSS lib).
- **Adoption gap = opportunity:** only ~41% have runtime guardrails; 69% run AI agents but only
  ~21% can secure them (Team8 2025; Akto 2025).
- **Procurement triggers:** customer **security questionnaires** (vendors must answer AI-specific
  controls), **compliance audits**, and **incidents** (a prompt-injection / data-leak event).
- **Compliance hooks to map the product to:**
  - **OWASP LLM Top 10 (2025):** LLM01 prompt injection (#1), LLM02 sensitive-info disclosure,
    LLM06 excessive agency, LLM07 system-prompt leakage, LLM08 vector/embedding weaknesses.
    ShadowShield should publish an explicit LLM0x → detector/responder coverage map — this is
    the literal checklist buyers paste into RFPs.
  - **EU AI Act:** in force Aug 2024; GPAI obligations Aug 2025; high-risk Aug 2026 (a Digital
    Omnibus may slip some high-risk dates to ~Dec 2027 — unsettled as of mid-2026). Art. 15
    robustness/adversarial-resilience duties map directly to guardrails.
  - **NIST AI RMF 1.0** + **GenAI Profile (AI 600-1, Jul 2024)** — referenced in US federal
    procurement.
  - **ISO/IEC 42001** (Dec 2023) — first certifiable AI management system; becoming a
    vendor-selection benchmark.
  - **MITRE ATLAS** — ATT&CK-style AI threat knowledge base for threat modeling/red-teaming.

---

## Positioning recommendations (OSS layer)

1. **Own a sentence:** *"The open-source, defense-in-depth security shield for agentic AI — one
   engine guarding input and output, with the agent-aware controls (tool-call guarding, canary
   tokens, alignment auditing, spotlighting-as-an-action) that single-regex guards and the now-
   acquired incumbents don't ship openly."*
2. **Lead with the differentiators the market rewards:** agent-awareness + active response +
   honest, reproducible benchmarks (recall **and** false-positive rate, published together).
   Make the benchmark harness a marketing asset.
3. **Map to compliance explicitly.** Ship an OWASP-LLM-Top-10 coverage table and a "controls for
   EU AI Act Art. 15 / NIST GenAI Profile / ISO 42001" page. This is how AppSec finds and
   justifies you.
4. **Exploit independence.** "Vendor-neutral, self-hostable, MIT, no model-license strings"
   directly counters LlamaFirewall's model license and the platform lock-in of the acquired set.
5. **Stay latency- and FPR-honest.** Publish p50/p95 and FPR per layer; let users compose layers
   to their latency budget (already a design property). This is the credibility moat.
6. **Distribution:** GitHub stars + a benchmark people cite + integrations (LangChain done; add
   LiteLLM for breadth, an MCP guard server for the agent wave). Adoption is the moat that the
   acquired competitors can no longer contest on open terms.

The monetization path (control-plane SaaS), open-core boundary, pricing, and licensing are in
**[SAAS_STRATEGY.md](SAAS_STRATEGY.md)**.

---

## Sources

Competitive landscape: github.com/protectai/llm-guard · github.com/NVIDIA-NeMo/Guardrails ·
github.com/guardrails-ai/guardrails · github.com/protectai/rebuff · ai.meta.com/blog/llamacon-llama-news ·
github.com/meta-llama/PurpleLlama · github.com/deadbits/vigil-llm · appsecsanta.com/promptfoo ·
github.com/Giskard-AI/giskard-oss · docs.lakera.ai/guard · hiddenlayer.com/aisec-platform ·
arthur.ai/built-in-guardrails · github.com/whylabs/langkit

M&A / funding: blogs.cisco.com (Robust Intelligence) · paloaltonetworks.com/company/press (Protect AI) ·
bankinfosecurity.com (Protect AI $650–700M est.) · checkpoint.com + globenewswire.com (Lakera) ·
sentinelone.com/press (Prompt Security) · f5.com + geekwire.com (CalypsoAI $180M) ·
coralogix.com/blog (Aporia) · techcrunch.com (Lakera $20M Series A) · bloomberg.com (Protect AI $400M) ·
securityweek.com (Protect AI $60M Series B) · geekwire.com (Guardrails AI $7.5M)

Market size: grandviewresearch.com (AI TRiSM $7.44B/2030; AI-cybersecurity $93.75B/2030) ·
marketsandmarkets.com (GenAI cybersecurity) · growthmarketreports.com (LLM security platforms) ·
gartner.com/newsroom (infosec spend 2025/2026). Low-credibility, flagged: market.us AI guardrails.

Compliance / buyer: genai.owasp.org/llm-top-10 · owasp.org OWASP-Top-10-for-LLMs-v2025.pdf ·
artificialintelligenceact.eu/article/113 + /implementation-timeline · digital-strategy.ec.europa.eu ·
gibsondunn.com (Digital Omnibus) · nist.gov/itl/ai-risk-management-framework ·
nvlpubs.nist.gov NIST.AI.600-1.pdf · iso.org/standard/42001 · atlas.mitre.org ·
team8.vc/ciso-village-survey-2025 · akto.io/blog/state-of-agentic-ai-security-2025 ·
proofpoint.com 2025 Voice of the CISO

Open-core / pricing comps: grafana.com/blog (AGPLv3 relicense) · blog.sentry.io (FSL) ·
docs.gitlab.com/development/licensing · elastic.co/pricing/faq/licensing · devclass.com (Elastic AGPL) ·
opentofu.org/blog · govconwire.com (IBM/HashiCorp close) · redis.io/blog/agplv3 ·
handbook.mattermost.com · posthog.com/docs/self-host · eesel.ai/blog/lakera-pricing ·
cekura.ai (Langfuse pricing) · metacto.com (LangSmith) · aihungry.com (Helicone) ·
phoenix.arize.com/pricing · a16z.com/open-source-from-community-to-commercialization ·
unusual.vc/articles/building-gtm-for-an-open-source-company · futureagi.com (guardrails differentiation) ·
unit42.paloaltonetworks.com (LLM guardrail comparison)

> Verification note: an early source mis-attributed Lakera's acquisition to Cisco; the correct
> acquirer is **Check Point** (announced Sep 16, 2025). Protect AI's ~$650–700M price is a
> Jefferies estimate, not an officially disclosed figure.
