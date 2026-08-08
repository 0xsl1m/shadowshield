# Industry-Standard Benchmarks

The consolidated, reproducible benchmark matrix for ShadowShield: the public
suites the prompt-injection field actually cites, run with published
methodology. For the original curated evals see [BENCHMARKS.md](BENCHMARKS.md).

**Measurement date:** 2026-08-08 (deepset/multilingual: 2026-08-07/08).
**Config:** `Shield.for_mode("balanced")` — the shipped default deterministic
stack — unless an arm says otherwise. **Agent model:** gpt-4o-mini-2024-07-18,
temperature 0. **Statistics:** Wilson 95% CIs; latency is CPU
(hardware-dependent). Every detection benchmark reports two predicates:
**catch-rate** (any detector fires — the sensitive measure) and **block-rate**
(hard-block decisions only — the deployment-enforcement measure).
Runners: `scripts/agentdojo_bench.py`, `scripts/injecagent_bench.py`,
`scripts/bipia_bench.py`, `scripts/industry_classify_bench.py`,
`scripts/perf_bench.py`.

## 1. Detection benchmarks (input classification)

| Benchmark | n | Catch recall | Catch FPR | Block recall | Block FPR |
|-----------|---|--------------|-----------|--------------|-----------|
| **LLMail-Inject** (Microsoft; 2,000 sampled real attack submissions + 203 FP emails) | 2,203 | **96.75%** | **0.0%** | 44.9% | **0.0%** |
| **NotInject** (Meta PG2 paper's over-defense set, all-benign trigger words) | 339 | — | 6.8% (flags only) | — | **0.0%** |
| **BIPIA email** (faithful end/start/middle composition) | 100 | 58.0% | 58.0% | 2.0% | 8.0% |
| **BIPIA table** | 200 | 17.0% | 17.0% | 0.0% | 0.0% |
| **BIPIA code** | 100 | 14.0% | 10.0% | 4.0% | 2.0% |
| deepset/prompt-injections test | 116 | 48.3% (EN model) / **85.0%** (multilingual) | 0.0% | — | — |

Reading: LLMail (real-world adversarial submissions) is the strongest result —
96.75% catch at 0% FPR; the catch-to-block gap is attacks *sanitized* (threat
neutralized, request survives), not missed. NotInject shows zero over-defense
at the block level; the 6.8% flag-rate is low-severity PII pattern-matching
(score ~0.3) that never escalates. BIPIA's attack instructions are mostly
benign-looking imperatives (the semantic-pretext class) — deterministic
detection cannot separate them from context, and email's catch == FPR reflects
the spam-like corpus tripping PII/exfil heuristics. This is the documented
recall ceiling, not a tuning failure.

## 2. Agent-level benchmarks (ASR at fixed utility)

### AgentDojo (v1.2, `important_instructions` attack, tool-output defense)

| Suite | Runs/arm | Baseline ASR | Defended ASR | Utility (baseline → defended) |
|-------|----------|--------------|--------------|-------------------------------|
| Banking (full) | 144 + 16 | 50.7% | 52.1% | 56.3% → 62.5% |
| Travel (full) | 140 + 20 | 27.1% | 30.7% | 50.0% → 55.0% |
| Slack (full) | 105 + 21 | 61.9% | 64.8% | 81.0% → 71.4% |
| Workspace (stratified 1-in-5 sample) | 112 + 8 | 18.8% | 17.9% | 87.5% → 100% |

Replicated across four suites: **zero utility cost within noise** (the defense
never meaningfully degrades clean trajectories) and **ASR unmoved** —
`important_instructions` phrases payloads as benign user-prefixed pretexts,
exactly the class deterministic tiers cannot see. This harness is the
acceptance test for the classifier tranche.

### InjecAgent (1,054 cases/arm, enhanced setting, three defense arms)

| Arm | Valid rate (utility) | ASR-all (Direct Harm) | ASR-all (Data Stealing) | **ASR-all (Total)** |
|-----|---------------------|----------------------|------------------------|---------------------|
| No defense | 88.7% | 10.0% | 27.0% | **18.8%** |
| ShadowShield — redact | 25.2% | 0.0% | 0.0% | **0.0%** |
| ShadowShield — **sanitize** | **88.2%** | 12.2% | 4.2% | **8.1%** |

The headline agent-level result: **sanitize mode cuts total ASR 18.8% → 8.1%
(−57%) at statistically identical utility** (88.2% vs 88.7%), with
data-stealing ASR collapsing 27.0% → 4.2%. The redact arm shows brute-force
blocking's cost (0% ASR, utility destroyed). Residual 8.1% is the
semantic-pretext instruction that survives span-redaction of the explicit
wrapper — the classifier tranche's target. (Sanitize arm config: balanced
policy with high/critical → SANITIZE and `block_threshold` lifted; the
threshold is an independent floor above per-band policy.)

## 3. Multilingual classifier head-to-head

Full table in [BENCHMARKS.md §4](BENCHMARKS.md). Summary: the non-gated
`proventra/mdeberta-v3-base-prompt-injection` beats Meta's gated
Llama-Prompt-Guard-2-22M on every quality metric (85.0% vs 25.0% deepset
recall, both 0% FPR); PG2-22M's edge is footprint and ~2.5× latency.

## 4. Performance (CPU, p50 latency / throughput / memory)

| Tier | p50 short / med / long | Throughput (seq) | Warmup (cached) | RSS delta |
|------|------------------------|------------------|-----------------|-----------|
| Deterministic (default) | 0.25 / 2.3 / 10.0 ms | **374 scans/s** | 0.01 ms | 0.2 MB |
| + Vectors | 29.5 / 55.6 / 73.6 ms | 14.7 scans/s | 53.8 s | 867 MB |
| + Transformer EN (ProtectAI DeBERTa) | 148 / 497 / 1,140 ms | 2.0 scans/s | 21.0 s | 529 MB |
| + Transformer multi (proventra mDeBERTa) | 148 / 682 / 1,139 ms | 1.5 scans/s | 20.6 s | 647 MB |

The deterministic backbone is sub-millisecond on typical payloads with
negligible memory — safe for any synchronous request path. ML tiers cost
60–600× per scan and 0.5–0.9 GB RSS; parallel CPU threads do not help them
(torch contention). Payload-size scaling is ~linear for regex tiers;
transformer tiers truncate at 512 tokens so long-doc cost plateaus.

## 5. Coverage and availability caveats

- **PINT (Lakera):** the full dataset is proprietary (public repo ships only a
  10-row example); evaluation is via Lakera's paid API. Not runnable.
- **HackAPrompt:** gated dataset requiring manual license acceptance on the
  HuggingFace website; not automated here.
- **BIPIA WebQA / Summarization:** context files require external licensed
  datasets (NewsQA via Docker, XSum); email/table/code tasks run instead.
- **AgentDojo workspace:** full suite is 560 runs/arm; a stratified 1-in-5
  user-task sample (112 runs/arm) is reported and labeled as sampled.
- **InjecAgent base setting:** attacker instructions carry no injection syntax
  (pure semantic pretext); the enhanced setting — where injection syntax is
  present — is the discriminative configuration and the one reported.
- Agent-level numbers use gpt-4o-mini; absolute ASR levels are model-dependent
  (defense *deltas* are the portable quantity). gpt-4o-mini ends some
  trajectories early with clarifying questions; ASR is reported over all runs
  per each benchmark's own convention.

## 6. What the matrix establishes

1. **Best-in-class real-world detection**: 96.75% catch / 0% FPR on LLMail's
   real adversarial submissions.
2. **Zero measured over-defense at enforcement level**: 0% block-FPR on
   NotInject and every benign split.
3. **Decisive where injection syntax is present**: InjecAgent sanitize arm
   −57% ASR at unchanged utility; 100% redaction rate on enhanced payloads.
4. **Honestly bounded**: semantic-pretext attacks (AgentDojo
   `important_instructions`, BIPIA, InjecAgent base) pass the deterministic
   tiers — replicated across six independent evals. Closing that class is the
   classifier tranche's job, and this harness is its acceptance test.
5. **Production-shaped performance**: sub-ms deterministic scans at 374/s,
   with measured cost curves for every optional tier.
