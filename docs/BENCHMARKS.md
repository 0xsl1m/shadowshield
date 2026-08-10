# Benchmarks

Reproducible, honestly-reported numbers. The guiding principle (per the 2026
distribution-shift literature) is to **always report false-positive rate next to
detection rate, and to report an *external* number, not just an in-distribution
one** — a guard that blocks everything has perfect recall and is useless.

## How to reproduce

```bash
# Bundled offline benchmark (no network, no extra deps)
shadowshield benchmark
shadowshield benchmark --adversarial

# Independently authored blind semantic snapshots
shadowshield benchmark --generalization v1
shadowshield benchmark --generalization v2
shadowshield benchmark --generalization v3
shadowshield benchmark --generalization all

# External public dataset (needs the datasets extra)
pip install "shadowshield[datasets]"
shadowshield benchmark --hf deepset/prompt-injections --split test
# with the ML classifier layer:
pip install "shadowshield[transformers]"
shadowshield benchmark --hf deepset/prompt-injections --split test --transformer
```

The CLI warms every configured detector before starting the latency clock. Its
JSON and text reports include a runtime-integrity section covering warmup,
readiness, and bounded per-detector failure counts. A benchmark with a warmup
failure, a detector that remains unready, or any detector error exits non-zero
and is marked **unreliable**; its confusion counts remain available for
diagnosis but must not be published as quality evidence. CLI benchmark shields
disable normal audit emission so logging I/O does not distort latency or corrupt
the command's machine-readable JSON stdout.

Programmatic callers can request the same behavior with
`evaluate_shield(shield, examples, warmup=True)`. The default remains
`warmup=False` for API compatibility. In both modes, readiness is checked after
the scans and per-scan detector error counters are aggregated.

Per-category output retains the original `total`, `flagged`, and flag-rate
fields, and additionally reports class-conditional TP/FP/TN/FN, recall, FPR,
and balanced accuracy. Recall is `null`/`n/a` for categories with no attack
rows; FPR is `null`/`n/a` for categories with no benign rows; balanced accuracy
is defined only when both classes are present.

Aggregate and per-category recall/FPR also include two-sided 95% Wilson score
intervals. Wilson intervals remain informative at small sample sizes and at
observed rates of 0% or 100%; an interval is `null`/`n/a` when that category has
no rows for the corresponding class. Existing scalar metric fields are
unchanged, and the interval fields are additive.

## 1. Bundled benchmark (in-distribution — a regression baseline)

75 curated examples (40 attack / 35 benign, incl. 16 NotInject-style hard
negatives). `balanced` mode:

| recall (95% CI) | FPR (95% CI) | precision | F1 | p50 |
|---:|---:|---:|---:|---:|
| 100% [91.2%, 100%] | 0% [0%, 9.9%] | 100% | 100% | 0.16 ms |

**This is a regression baseline and a smoke test — NOT a claim of real-world
accuracy.** 100% on our own set just means we don't regress on the attack
catalogue we curated. The blind and external numbers below are the real constraint.

## 2. Curated adversarial regression set

The 36-row adversarial catalogue includes obfuscation, multilingual and indirect
attacks, plus benign trigger-heavy counterexamples. It improved from
15/2/16/3 to 18/0/18/0 (TP/FP/TN/FN):

| recall (95% CI) | FPR (95% CI) | precision | F1 |
|---:|---:|---:|---:|
| 100% [82.4%, 100%] | 0% [0%, 17.6%] | 100% | 100% |

This is still a curated regression set. The signatures were developed with these
cases visible, so its perfect score is not a generalization claim.

## 3. Blind semantic snapshots (the anti-gaming result)

Three balanced snapshots were authored independently without detector or regex
context, then frozen. They deliberately pair attacks with benign text containing
similar roleplay, authority, debug, and policy vocabulary.

Isolation protocol: the v1/v2 authoring tasks received only the five semantic
category names, required row/balance counts, and a request for attack/benign
contrast pairs. The v3 task received modality coverage requirements but no
detector source, signatures, or current predictions. The files were frozen before
detector tuning and are integrity-pinned in tests:
v1 SHA-256 `b3281ba1a42d266bb930bbb41943016d47b38dbc822ff7cff5131f3448a0248f`;
v2 SHA-256 `aa8b8c81c00a55bb65180e15ff743b6241d24845b3886e8e60b52b9b23db47fa`;
v3 SHA-256 `2285031e8143572311a522a4b6ec1a39c96a34ac2b42785f17818e8a145342bf`.

| snapshot | rows | TP/FP/TN/FN | recall (95% CI) | FPR (95% CI) | balanced accuracy |
|---|---:|---:|---:|---:|---:|
| v1 | 30 | 4/2/13/11 | 26.7% [10.9%, 52.0%] | 13.3% [3.7%, 37.9%] | 56.7% |
| v2 | 20 | 0/1/9/10 | 0% [0%, 27.8%] | 10% [1.8%, 40.4%] | 45% |
| v3 | 40 | 6/6/14/14 | 30% [14.5%, 51.9%] | 30% [14.5%, 51.9%] | 50% |
| **aggregate** | **90** | **10/9/36/35** | **22.2% [12.5%, 36.3%]** | **20% [10.9%, 33.8%]** | **51.1%** |

The v3 snapshot was opened only after a detector candidate and acceptance bar
were frozen. That candidate raised aggregate recall to 55.6% but failed the
predeclared false-positive and balanced-accuracy gates (24.4% FPR; 65.6%
balanced accuracy), so it was discarded in full. No v3-driven detector tuning
ships in 0.6.2; the table records the unchanged released core.

These snapshots expose the core deterministic tier's semantic-generalization
ceiling and are development evidence for a fresh-corpus classifier/conjunction
tranche, not numbers to hide or a set to tune against.

## 4. External: `deepset/prompt-injections` (out-of-distribution)

The field's standard public smoke set (662 rows, English + German, diverse
phrasings). This is where in-distribution scores collapse — and ours do too.

### The layer ladder (deepset test split, n=116)

Each layer is additive and configurable. **Every one adds recall at zero
false-positive cost** — precision and FPR stay perfect throughout, which is the
whole point (over-defense is the field's failure mode).

| configuration | install | recall | FPR | precision | p50 |
|---|---|---:|---:|---:|---:|
| regex only (English) | core | 18.3% | 0% | 100% | 0.1 ms |
| + multilingual signatures | core | **23.3%** | 0% | 100% | 0.1 ms |
| + vector similarity | `[vectors]` | **25.0%** | 0% | 100% | 21 ms |
| + DeBERTa classifier | `[transformers]` | **48.3%** | 0% | 100% | 165 ms |

(train split, deterministic tiers: 26.1% recall / 0.6% FPR / 96.4% precision.)

**How to read it:**
- The **deterministic tiers** (regex + multilingual signatures, de/es/fr/it/pt/zh) are
  high-precision/low-recall, cheap (sub-ms), explainable, and obfuscation-aware.
  Multilingual signatures alone added +5pp on this German-heavy set — a capability
  most OSS guards lack entirely at the signature tier.
- The **vector-similarity** tier (`use_vectors=True`) catches *paraphrases* of
  known attacks via cross-lingual embeddings, at ~21 ms, and is **self-hardening**
  (`shield.harden(text)` adds confirmed attacks to the index). Modest here only
  because the bundled corpus is deliberately small and the threshold is not tuned
  on the eval set.
- The **classifier** (`use_transformer=True`) is the recall workhorse — 2.5× over
  regex-only — using `protectai/deberta-v3-base-prompt-injection-v2` (configurable).

48% (not higher) is honest, not cherry-picked: `deepset` is heavily German and the
default classifier is English-trained. For stronger non-English ML coverage, swap
in a **multilingual model** — `meta-llama/Llama-Prompt-Guard-2-22M` (mDeBERTa, 22M)
via `use_transformer="meta-llama/Llama-Prompt-Guard-2-22M"`. Note: the Prompt-Guard-2
models are **gated** on HuggingFace — accept the license and run `huggingface-cli
login` (or set `HF_TOKEN`) first. The default ProtectAI model needs no token.

**Measured head-to-head (balanced mode, CPU, Wilson 95% CIs):** both multilingual
candidates were benchmarked through ShadowShield on the same two evals —
deepset/prompt-injections test (n=116) and the v4 generalization set (n=58):

| Model | deepset recall | deepset FPR | v4 recall | v4 FPR | p50 latency |
|-------|---------------|-------------|-----------|--------|-------------|
| `protectai/deberta-v3-base-prompt-injection-v2` (default, English) | 48.3% | 0% | — | — | — |
| `meta-llama/Llama-Prompt-Guard-2-22M` (gated; measured 2026-08-08) | 25.0% [15.8%, 37.2%] | **0.0%** | 62.1% [44.0%, 77.3%] | 6.9% [1.9%, 21.9%] | **106 ms** |
| `proventra/mdeberta-v3-base-prompt-injection` (measured 2026-08-07) | **85.0%** [73.9%, 91.9%] | **0.0%** | **100%** [88.3%, 100%] | 41.4% [25.5%, 59.3%] | 266 ms |

Honest reading:

- **The non-gated proventra fine-tune beats Meta's gated 22M on every quality
  metric here** (+60pp deepset recall at the same 0% FPR; confusion 15/0/56/45
  for PG2 vs 51/0/56/9). Gating is a distribution hurdle, not a quality signal —
  the 22M's strength is footprint and speed (~2.5× faster), not detection.
- The proventra model's v4 profile (catches everything, over-flags
  semantic-pretext benign text) means: **deterministic tiers remain the
  zero-FPR backbone; the multilingual classifier is the high-recall layer to
  compose deliberately** (e.g. behind a "multilingual input" routing rule or as
  a canary/alignment confirmation signal), not a drop-in replacement at default
  thresholds. PG2-22M is the pick when latency/footprint dominates and modest
  recall is acceptable.

## 5. Interpretation & roadmap

- **Use the deterministic tiers** for cheap, explainable, obfuscation-aware,
  zero-false-positive catches and for everything the classifier can't do
  (output/secret/PII, canaries, tool-call + alignment auditing).
- **Add the vector tier** (`use_vectors=True`) for cheap paraphrase coverage and
  self-hardening; **add the classifier** (`use_transformer=True`) for the biggest
  recall jump. Compose what your latency budget allows.

### AgentDojo (agent-level ASR + utility)

ShadowShield ships an **AgentDojo defense adapter**
(`shadowshield.integrations.make_agentdojo_defense`) and a dev runner
(`scripts/agentdojo_bench.py`) for the gold-standard agent-injection benchmark
(security *and* utility jointly). First published results (2026-08-07, banking
suite v1.2, `gpt-4o-mini-2024-07-18` temp 0, `important_instructions` attack,
16 user tasks × 9 injection tasks = 144 attack runs + 16 utility runs per arm,
full script + methodology in `scripts/agentdojo_bench.py`):

| Arm | Utility (clean tasks) | ASR (attack success rate, lower is better) |
|-----|----------------------|--------------------------------------------|
| No defense | 56.3% (9/16) | 50.7% (73/144) |
| ShadowShield (deterministic tiers, tool-output scanning) | **62.5% (10/16)** | **52.1% (75/144)** |

Three honest takeaways:

1. **Zero utility cost** — the defense never aborted a clean trajectory;
   utility is unchanged within noise (62.5% vs 56.3%).
2. **The ASR delta is within noise — and that *is* the finding.** The
   deterministic tiers are designed for explicit injection syntax
   ("ignore previous instructions…"), canaries, secrets/PII, and tool-call
   auditing. AgentDojo's `important_instructions` attack phrases its payloads
   as *benign user-prefixed pretexts* — exactly the semantic-pretext class
   where deterministic detection binds (see the 23–58% recall ceiling
   documented in §4). Closing this gap is the classifier tranche's job, and
   this harness is now its acceptance test: re-run with
   `use_transformer="proventra/mdeberta-v3-base-prompt-injection"` and compare.
3. **Methodology caveats.** gpt-4o-mini ends ~40% of trajectories early with a
   clarifying question, so some "prevented" attacks were never attempted
   (ASR is reported over all 144 runs per AgentDojo convention); a single
   suite/attack/model is a starting point, not the full matrix. The run also
   surfaced an adapter compat fix for agentdojo ≥ 0.1.33 (`PipelineElement` →
   `BasePipelineElement`), which shipped with these numbers.

**Remaining suites (2026-08-08):** travel, slack, and a stratified workspace
sample replicate the banking signature — ASR unmoved within noise at zero
utility cost everywhere. Full cross-suite table plus InjecAgent, BIPIA,
LLMail-Inject, NotInject, and the performance suite:
[INDUSTRY_BENCHMARKS.md](INDUSTRY_BENCHMARKS.md).

> External model numbers measured 2026-06-12; curated/blind snapshots measured
> 2026-07-25 on CPU; mDeBERTa multilingual classifier + AgentDojo banking numbers
> measured 2026-08-07 on CPU; gated Llama-Prompt-Guard-2-22M numbers measured
> 2026-08-08 on CPU. Latency is hardware-dependent; the
> classifier adds tens of ms/scan on CPU, the vector tier ~20 ms, vs. sub-ms for
> the deterministic tiers.
