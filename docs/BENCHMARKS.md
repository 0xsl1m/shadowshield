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

# External public dataset (needs the datasets extra)
pip install "shadowshield[datasets]"
shadowshield benchmark --hf deepset/prompt-injections --split test
# with the ML classifier layer:
pip install "shadowshield[transformers]"
shadowshield benchmark --hf deepset/prompt-injections --split test --transformer
```

## 1. Bundled benchmark (in-distribution — a regression baseline)

75 curated examples (40 attack / 35 benign, incl. 16 NotInject-style hard
negatives). `balanced` mode:

| recall | FPR | precision | F1 | p50 |
|---:|---:|---:|---:|---:|
| 100% | 0% | 100% | 100% | 0.16 ms |

**This is a regression baseline and a smoke test — NOT a claim of real-world
accuracy.** 100% on our own set just means we don't regress on the attack
catalogue we curated. The blind and external numbers below are the real constraint.

## 2. Curated adversarial regression set

The 36-row adversarial catalogue includes obfuscation, multilingual and indirect
attacks, plus benign trigger-heavy counterexamples. It improved from
15/2/16/3 to 18/0/18/0 (TP/FP/TN/FN):

| recall | FPR | precision | F1 |
|---:|---:|---:|---:|
| 100% | 0% | 100% | 100% |

This is still a curated regression set. The signatures were developed with these
cases visible, so its perfect score is not a generalization claim.

## 3. Blind semantic snapshots (the anti-gaming result)

Two balanced snapshots were authored independently without detector or regex
context, then frozen. They deliberately pair attacks with benign text containing
similar roleplay, authority, debug, and policy vocabulary.

Isolation protocol: the authoring task received only the five semantic category
names, required row/balance counts, and a request for attack/benign contrast
pairs. It did not receive detector source, signatures, or current predictions.
The files were frozen before detector tuning and are integrity-pinned in tests:
v1 SHA-256 `b3281ba1a42d266bb930bbb41943016d47b38dbc822ff7cff5131f3448a0248f`;
v2 SHA-256 `aa8b8c81c00a55bb65180e15ff743b6241d24845b3886e8e60b52b9b23db47fa`.

| snapshot | rows | TP/FP/TN/FN | recall | FPR | balanced accuracy |
|---|---:|---:|---:|---:|---:|
| v1 | 30 | 4/2/13/11 | 26.7% | 13.3% | 56.7% |
| v2 | 20 | 0/1/9/10 | 0% | 10% | 45% |

The narrow 0.6.1 fixes intentionally leave these results unchanged. They expose
the core deterministic tier's semantic-generalization ceiling and are development
evidence for the next classifier/conjunction tranche, not a number to hide.

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
- The **deterministic tiers** (regex + multilingual signatures, de/es/fr/it/pt) are
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

## 5. Interpretation & roadmap

- **Use the deterministic tiers** for cheap, explainable, obfuscation-aware,
  zero-false-positive catches and for everything the classifier can't do
  (output/secret/PII, canaries, tool-call + alignment auditing).
- **Add the vector tier** (`use_vectors=True`) for cheap paraphrase coverage and
  self-hardening; **add the classifier** (`use_transformer=True`) for the biggest
  recall jump. Compose what your latency budget allows.

### AgentDojo (agent-level ASR + utility)

ShadowShield ships an **AgentDojo defense adapter**
(`shadowshield.integrations.make_agentdojo_defense`) so it can be evaluated on the
gold-standard agent-injection benchmark (security *and* utility jointly). Running
it needs `pip install agentdojo` and an LLM API key; the adapter and a
standalone `scan_messages_for_injection` helper are tested and ready. Publishing
the ASR-at-fixed-utility number is the next milestone.

> External model numbers measured 2026-06-12; curated/blind snapshots measured
> 2026-07-25 on CPU. Latency is hardware-dependent; the
> classifier adds tens of ms/scan on CPU, the vector tier ~20 ms, vs. sub-ms for
> the deterministic tiers.
