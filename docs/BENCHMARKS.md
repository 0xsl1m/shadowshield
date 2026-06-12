# Benchmarks

Reproducible, honestly-reported numbers. The guiding principle (per the 2026
distribution-shift literature) is to **always report false-positive rate next to
detection rate, and to report an *external* number, not just an in-distribution
one** — a guard that blocks everything has perfect recall and is useless.

## How to reproduce

```bash
# Bundled offline benchmark (no network, no extra deps)
shadowshield benchmark

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
catalogue we curated. The number that matters is the external one below.

## 2. External: `deepset/prompt-injections` (out-of-distribution — the honest number)

The field's standard public smoke set (662 rows, English + German, diverse
phrasings). This is where in-distribution scores collapse — and ours do too.

### Deterministic tier only (default install, no ML)

| split | n | recall (detection) | FPR | precision | F1 |
|---|---:|---:|---:|---:|---:|
| test | 116 | **23.3%** | 0.0% | 100% | 37.8% |
| train | 546 | **26.1%** | 0.6% | 96.4% | 41.1% |

**Honest read:** the regex/heuristic tier is **high-precision, low-recall** on
real-world data. When it flags, it's almost always right (≈96–100% precision, ≈0%
false positives — no over-defense), but it still *misses the majority of attacks*
because signatures can't generalise to truly novel phrasings. This is exactly why
every serious guard in the field wraps a trained classifier — and why ShadowShield
ships one (below).

> **Multilingual signatures** (added in the multilingual upgrade) cover override /
> extraction / persona templates in German, Spanish, French, Italian, and
> Portuguese. On this German-heavy set they lifted deterministic recall from 18.3%
> → **23.3%** (test) and 20.2% → 26.1% (train) at **zero** false-positive cost —
> a capability most OSS guards lack entirely at the signature tier.

### With the DeBERTa classifier (`shadowshield[transformers]`, `use_transformer=True`)

Model: `protectai/deberta-v3-base-prompt-injection-v2` (configurable).

| split | n | recall (detection) | FPR | precision | F1 | p50 |
|---|---:|---:|---:|---:|---:|---:|
| test | 116 | **48.3%** | **0.0%** | **100%** | ~65% | 131 ms |

**The classifier recovers recall — 23.3% → 48.3% (and the regex-only baseline was
18.3%) — at *zero* false-positive cost** (precision and FPR stay perfect). That's
the headline: each layer adds real-world detection *without* eroding ShadowShield's
defining zero-over-defense property. The deterministic tiers still carry everything
the classifier can't — obfuscation resistance, output/secret/PII scanning, canary
detection, and the tool-call + alignment auditing layers.

48% (not higher) is honest, not cherry-picked: `deepset` is heavily German and the
default classifier is English-trained. For stronger non-English coverage, swap in a
**multilingual model** — `meta-llama/Llama-Prompt-Guard-2-22M` (mDeBERTa, 22M,
low-latency) via `use_transformer="meta-llama/Llama-Prompt-Guard-2-22M"`. Note: the
Prompt-Guard-2 models are **gated** on HuggingFace — accept the license and run
`huggingface-cli login` (or set `HF_TOKEN`) before first use. The default ProtectAI
model needs no token.

## 3. Interpretation & roadmap

- **Use the deterministic tiers** for cheap, explainable, obfuscation-aware,
  zero-false-positive catches and for everything the classifier can't do
  (output/secret/PII, canaries, tool-call + alignment auditing).
- **Add the classifier** (`use_transformer=True`) for real-world input-injection
  recall. For multilingual, `meta-llama/Llama-Prompt-Guard-2-22M` is a low-latency
  option.
- **Next:** publish an AgentDojo / InjecAgent agent-ASR-at-fixed-utility number
  (the harness already loads external datasets), and add a vector-similarity tier
  to catch paraphrases the regex misses without a model call.

> Numbers measured 2026-06-12 on CPU. Latency is hardware-dependent; the
> classifier adds tens of ms/scan on CPU vs. sub-ms for the deterministic tiers.
