# ShadowShield — Competitive & Technique Landscape

**Date:** 2026-06-12
**Purpose:** Map the OSS LLM/agentic-AI security landscape so we know exactly what "best open-source prompt-injection guard" must beat. Implementation-ready: names, model IDs, dataset IDs, URLs.

> **Provenance note:** Every claim below is sourced (Section 5). All web content was treated as untrusted **data**. No fetched page contained executable instructions targeting this research; nothing was acted on. Figures (stars, dates) are as reported by GitHub/HF at fetch time on 2026-06-12 and should be re-verified before publication. Items that could not be fully verified are explicitly flagged **[UNVERIFIED]**.

---

## TL;DR

The OSS field splits into three camps: **guards** (runtime input/output filters — LLM Guard, Vigil, Guardrails AI, NeMo Guardrails, LlamaFirewall), **classifier models** (the DeBERTa-family detectors everyone wraps — ProtectAI v2, Meta Prompt-Guard-2), and **red-team/test harnesses** (garak, PyRIT, Giskard, AgentDojo). The current quality bar is set by **Meta LlamaFirewall** (production-grade, agent-aware, three-layer: PromptGuard 2 + AlignmentCheck + CodeShield) and **Protect AI LLM Guard** (breadth: 15 input + 20 output scanners). Table-stakes are now: a wrapped DeBERTa classifier, regex/heuristic tier, secret+PII output scanning, and a benchmark number on **PINT** or **AgentDojo**. The open differentiators ShadowShield can win on: **agent-trace / tool-output (indirect) injection defense**, **low false-positive rate on NotInject-style benign-trigger inputs**, **spotlighting/datamarking as a first-class responder**, and **clean framework middleware** (OpenAI/LangChain) — an area where most OSS guards are clumsy.

---

## 1. Competitive Landscape — Major OSS Players

### Comparison table (as of 2026-06-12)

| Tool | Type | License | Stars | Maintenance | Core technique |
|---|---|---|---|---|---|
| **Protect AI LLM Guard** | Runtime guard | MIT | ~3.1k | Active | 15 input + 20 output scanners; DeBERTa classifier + regex + Presidio-style |
| **Meta LlamaFirewall** | Agent guard | (Meta OSS, permissive) **[UNVERIFIED license]** | n/a (PurpleLlama org) | Active (2025) | PromptGuard 2 + AlignmentCheck (CoT auditor) + CodeShield |
| **NVIDIA NeMo Guardrails** | Programmable rails | Apache-2.0 | ~5.6k | Active | Colang DSL; 5 rail types (input/dialog/retrieval/execution/output) |
| **Guardrails AI** | Validator framework | Apache-2.0 | ~6.6k | Active | Validator Hub; input/output Guards; many validators wrap Rebuff/LLM-judge |
| **Rebuff** | PI detector | Apache-2.0 | ~1.5k | **ARCHIVED 2025-05-16** | 4 layers: heuristics + LLM + VectorDB + canary tokens |
| **Vigil** (deadbits) | PI scanner | Apache-2.0 | ~481 | **Alpha / stale (last rel 2023-12-31)** | YARA + transformer + vector-DB similarity + canary + prompt-response sim |
| **garak** (NVIDIA) | Red-team scanner | Apache-2.0 | ~7.8k | Very active | 50+ probe modules; static/dynamic/adaptive attack probes |
| **PyRIT** (Microsoft) | Red-team framework | MIT | ~3.4k | Very active | Automated single/multi-turn attack orchestration + scoring |
| **Giskard** | Eval / red-team | Apache-2.0 | ~5.2k | Active | LLM Scan, RAG eval, vuln detection |
| **Presidio** (Microsoft) | PII engine | MIT | (high) | Active | NER (spaCy) + regex + checksum recognizers |
| **LangKit** (WhyLabs) | LLM telemetry | Apache-2.0 | (moderate) | Slowing | Metric extraction; wraps Presidio for PII |
| **Lakera Guard** | Commercial guard | **CLOSED-SOURCE** (PINT bench is MIT) | n/a | Active | Proprietary classifier; publishes PINT benchmark |
| **AgentDojo / Invariant** | Agent bench + defenses | (research, OSS) | (moderate) | Active | Attack/defense plugin harness for agents |
| **Meta SecAlign** | Secure foundation LLM | Open weights | n/a | 2025 research | Model-level defense; extra "input" role token |

> Star counts are search-reported and may be ±10%; re-verify on the repo before citing publicly.

---

### Protect AI — LLM Guard (`protectai/llm-guard`)
- **What it does:** The most complete OSS runtime guard. Runs **15 input scanners** on prompts and **20 output scanners** on responses.
- **Input scanners (15):** Anonymize, BanCode, BanCompetitors, BanSubstrings, BanTopics, Code, Gibberish, InvisibleText, Language, **PromptInjection**, Regex, Secrets, Sentiment, TokenLimit, Toxicity.
- **Output scanners (20):** BanCode, BanCompetitors, BanSubstrings, BanTopics, Bias, Code, Deanonymize, JSON, Language, LanguageSame, MaliciousURLs, NoRefusal, ReadingTime, FactualConsistency, Gibberish, Regex, Relevance, Sensitive, Sentiment, Toxicity, URLReachability.
- **Detection techniques:** PromptInjection scanner = fine-tuned `microsoft/deberta-v3-base` (ML, not regex — catches indirect injection in docs/tool output). Plus regex, ban-lists, gibberish/toxicity transformer models, Presidio-style PII (Anonymize/Deanonymize), secret scanning.
- **Architecture:** Scanner registry; each scanner is independent and composable; `scan_prompt()` / `scan_output()` return (sanitized_text, results_dict, risk_score). Production deployment supported (API server).
- **License:** MIT. **Stars:** ~3.1k, 402 forks, ~517 commits. Active.
- **Strengths:** Breadth; clean scanner abstraction; MIT; the de-facto "kitchen sink" reference.
- **Weaknesses:** Heavy dependency footprint (transformers, spaCy, ONNX); not agent/tool-trace aware; scanners are independent (no cross-scanner correlation); latency stacks up with many scanners; English-centric classifier.
- **Steal:** The scanner taxonomy and the input/output split. The `(sanitized, results, score)` return contract. **ShadowShield's responder model (sanitize/block/isolate) is a step beyond their pure detect-and-flag.**

### Meta — LlamaFirewall + Prompt Guard 2 (`meta-llama/PurpleLlama`)
- **What it does:** Production guardrail system for **agents** (used in production at Meta). Three layers:
  1. **PromptGuard 2** — universal jailbreak/injection classifier (86M and 22M).
  2. **AlignmentCheck** — experimental **chain-of-thought auditor**: inspects the agent's *reasoning over the full execution trace* for goal hijacking / misalignment (not per-message).
  3. **CodeShield** — static analysis on LLM-generated code; rule-based analyzers across 7 languages, 50+ CWEs.
- **Reported performance:** PromptGuard 2 (86M) cut attack success rate (ASR) 17.6% → 7.5%; AlignmentCheck → 2.9% ASR; combined → **1.75% ASR (≈90% reduction)**. CodeShield: 96% precision / 79% recall on insecure completions. (arXiv 2505.03574.)
- **Architecture:** Layered scanners over agent I/O + reasoning trace; the **trace-level alignment audit is the standout** and is rare in OSS.
- **License:** Meta open-source (permissive, Llama-style). **[UNVERIFIED exact SPDX]**
- **Strengths:** The only widely-cited OSS system that defends **indirect/agent-trace injection** at the reasoning level; strong published ASR numbers; backed by a real classifier.
- **Weaknesses:** AlignmentCheck needs a capable LLM (cost/latency); Meta licensing has acceptable-use clauses; integration is opinionated toward Llama stack.
- **Steal:** **The trace-level AlignmentCheck concept is the single highest-value pattern to replicate.** ShadowShield should add an optional "agent objective vs. observed action" alignment responder. Also mirror the layered ASR-reporting methodology.

### NVIDIA — NeMo Guardrails (`NVIDIA-NeMo/Guardrails`)
- **What it does:** Programmable guardrails for conversational LLM apps via the **Colang** DSL.
- **Rail types (5):** input rails, dialog rails (multi-turn flow control — unique), retrieval rails (filter RAG results), execution rails (gate tool/action calls), output rails.
- **Detection:** jailbreak detection, prompt-injection checks, fact-checking vs KB, hallucination detection; OpenTelemetry tracing. Colang 2.0 adds parallel flows + pattern matching over event streams.
- **License:** Apache-2.0. **Stars:** ~5.6k, ~597 forks. Active.
- **Strengths:** Dialog/flow control and **execution rails (tool gating)** that simple filters lack; tracing.
- **Weaknesses:** Colang is a learning curve / lock-in; heavyweight for a "just filter my prompt" use case; injection detection is not its strongest axis.
- **Steal:** **Execution rails = gate tool calls before they run.** ShadowShield should expose a tool-call interception hook, not just text I/O scanning. Adopt OpenTelemetry-style tracing of guard decisions.

### Guardrails AI (`guardrails-ai/guardrails`)
- **What it does:** Validator framework. Input/Output **Guards** composed from **validators** pulled from the **Guardrails Hub**.
- **PI validators:** `detect_prompt_injection` (wraps the **Rebuff** library — now archived, a risk), `unusual_prompt` (jailbreak/psychological tricks via LLM judge), third-party `prompt_injection_detector` (secondary-LLM scoring 0–1, threshold 0.8).
- **License:** Apache-2.0. **Stars:** ~6.6k. Active.
- **Strengths:** Largest validator ecosystem; pluggable hub; strong on structured-output validation (Pydantic/JSON).
- **Weaknesses:** PI detection leans on Rebuff (archived) and LLM-judge (cost/latency/false positives); the hub is uneven quality; not agent-aware.
- **Steal:** **The Hub model** — a registry of community detectors/responders. ShadowShield's plugin system should be a Hub-equivalent with quality gates the Guardrails Hub lacks.

### Rebuff (`protectai/rebuff`) — **ARCHIVED**
- **What it does:** Self-hardening PI detector. **4 layers:** (1) heuristics, (2) dedicated-LLM detection, (3) **VectorDB** of past-attack embeddings, (4) **canary tokens** to detect leakage and auto-feed new attacks back into the VectorDB.
- **License:** Apache-2.0. **Stars:** ~1.5k. **Archived read-only 2025-05-16 — do not depend on it.**
- **Strengths:** The **canary-token + self-hardening loop** is the most-copied idea in the field (Guardrails, Vigil both borrow it).
- **Weaknesses:** Abandoned; TS-first (Python SDK secondary); prototype-grade.
- **Steal:** **Implement canary tokens + a self-hardening VectorDB loop natively** — and own it now that Rebuff is dead. This is a clean opportunity to become the maintained successor.

### Vigil (`deadbits/vigil-llm`) — **ALPHA / STALE**
- **What it does:** Python lib + REST API scanning prompts/responses.
- **Techniques:** **YARA signatures**, transformer classifier, vector-DB similarity, prompt-response similarity, canary tokens, sentiment/relevance, paraphrase detection.
- **License:** Apache-2.0. **Stars:** ~481. **Last release v0.10.3-alpha 2023-12-31 — effectively unmaintained.**
- **Strengths:** **YARA-based signature tier** is unusual and worth borrowing (mature, fast, auditable rule format). Ships datasets + signatures.
- **Weaknesses:** Stale, alpha, author redirects enterprise users elsewhere.
- **Steal:** **YARA as the heuristic/signature engine** — auditable, community-extensible rules instead of ad-hoc regex.

### garak (`NVIDIA/garak`) — red-team (testing, not a guard)
- **What it does:** "nmap for LLMs." 50+ probe modules: prompt injection, jailbreaks, data leakage, hallucination, toxicity, misinformation. Static + dynamic + adaptive probes.
- **License:** Apache-2.0. **Stars:** ~7.8k. Very active. `pip install -U garak`.
- **Use to ShadowShield:** **This is our adversarial test harness.** Point garak at a mock target wrapped by ShadowShield and measure ASR reduction. Reportable, credible, third-party.

### PyRIT (`microsoft/PyRIT`) — red-team framework
- **What it does:** Automated risk identification; generates/evolves harmful prompts, single- and multi-turn attack strategies, scores responses adaptively.
- **License:** MIT. **Stars:** ~3.4k. Very active.
- **Use to ShadowShield:** Second independent red-team engine for CI. Multi-turn attack coverage complements garak's probe library.

### Giskard (`Giskard-AI/giskard-oss`)
- **What it does:** LLM/agent evaluation + red-teaming; **LLM Scan** auto-detects vulns; RAG eval toolkit.
- **License:** Apache-2.0. **Stars:** ~5.2k. Active.
- **Use to ShadowShield:** Eval harness for false-positive/utility regression testing.

### LangKit / WhyLabs + Presidio
- **LangKit** (`whylabs/langkit`, Apache-2.0): telemetry/signal extraction from prompts+responses; wraps **Microsoft Presidio** for PII. Momentum slowing.
- **Presidio** (`microsoft/presidio`, MIT): the standard OSS **PII engine** — NER (spaCy `en_core_web_lg`) + regex + checksum recognizers; redact/mask/anonymize. **ShadowShield should integrate Presidio (optional dep) for the PII output scanner rather than reinventing it.**

### Lakera Guard — **CLOSED-SOURCE**
- Commercial. Scores ~92.5% on its own **PINT** benchmark (i.e. ~7.5% misclassified). Not OSS — but Lakera publishes the **PINT benchmark harness** (MIT) and the **Gandalf** game. Treat as the commercial bar to beat; use PINT to measure ourselves.

### invariant / AgentDojo (`ethz-spylab/agentdojo` + Invariant Labs)
- **What it does:** NeurIPS-2024 framework to **jointly evaluate security AND utility of agents** under injection. 70 tools, 97 user tasks, 27 injection targets across office/slack/banking/travel suites. **Plugin architecture for attacks AND defenses**; defenses can intercept at pre-input / tool-call-filter / tool-output-post-processing points.
- **Use to ShadowShield:** **This is the gold-standard agent-injection benchmark.** ShadowShield should ship as an AgentDojo *defense plugin* and publish utility-preserving ASR numbers. This is the most credible single number we can put on the box.

### Trending 2025–2026 (structural / model-level)
- **Microsoft Spotlighting** (Hines et al., CAMLIS 2024 / arXiv 2403.14720) → productized as **Prompt Shields**. (See §2.)
- **Meta SecAlign** (arXiv 2507.02735): first fully-open foundation LLM with **model-level** injection defense (extra "input" role token); SOTA robustness. Signals the field moving toward structural separation of instructions vs data.
- **DefensiveTokens** (arXiv 2507.07974): test-time defense via a few learned tokens.
- **AgentArmor** (arXiv 2508.01249) / tool-result-parsing defenses (arXiv 2601.04795): program-analysis over agent runtime traces — same lineage as LlamaFirewall AlignmentCheck.

---

## 2. Detection Techniques Catalogue (implementation-ready)

### 2.1 Classifier models (wrap these — don't train from scratch)
| Model ID | Base arch | Params | Notes |
|---|---|---|---|
| `protectai/deberta-v3-base-prompt-injection-v2` | deberta-v3-base | ~184M | The field default. v1 claimed ~99.9% on its own test set (overstated — distribution-narrow). **Do NOT run on system prompts (false positives).** English-only, no jailbreak coverage. |
| `protectai/deberta-v3-small-prompt-injection-v2` | deberta-v3-small | ~142M | Lower-latency variant. |
| `meta-llama/Llama-Prompt-Guard-2-86M` | mDeBERTa-base | 86M | Multilingual; injection + jailbreak; energy-based loss + adversarial tokenization. |
| `meta-llama/Llama-Prompt-Guard-2-22M` | DeBERTa-xsmall | 22M | ~75% lower latency/compute vs 86M; weaker on multilingual. Best for real-time. |
| `meta-llama/Prompt-Guard-86M` (v1) | DeBERTa | 86M | Original; superseded by v2. |
| `deepset/deberta-v3-base-injection` | deberta-v3-base | ~184M | Trained on `deepset/prompt-injections`. |

**Implementation:** load via HF `transformers` `AutoModelForSequenceClassification`; output is binary (0 benign / 1 injection) with a softmax score. Offer both ProtectAI (English, high precision) and Prompt-Guard-2-22M (multilingual, low-latency) and let config pick. ONNX-export for CPU latency.

**Known failure modes to design around:** (a) false positives on benign inputs containing trigger words ("ignore", "disregard") — the **NotInject** problem; (b) false positives on legitimate system prompts; (c) English bias; (d) over-fit to public datasets → poor under distribution shift (arXiv 2602.14161).

### 2.2 Canary / honeypot tokens (Rebuff-style)
Inject a unique secret token into the system prompt; if it appears in the model output, an injection/leak occurred. On detection: block + store the offending input's embedding in a VectorDB to harden against paraphrases. **Own this — Rebuff is archived.**

### 2.3 Vector-DB similarity to known-attack corpora
Embed incoming text; cosine-similarity vs an index of known attacks (seed from deepset/jayavibhav/HackAPrompt + canary-caught attacks). Catches paraphrases that classifiers/regex miss. Use a small embedding model (e.g., `all-MiniLM-L6-v2`) + FAISS/Chroma. Self-hardening: every confirmed attack is added to the index.

### 2.4 Heuristic / signature (regex + YARA)
Regex for fast, cheap, auditable signatures ("ignore previous instructions", role-reassignment, base64 blobs, bidi/invisible Unicode U+202A–U+202E / U+2066–U+2069 / U+200B–U+200F / U+FEFF, markdown-image exfil, `curl … | bash`). **Borrow Vigil's YARA approach** for a community-extensible, auditable rule format instead of scattered regex.

### 2.5 LLM-as-judge / self-check
Secondary LLM scores the input 0–1 for injection (Guardrails' approach, threshold ~0.8). High recall on novel attacks; costly + adds latency + its own injection surface. Make it an **optional high-assurance tier**, not the default.

### 2.6 Spotlighting / datamarking / delimiting (Microsoft, responder-side)
Plain delimiting alone leaves ASR >50% on GPT-family. **Spotlighting** = structural separation + transform of untrusted input + explicit instruction. Three modes:
- **Delimiting:** wrap untrusted data in unique markers.
- **Datamarking:** interleave a special token throughout the untrusted text (replace whitespace with the marker) so the model can always tell data from instruction. Drops ASR from ~50% to <3%.
- **Encoding:** base64-encode untrusted input. Drops ASR to ~0% in some setups (but costs model capability).
**ShadowShield differentiator:** ship spotlighting/datamarking as a first-class **responder** (the "isolate" action), not just detection. Few OSS guards do this.

### 2.7 Output / secret scanning + PII
- **Secrets:** regex/entropy for API keys, tokens, private keys in model output (LLM Guard's `Secrets`).
- **PII:** integrate **Microsoft Presidio** (NER + regex + checksum) for the PII detector/redactor. Optional dependency.
- **Output injection:** scan model output for malicious URLs, markdown-image exfiltration, refusal-bypass, `curl|bash`.

### 2.8 Semantic / embedding anomaly detection
Flag inputs whose embedding is an outlier vs the expected task distribution (sudden topic/instruction shift inside tool output = indirect-injection signal). Complements similarity-to-known-attacks with similarity-from-expected-distribution.

---

## 3. Benchmarks & Datasets (what to test against)

**Recommendation: standardize on these 4.** Two for detector accuracy/FP, two for agent-level ASR.

### Top picks

**1. PINT Benchmark (Lakera)** — the neutral detector benchmark.
- Repo: `github.com/lakeraai/pint-benchmark` (MIT harness).
- 4,314 inputs (3,016 EN / 1,298 non-EN, 24+ langs). Categories: prompt injections 5.2%, jailbreaks 0.9%, **hard negatives 20.9%** (benign-but-injection-looking), chat 36.5%, documents 36.5%.
- **The full dataset is proprietary** (you supply a detection fn; Lakera runs/scores). Harness + format (YAML: text/category/label) is open. Metric: balanced accuracy across categories; the hard-negatives split is the false-positive test. Lakera Guard ≈ 92.5% sets the bar.
- **How to use:** wrap ShadowShield as the eval fn in `pint-benchmark.ipynb`; for a fully-offline proxy, build a local PINT-shaped YAML from public data.

**2. AgentDojo** — the agent-injection gold standard.
- Repo: `github.com/ethz-spylab/agentdojo`; site `agentdojo.spylab.ai`; arXiv 2406.13352 (NeurIPS 2024).
- 70 tools, 97 user tasks, 27 injection targets, 4 suites. **Measures security AND utility jointly** — the honest metric (a guard that blocks everything scores 0 utility).
- License: OSS (MIT-style, research). `pip install agentdojo`. **Ship ShadowShield as a defense plugin and publish ASR + utility.**

**3. deepset/prompt-injections** — quick public detector training/eval.
- `huggingface.co/datasets/deepset/prompt-injections`. Apache-2.0. **662 rows (546 train / 116 test)**, columns `text` (str), `label` (0/1). EN + German. Load: `load_dataset("deepset/prompt-injections")`.
- Small + somewhat saturated — use for smoke tests and FP checks, not as a headline number.

**4. InjecAgent** — indirect (tool-response) injection for agents.
- arXiv 2403.02691; repo `github.com/uiuc-kang-lab/InjecAgent`. **1,054 test cases** across finance/email/smart-home/etc. Tests injection via tool outputs — directly relevant to ShadowShield's tool-output scanning. Metric: ASR (and ASR under enhanced attack).

### Secondary / supplementary
- **jayavibhav/prompt-injection** + **xTRam1/safe-guard-prompt-injection** (HF) — larger public training pools; combine for classifier fine-tuning.
- **NotInject** (from InjecGuard, arXiv 2410.22770) — purpose-built **false-positive** benchmark of benign inputs with trigger words. **Use this to prove low over-defense** — a key differentiator.
- **HackAPrompt** (HF) — large but noisy, narrow ("I have been PWNED"). Use for volume/robustness, not as a clean metric.
- **AdvBench** (520 harmful behaviors) / **HarmBench** / **JailbreakBench** — jailbreak/harmful-content, not injection per se. Useful if ShadowShield adds jailbreak coverage.
- **Caveat (arXiv 2602.14161, "When Benchmarks Lie"):** public PI classifiers overfit; numbers collapse under true distribution shift. **Always report a distribution-shift / NotInject number alongside headline accuracy.**

**Metrics that matter:** for detectors — balanced accuracy + **false-positive rate on hard negatives/NotInject** (not raw accuracy). For agents — **ASR reduction at fixed utility** (AgentDojo/InjecAgent). For latency — p50/p95 ms per scan per tier.

---

## 4. What Makes the Best Tool — Prioritized Synthesis

**Table-stakes (you don't exist without these):**
1. **A wrapped DeBERTa PI classifier** with a configurable model (ProtectAI v2 + Prompt-Guard-2-22M), binary score + threshold. *Everyone has this; absence = instant disqualification.*
2. **Input AND output scanning** with a clean `(sanitized, results, risk_score)` contract (LLM Guard's contract is the reference).
3. **Heuristic/regex tier** for cheap, auditable, zero-latency catches (incl. invisible-Unicode + base64 + exfil patterns).
4. **Secret + PII output scanning** (Presidio integration).
5. **A published benchmark number** on PINT and/or AgentDojo. No number = not credible.
6. **Framework middleware** (OpenAI client wrapper, LangChain) that's actually ergonomic.
7. **Permissive license (MIT/Apache-2.0)** and low/optional dependency footprint.

**Differentiators (where ShadowShield wins):**
1. **Agent-trace / indirect-injection defense** (the LlamaFirewall AlignmentCheck pattern): audit *agent objective vs. observed tool calls/reasoning*, not just text. **Highest-impact gap in OSS** — most guards are still single-message text filters. *(rank #1)*
2. **Spotlighting/datamarking as a first-class "isolate" responder.** ShadowShield's sanitize/block/**isolate** model maps perfectly; almost no OSS guard ships datamarking. Proven ASR ~50%→<3%. *(rank #2)*
3. **Low false-positive rate, proven on NotInject.** Over-defense is the field's dirty secret (Lakera 7.5% FP). Ship a NotInject number and a "system-prompt-safe" mode. *(rank #3)*
4. **Native canary tokens + self-hardening VectorDB loop** — become the maintained successor to the archived Rebuff. *(rank #4)*
5. **Tool-call interception / execution rails** (NeMo's idea) so ShadowShield gates *actions*, not just text. *(rank #5)*
6. **Plugin Hub with quality gates** — Guardrails' Hub idea but curated, so detectors/responders are community-extensible without the quality lottery.
7. **Rate limiting + abuse controls** built in — most guards ignore the operational layer; ShadowShield already has it. Minor but real differentiator.
8. **Defense-in-depth orchestration** (tiered: regex → classifier → vector-sim → LLM-judge, fail-closed, with per-tier latency budgets) rather than a flat list of independent scanners.

**Honest bar-setting:** "best" today means roughly: **match LLM Guard's breadth, add LlamaFirewall's agent-trace alignment check, beat both on false-positives (NotInject) and on indirect injection (InjecAgent/AgentDojo), and be easier to wire into OpenAI/LangChain than any of them — under MIT/Apache with a light dependency footprint and a published, reproducible benchmark.**

---

## 5. Sources

**Guards**
- LLM Guard: https://github.com/protectai/llm-guard · https://protectai.github.io/llm-guard/input_scanners/prompt_injection/
- LlamaFirewall: https://arxiv.org/abs/2505.03574 · https://ai.meta.com/research/publications/llamafirewall-an-open-source-guardrail-system-for-building-secure-ai-agents/ · https://github.com/meta-llama/PurpleLlama
- NeMo Guardrails: https://github.com/NVIDIA-NeMo/Guardrails · https://docs.nvidia.com/nemo/guardrails/latest/about/overview.html
- Guardrails AI: https://github.com/guardrails-ai/guardrails · https://github.com/guardrails-ai/detect_prompt_injection · https://guardrailsai.com/hub
- Rebuff (archived): https://github.com/protectai/rebuff · https://www.langchain.com/blog/rebuff
- Vigil: https://github.com/deadbits/vigil-llm
- Presidio: https://github.com/microsoft/presidio · https://microsoft.github.io/presidio/
- LangKit: https://github.com/whylabs/langkit · https://docs.whylabs.ai/docs/secure/guardrail-metrics/
- Lakera Guard / PINT: https://www.lakera.ai/product-updates/lakera-pint-benchmark · https://github.com/lakeraai/pint-benchmark

**Classifier models**
- ProtectAI v2: https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2 · https://huggingface.co/protectai/deberta-v3-small-prompt-injection-v2
- ProtectAI v1: https://huggingface.co/protectai/deberta-v3-base-prompt-injection
- Prompt Guard 2: https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M · https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M · https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Prompt-Guard-2/86M/MODEL_CARD.md
- deepset model: https://huggingface.co/deepset/deberta-v3-base-injection

**Red-team / testing**
- garak: https://github.com/NVIDIA/garak · https://garak.ai/
- PyRIT: https://github.com/microsoft/PyRIT · https://azure.github.io/PyRIT/
- Giskard: https://github.com/Giskard-AI/giskard-oss · https://docs.giskard.ai/
- AgentDojo: https://github.com/ethz-spylab/agentdojo · https://agentdojo.spylab.ai/ · https://arxiv.org/abs/2406.13352 · https://invariantlabs.ai/blog/agentdojo

**Datasets / benchmarks**
- deepset/prompt-injections: https://huggingface.co/datasets/deepset/prompt-injections
- InjecAgent: https://arxiv.org/pdf/2403.02691
- InjecGuard / NotInject: https://arxiv.org/abs/2410.22770
- "When Benchmarks Lie" (distribution shift): https://arxiv.org/pdf/2602.14161
- HackAPrompt / dataset eval: https://hiddenlayer.com/innovation-hub/evaluating-prompt-injection-datasets/

**Techniques / trends**
- Spotlighting/datamarking: https://arxiv.org/pdf/2403.14720 · https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks
- Meta SecAlign: https://arxiv.org/abs/2507.02735
- DefensiveTokens: https://arxiv.org/pdf/2507.07974
- AgentArmor: https://arxiv.org/pdf/2508.01249
- Tool-result-parsing defense: https://arxiv.org/pdf/2601.04795

### Flagged / unverified
- **LlamaFirewall exact SPDX license** — not confirmed at source; verify on PurpleLlama repo before citing.
- **Star counts** — search-reported (2026-06-12), not all read from repo headers; re-verify before publication.
- **PINT full dataset** — proprietary; only the harness/format is open. The "92.5% Lakera Guard" figure is from Lakera's own publication (vendor self-report).
- **ProtectAI v1 "99.9%"** accuracy is on its own narrow test set and is widely considered inflated; do not cite as real-world performance.
- **InjecAgent repo URL** (`uiuc-kang-lab/InjecAgent`) inferred from the paper; confirm before linking in product docs.
