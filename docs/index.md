# ShadowShield Documentation

ShadowShield is a unified, defense-in-depth security framework for agentic AI
systems. This directory is the deep-dive companion to the top-level
[`README.md`](../README.md).

## Contents

- [Security model](security-model.md) — threat taxonomy, layers, trust boundaries.
- [Detectors](detectors.md) — every built-in detector and what it catches.
- [Configuration](configuration.md) — modes, policy, weights, and YAML reference.
- [Plugins](plugins.md) — packaging custom detectors/responders for distribution.

## Mental model in one paragraph

Untrusted text (model **input** *or* **output**) is normalised once (invisibles
stripped, NFKC-folded, homoglyphs mapped, base64/hex decoded), then passed to a
suite of **detectors** that emit `Threat` findings. The findings are aggregated
with a weighted **noisy-or** into a single score + severity. A **policy** (plus a
score floor and a per-identity rate limiter) maps that to a **Decision**, which
the **responders** enact — sanitize, isolate, or block with a safe fallback —
producing a `ScanResult` and a structured audit record. The same pipeline runs
in both directions, which is what makes ShadowShield one coherent shield rather
than a detector library next to a responder library.

## The two heritages

| | Sentinel (detection) | ShadowClaw (response) |
|---|---|---|
| Question | "Is this dangerous?" | "What do we do about it?" |
| Modules | `detectors/`, `utils/` | `responders/` |
| Output | `Threat` findings, scores | sanitized text, blocks, throttles |

ShadowShield's contribution is *fusing* them behind one `Shield` object with one
config, so detection and response are never out of sync.
