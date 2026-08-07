# ShadowShield — Comprehensive Audit Report

**Project:** shadowshield v0.6.3 (`C:\Users\jhwil\Documents\OpenClaw VPS\shadowshield`)
**Audit date:** 2026-08-05 · **Auditor:** Kimi Work (automated code audit)
**Scope:** full repository — source, tests, packaging, CI/CD, container, docs, dependency & secret hygiene

---

## 1. Executive summary

ShadowShield is a unified open-source security shield for agentic AI systems
(prompt-injection / jailbreak / PII / exfiltration detection with a
detect → decide → respond engine, plus an optional FastAPI control plane).

**Overall verdict: strong.** This is an unusually disciplined codebase for a
0.x project: the full test suite passes, strict mypy and Ruff are clean, the
threat model is documented and consistently implemented, and the release
pipeline is among the most hardened seen in open-source Python (hash-locked
builds, reproducible-build gate, pinned actions, Trivy gates, OIDC publishing,
fail-closed container startup tests). Findings are limited to one
medium-severity API design issue and a set of low-severity gaps.

**Verification results from this audit run (2026-08-05):**

| Check | Result |
|---|---|
| Test suite (`pytest tests`) | **320 passed, 2 skipped** (opt-in real-model tests), 38.8 s |
| Ruff lint | **Clean** (`All checks passed!`) |
| mypy (strict, 54 source files) | **Clean** (`no issues found`) |
| Coverage | **86%** total (branch), gate `fail_under = 80` met |
| pip-audit (installed environment) | **No known vulnerabilities** |
| Dangerous-sink scan (`eval/exec/pickle/subprocess/shell=True/yaml.load`) | **None in `src/`** |
| Committed-secret scan (AWS/GitHub/OpenAI key patterns, private keys) | **None** (2 hits are intentional test fixtures) |
| Git working tree | Clean; 146 tracked files; build artifacts correctly ignored |

---

## 2. Strengths confirmed

### 2.1 Detection core
- **ReDoS-conscious regexes.** Signature patterns use bounded quantifiers
  (`[\w\s,'’]{0,40}?` etc.); multilingual regex groups are pre-filtered by
  cheap vocabulary cues before running (`_candidate_signatures`,
  `prompt_injection.py:487`). Exfiltration detector explicitly documents a
  rewrite away from a quadratic pattern.
- **Defense in depth.** Normalization (zero-width, homoglyph, bidi stripping),
  base64/hex payload decoding with re-scan and severity bump, canary tokens for
  detecting *successful* injections, optional transformer/vector/LLM-judge
  layers that are lazy-imported and never pulled in by the base install.
- **Bounded outputs.** `MAX_FINDINGS_PER_DETECTOR`, truncated matched text
  (`m.group(0)[:160]`), content-free telemetry — detection failures cannot
  amplify into memory or leak content into logs.

### 2.2 HTTP control plane (`_security.py`, `control.py`, `server.py`)
- **Fail-closed by default:** the app factory raises if API/admin keys are
  missing; insecure mode requires an explicit `allow_insecure_local=True`.
- **Early authentication** before body reads; constant-time key comparison via
  `hmac.compare_digest` (byte-safe for non-ASCII input).
- **Intake hardening:** 1 MiB body cap, 8,192-frame cap, single 15 s total read
  deadline (defeats slow/chunked-body starvation of admission slots),
  503-with-`Retry-After` concurrency cap (16) on scan paths, `OPTIONS`
  authenticated like other requests.
- **Credential hygiene enforced at startup:** scan keys, admin keys, policy
  signing key, and policy-state key must all be pairwise distinct
  (constant-time overlap check); policy-state key has a minimum length.
- **Browser hardening:** CSP, `nosniff`, `DENY` framing, `no-store`, COOP,
  conditional HSTS; docs/redoc/openapi endpoints disabled.

### 2.3 Policy push (`core/policy.py`) — the standout design
Signed (HMAC-SHA256, pluggable verifier) config bundles with a **structural
protection floor**: allow-listed fields only, always-on detectors cannot be
disabled or de-weighted below baseline, block-threshold ceiling, aggregate
degradation cap, fail-safe (never fail-open) semantics with durable HMAC'd
anti-replay state. A compromised control plane cannot remotely weaken the
fleet — this is the correct threat model, implemented end-to-end.

### 2.4 Supply chain & CI
- All GitHub Actions **SHA-pinned**; `persist-credentials: false`; read-only
  token permissions; actionlint gate.
- **Reproducible-build gate** (double build + `cmp`), Twine metadata check,
  installed-wheel smoke test.
- Hash-locked build/container lockfiles (`uv pip compile --generate-hashes`),
  `--require-hashes` installs in the Dockerfile; base image **digest-pinned**.
- Per-extra dependency-audit matrix (dynamically discovered), Trivy SBOM +
  fail-on-fixable-CRITICAL/HIGH gate, PyPI OIDC publishing, SLSA/CycloneDX
  attestations, Dependabot, pre-commit.
- Container: non-root user, read-only root fs, `cap_drop: ALL`,
  `no-new-privileges`, pids/mem/cpu limits, healthcheck; CI proves the image
  **refuses to start without keys** and exercises 401/200/413 paths end-to-end.

### 2.5 Honest posture
`docs/PRODUCTION_READINESS.md` reports blind-generalization detection honestly
(v3: 30% ASR / 30% FPR — labeled **Beta**, not oversold), separates
library-ready vs operator-owned items, and the changelog is precise about what
each release changed.

---

## 3. Findings

### M-1 (Medium) — `apply_bundle` accepts unsigned bundles when no verifier is passed
`src/shadowshield/core/policy.py:250` — `if verifier is not None and not
verifier(bundle): raise PolicyRejected`. When the caller omits `verifier`, an
**unsigned bundle is silently applied**, contradicting the module's own
documented invariant ("an unsigned/badly-signed bundle is rejected"). The
control plane compensates (`control.py:1286` rejects remote updates when no
verifier exists unless `allow_insecure_local`), so the deployed path is safe —
but the **library API itself is fail-open by default**, and any future caller
that forgets the verifier gets no protection.

**Recommendation:** make verification mandatory by default — e.g. raise unless
`verifier` is provided, or add an explicit `allow_unsigned: bool = False`
opt-in so skipping signature checks is a deliberate, greppable decision.

### L-1 (Low) — Coverage gaps in glue/integration code
86% overall, but: `middleware/langchain.py` **0%**, `plugins/manager.py` 33%,
`integrations/agentdojo.py` 23%, `middleware/base.py` 57%, `detectors/pii.py`
77%. LangChain middleware and the plugin manager are user-facing extension
points; their error paths are exactly where misuse bugs live. The AgentDojo
adapter is acceptable to leave low (needs API keys), but langchain middleware
and plugin-manager state transitions deserve unit tests with fakes.

### L-2 (Low) — `control.py` is a 1,448-line god-file
App factory, auth, policy endpoints, metrics/Prometheus, dashboard HTML, and
CLI glue in one module. It is well organized internally, but this size raises
audit cost and regression risk per edit. Consider splitting into
`control/auth.py`, `control/policy_api.py`, `control/metrics.py`,
`control/dashboard.py`.

### L-3 (Low) — Reporter transport hardening
`reporter.py:_http_transport`: TLS verification relies on httpx defaults
(fine), but there is no scheme enforcement — an `http://` endpoint would ship
telemetry plus the `x-api-key` header in cleartext. Add an https-only check
(or loud warning) at construction. The bounded queue with silent drop-counting
is good; consider emitting a log line when drops begin so operators notice
collector outages.

### L-4 (Low) — Sanitizer overlapping spans
`sanitizer.py` replaces spans right-to-left with index clamping — correct for
nested/disjoint spans, but two overlapping detector spans can yield nested
`[redacted:…]` placeholders. Harmless (no corruption), but a span-merge pass
would produce cleaner output.

### L-5 (Info) — Local pip-audit of `container.lock` fails offline
`pip-audit -r requirements/container.lock` errors locally because the lock
contains a direct-URL `colorama` entry combined with `--require-hashes`. CI
audits it with `--no-deps`, which passes — so this is a reproduction quirk,
not a defect. Worth one line in `requirements/` docs for anyone auditing
locally.

### L-6 (Info) — Local environment drift
`uvicorn` is not installed in the local `.venv` despite being in the
`dashboard` extra (tests pass regardless). Also `.coverage`/`coverage.xml`/
`dist/`/`production-dist/` artifacts exist locally (all correctly gitignored).
Housekeeping only.

---

## 4. Non-findings (checked, no issue)

- **Committed secrets:** none. Two regex hits are deliberate detector test
  fixtures (`tests/test_detectors.py:131`, `tests/test_telemetry.py:19`).
- **`.env.example`:** empty values by design; `compose.yaml` uses
  `${VAR:?…}` so copying the example can never boot with placeholder creds.
- **Dangerous dynamic execution:** no `eval/exec/pickle/subprocess/shell=True`
  in `src/`; YAML usage is safe; FastAPI apps disable introspection endpoints.
- **Skipped tests:** both skips are opt-in real-model tests covered by the
  dedicated `ml-integration` CI job, not silent gaps.
- **Site headers:** `site/vercel.json` ships a strict CSP with per-script
  hashes, HSTS preload, and a restrictive Permissions-Policy.

## 5. Recommended next actions (priority order)

1. **M-1:** make bundle signature verification non-skippable by default in
   `core/policy.py` (small change, closes the only fail-open path).
2. **L-1:** add unit tests for `middleware/langchain.py` and
   `plugins/manager.py` error paths.
3. **L-2:** split `control.py` before it grows further.
4. **L-3:** enforce https (or warn) on `Reporter` endpoints.
5. Keep the blind-benchmark program running; the honest Beta label is a
   strength — protect it.

---

*Verification commands: `.venv/Scripts/python.exe -m pytest tests -q`,
`-m ruff check .`, `-m mypy`, `-m coverage report`,
`uv tool run pip-audit --path .venv/Lib/site-packages`,
plus targeted source review of `_security.py`, `core/policy.py`,
`core/engine.py`, `responders/sanitizer.py`, `reporter.py`, `control.py`,
CI workflows, Dockerfile, and `compose.yaml`.*
