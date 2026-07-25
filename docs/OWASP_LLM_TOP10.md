# ShadowShield — OWASP Top 10 for LLM Applications (2025) Coverage

**Date:** 2026-06-16 · Source: <https://genai.owasp.org/llm-top-10/>

Reported honestly: `covered` where ShadowShield provides direct runtime controls,
`partial` where it helps but the application still owns part of the control, and
`out of scope` where the risk belongs to a different layer (model scanning, SCA,
training-time governance). This table is generated from `shadowshield.core.coverage`
and matches the `shadowshield owasp` command.

**Summary:** 4 covered · 4 partial · 2 out of scope.

| ID | Risk | Status | ShadowShield mechanisms |
|---|---|---|---|
| LLM01 | Prompt Injection | ✅ covered | `prompt_injection (+ multilingual)`, `jailbreak`, `encoding_obfuscation`, `llm_self_check (opt-in)`, `transformer_classifier (opt-in)`, `vector_similarity (opt-in)`, `isolate/spotlight responder` |
| LLM02 | Sensitive Information Disclosure | ✅ covered | `pii`, `data_exfiltration (secret patterns)`, `sanitizer responder`, `redacting audit log` |
| LLM03 | Supply Chain | ⚪ out of scope | — |
| LLM04 | Data and Model Poisoning | ⚪ out of scope | `vector_similarity self-hardening (adjacent)` |
| LLM05 | Improper Output Handling | 🟡 partial | `data_exfiltration (output)`, `encoding_obfuscation`, `sanitizer responder` |
| LLM06 | Excessive Agency | ✅ covered | `alignment_check (agent-trace audit)`, `scan_tool_call`, `scan_tool_result`, `canary_leak` |
| LLM07 | System Prompt Leakage | ✅ covered | `data_exfiltration (system-prompt extraction)`, `canary_leak` |
| LLM08 | Vector and Embedding Weaknesses | 🟡 partial | `scan_tool_result (untrusted retrieved content)`, `isolate/spotlight responder` |
| LLM09 | Misinformation | 🟡 partial | `alignment_check (opt-in judge)` |
| LLM10 | Unbounded Consumption | 🟡 partial | `input_size_guard (max_input_chars)`, `rate_limiter responder` |

## Notes

- **LLM01 Prompt Injection** — Direct + indirect injection is the core focus; layered detection + active response.
- **LLM02 Sensitive Information Disclosure** — Output-side secret/PII detection stops leaks at the exit; payloads are redacted from logs.
- **LLM03 Supply Chain** — Model/dependency provenance is outside a runtime guard's remit; use model scanning + SCA.
- **LLM04 Data and Model Poisoning** — Training-time poisoning is out of scope; the vector layer can learn confirmed attack strings.
- **LLM05 Improper Output Handling** — Detects dangerous output (secrets, beacons, encoded payloads); downstream encoding/escaping is still the application's responsibility.
- **LLM06 Excessive Agency** — Tool-call guarding + goal-hijack (alignment) auditing target agent over-permission directly.
- **LLM07 System Prompt Leakage** — Blocks extraction attempts; canary tokens confirm a *successful* leak.
- **LLM08 Vector and Embedding Weaknesses** — Indirect injection via retrieved/RAG content is guarded; embedding-store access control is the application's responsibility.
- **LLM09 Misinformation** — No factuality engine; an alignment/LLM judge can flag off-objective or unsupported output.
- **LLM10 Unbounded Consumption** — Caps oversized payloads and rate-limits per identity; cost/quota controls remain app-level.
