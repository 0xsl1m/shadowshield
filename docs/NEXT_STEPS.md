# ShadowShield — Prioritized Next Steps (and execution status)

**Date:** 2026-06-16 · Derived from UPGRADE_OPPORTUNITIES, PLAN_REVIEW, and REPORTER_SDK_SPEC.

Scope discipline (per the review): advance the **OSS engine + credibility + the cheap, reversible
build-now items**. Nothing here touches the gated multi-tenant SaaS backend, which stays behind the
design-partner pre-sell.

| # | Step | Why | Type |
|---|---|---|---|
| P1 | Content-free reporter SDK + telemetry types + no-leak property test | Last "build-now" item; export metadata to any collector with zero payload leakage | code+test |
| P2 | Span coverage fix across detectors | Threats carry offsets → dashboard highlighting + telemetry span offsets | code+test |
| P3 | Wire protection-floor policy into the control server (`/api/policy`) | Make floor-bounded config changes usable end-to-end, fail-safe | code+test |
| P4 | `shadowshield schema` — Config JSON-Schema export | Drives editor/CI validation + future UI form-gen (free from pydantic) | code+test |
| P5 | OWASP LLM Top 10 coverage map (`shadowshield owasp` + doc) | The literal checklist AppSec pastes into RFPs | code+doc+test |
| P6 | Adversarial benchmark set + loader + `benchmark --adversarial` | Credibility gate: publish honest, harder numbers | code+data+test |
| P7 | MCP tool-guard integration (transport-agnostic handler) | Meets the agentic ecosystem; differentiator | code+test |
| P8 | MIT-forever pledge (GOVERNANCE.md) | Removes the panic-relicense failure mode | doc |
| P9 | CHANGELOG + version bump → 0.6.0 | Ship the dashboard/auth/metrics/policy/reporter work | housekeeping |
| P10 | README + docs index refresh | Make all the above discoverable | doc |

Status is tracked in the task list; this table is updated to ✅ as each lands.

---

## Execution status — all 10 complete (2026-06-16)

| # | Step | Status |
|---|---|---|
| P1 | Reporter SDK + content-free telemetry | ✅ `core/telemetry.py`, `reporter.py`, `test_telemetry.py` |
| P2 | Span coverage fix | ✅ exfiltration/jailbreak/canary, `test_spans.py` |
| P3 | Protection-floor in control server | ✅ `GET/POST /api/policy`, `--policy-key` |
| P4 | `shadowshield schema` | ✅ `test_cli.py` |
| P5 | OWASP LLM Top 10 coverage | ✅ `core/coverage.py`, `shadowshield owasp`, `docs/OWASP_LLM_TOP10.md` |
| P6 | Adversarial benchmark | ✅ `benchmark --adversarial` → 83% recall / 11% FPR (honest) |
| P7 | MCP tool-guard | ✅ `integrations/ToolGuard`, `build_mcp_server`, `test_mcp_guard.py` |
| P8 | MIT-forever pledge | ✅ `GOVERNANCE.md` |
| P9 | CHANGELOG + bump 0.6.0 | ✅ |
| P10 | README + docs refresh | ✅ |

**Verification:** 144 tests pass (+19), ruff clean, mypy-strict clean across 54 source files.
Nothing touched the gated multi-tenant SaaS backend.
