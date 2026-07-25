"""ShadowShield coverage of the OWASP Top 10 for LLM Applications (2025).

This is the checklist AppSec teams map products against in RFPs and security
questionnaires. We report coverage *honestly* - ``covered`` / ``partial`` /
``out_of_scope`` - because over-claiming on a security checklist is a credibility
loss, and ShadowShield is a runtime guard, not a whole AI-governance program.

Source list: https://genai.owasp.org/llm-top-10/ (2025 edition).
"""

from __future__ import annotations

from dataclasses import dataclass

COVERED = "covered"
PARTIAL = "partial"
OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True, slots=True)
class OwaspItem:
    id: str
    title: str
    status: str
    mechanisms: tuple[str, ...]
    note: str


OWASP_LLM_TOP_10_2025: tuple[OwaspItem, ...] = (
    OwaspItem(
        "LLM01",
        "Prompt Injection",
        COVERED,
        (
            "prompt_injection (+ multilingual)",
            "jailbreak",
            "encoding_obfuscation",
            "llm_self_check (opt-in)",
            "transformer_classifier (opt-in)",
            "vector_similarity (opt-in)",
            "isolate/spotlight responder",
        ),
        "Direct + indirect injection is the core focus; layered detection + active response.",
    ),
    OwaspItem(
        "LLM02",
        "Sensitive Information Disclosure",
        COVERED,
        (
            "pii",
            "data_exfiltration (secret patterns)",
            "sanitizer responder",
            "redacting audit log",
        ),
        "Output-side secret/PII detection stops leaks at the exit; payloads are redacted from logs.",
    ),
    OwaspItem(
        "LLM03",
        "Supply Chain",
        OUT_OF_SCOPE,
        (),
        "Model/dependency provenance is outside a runtime guard's remit; use model scanning + SCA.",
    ),
    OwaspItem(
        "LLM04",
        "Data and Model Poisoning",
        OUT_OF_SCOPE,
        ("vector_similarity self-hardening (adjacent)",),
        "Training-time poisoning is out of scope; the vector layer can learn confirmed attack strings.",
    ),
    OwaspItem(
        "LLM05",
        "Improper Output Handling",
        PARTIAL,
        ("data_exfiltration (output)", "encoding_obfuscation", "sanitizer responder"),
        "Detects dangerous output (secrets, beacons, encoded payloads); downstream encoding/escaping "
        "is still the application's responsibility.",
    ),
    OwaspItem(
        "LLM06",
        "Excessive Agency",
        COVERED,
        (
            "alignment_check (agent-trace audit)",
            "scan_tool_call",
            "scan_tool_result",
            "canary_leak",
        ),
        "Tool-call guarding + goal-hijack (alignment) auditing target agent over-permission directly.",
    ),
    OwaspItem(
        "LLM07",
        "System Prompt Leakage",
        COVERED,
        ("data_exfiltration (system-prompt extraction)", "canary_leak"),
        "Blocks extraction attempts; canary tokens confirm a *successful* leak.",
    ),
    OwaspItem(
        "LLM08",
        "Vector and Embedding Weaknesses",
        PARTIAL,
        ("scan_tool_result (untrusted retrieved content)", "isolate/spotlight responder"),
        "Indirect injection via retrieved/RAG content is guarded; embedding-store access control is "
        "the application's responsibility.",
    ),
    OwaspItem(
        "LLM09",
        "Misinformation",
        PARTIAL,
        ("alignment_check (opt-in judge)",),
        "No factuality engine; an alignment/LLM judge can flag off-objective or unsupported output.",
    ),
    OwaspItem(
        "LLM10",
        "Unbounded Consumption",
        PARTIAL,
        ("input_size_guard (max_input_chars)", "rate_limiter responder"),
        "Caps oversized payloads and rate-limits per identity; cost/quota controls remain app-level.",
    ),
)


def owasp_coverage() -> list[dict[str, object]]:
    """Machine-readable coverage map (for the dashboard / compliance export)."""
    return [
        {
            "id": i.id,
            "title": i.title,
            "status": i.status,
            "mechanisms": list(i.mechanisms),
            "note": i.note,
        }
        for i in OWASP_LLM_TOP_10_2025
    ]


def coverage_summary() -> dict[str, int]:
    out = {COVERED: 0, PARTIAL: 0, OUT_OF_SCOPE: 0}
    for i in OWASP_LLM_TOP_10_2025:
        out[i.status] += 1
    return out


def format_coverage_text() -> str:
    mark = {
        COVERED: "[x] covered    ",
        PARTIAL: "[~] partial    ",
        OUT_OF_SCOPE: "[ ] out-of-scope",
    }
    lines = ["ShadowShield - OWASP Top 10 for LLM Applications (2025) coverage", "-" * 64]
    for i in OWASP_LLM_TOP_10_2025:
        lines.append(f"{i.id}  {mark[i.status]}  {i.title}")
        if i.mechanisms:
            lines.append(f"        via: {', '.join(i.mechanisms)}")
        lines.append(f"        {i.note}")
    s = coverage_summary()
    lines.append("-" * 64)
    lines.append(f"covered {s[COVERED]} · partial {s[PARTIAL]} · out-of-scope {s[OUT_OF_SCOPE]}")
    return "\n".join(lines)
