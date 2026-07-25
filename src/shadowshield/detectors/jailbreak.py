"""Jailbreak & role-play detection.

Distinct from instruction-override (handled by ``prompt_injection``): jailbreaks
try to *unlock disallowed behaviour* by reframing the model — DAN-style personas,
"developer mode", hypothetical/fiction wrappers used to launder unsafe requests,
and explicit "no restrictions / no filters" assertions.
"""

from __future__ import annotations

import re

from ..core.types import Direction, Severity, Threat, ThreatCategory
from .base import Detector, ScanContext, locate_span, register_detector

_PATTERNS: tuple[tuple[str, Severity, float, str], ...] = (
    (
        r"\b(?:activate|enable|enter|switch to|turn on|unlock)\b[\w\s]{0,12}?"
        r"\b(?-i:DAN|STAN|DUDE|AIM)\s+(?:mode|prompt|jailbreak)\b",
        Severity.HIGH,
        0.8,
        "Activated named jailbreak persona.",
    ),
    (
        r"\b(?:respond|act|behave|answer)\s+as\s+(?-i:DAN|STAN|DUDE|AIM)\b"
        r".{0,60}?\b(?:"
        r"(?:(?:has\s+)?broken\s+free\s+of|freed\s+from)"
        r"\s+(?:(?:all|every)\s+)?(?:safety\s+)?"
        r"(?:restrictions?|rules?|filters?|limits?|guidelines?)|"
        r"no\s+longer\s+(?:bound|restricted|constrained)\s+by\s+(?:any\s+)?"
        r"(?:rules?|filters?|limits?|guidelines?|restrictions?))\b",
        Severity.HIGH,
        0.8,
        "Named jailbreak persona assigned with explicit freedom from restrictions.",
    ),
    (
        r"(?:\byou\s+(?:are\s+(?:now\s+)?in|"
        r"(?:must|should|will)\s+(?:now\s+)?"
        r"(?:enable|enter|activate|switch to|turn on|unlock))\s+"
        r"(?:developer|debug|god|sudo|root|dan|jailbreak)\s+mode\b|"
        r"\b(?:enable|enter|activate|switch to|turn on|unlock)\s+"
        r"(?:ai|model|assistant)\s+(?:developer|debug|root|admin)\s+mode\b)",
        Severity.HIGH,
        0.75,
        "Model-directed privileged 'mode' unlock attempt.",
    ),
    (
        r"\b(?:enable|enter|activate|switch to|turn on|unlock)\b[\w\s]{0,15}?"
        r"\b(?:developer|debug|god|sudo|root|dan)\s+mode\b"
        r"(?![\w\s,.;:]{0,40}\b(?:must|should|does|can|will)\s+not\b)"
        r"[\w\s,.;:]{0,60}?\b(?:bypass|disable|remove|ignore)\b"
        r"[\w\s]{0,15}?\b(?:(?:safety|content|moderation)\s+)?"
        r"(?:filters?|rules?|restrictions?|limits?)\b",
        Severity.HIGH,
        0.78,
        "Privileged mode activation paired with restriction removal.",
    ),
    (
        r"\b(?:do anything now|no longer (?:bound|restricted)|without (?:any )?(?:restrictions?|filters?|guidelines?|rules?))\b",
        Severity.HIGH,
        0.8,
        "Explicit restriction-removal request.",
    ),
    (
        r"\byou (?:have|are) no (?:restrictions?|limits?|filters?|rules?|guidelines?)\b",
        Severity.HIGH,
        0.78,
        "Assertion that the model has no restrictions.",
    ),
    (
        r"\bpretend (?:to be|you are|that you)\b|\bact as (?:if|though|an?)\b|\brole[\s-]?play(?:ing)?\b",
        Severity.MEDIUM,
        0.5,
        "Role-play framing (weak on its own; corroborating).",
    ),
    (
        r"\b(?:hypothetical(?:ly)?|in a fictional|for a (?:story|novel|movie)|"
        r"if you had no (?:guidelines?|rules?|restrictions?|limits?))\b.{0,70}?"
        r"\b(?:how (?:to|do|would|can|could|might|should|i|you)|steps?|instructions?|tutorial|make|build|create)\b",
        Severity.MEDIUM,
        0.55,
        "Fiction/hypothetical wrapper around an operational request.",
    ),
    (
        r"\bopposite day\b|\bevil (?:confidant|assistant)\b|\bunfiltered\b",
        Severity.MEDIUM,
        0.55,
        "Persona-inversion jailbreak cue.",
    ),
    (
        r"\bdo not (?:warn|lecture|refuse|mention (?:safety|ethics|guidelines))\b",
        Severity.MEDIUM,
        0.6,
        "Instruction to suppress safety behaviour.",
    ),
)

_COMPILED = tuple((re.compile(p, re.IGNORECASE | re.DOTALL), s, sc, m) for p, s, sc, m in _PATTERNS)


@register_detector
class JailbreakDetector(Detector):
    """Detects jailbreak personas, mode-unlocks, and safety-suppression cues."""

    name = "jailbreak"
    # Jailbreaks are an input-side concern; output is covered by other detectors.
    directions = (Direction.INPUT,)

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        body = context.normalized.normalized
        threats: list[Threat] = []
        for pattern, severity, score, message in _COMPILED:
            m = pattern.search(body)
            if m:
                threats.append(
                    Threat(
                        category=ThreatCategory.JAILBREAK,
                        severity=severity,
                        score=score,
                        detector=self.name,
                        message=message,
                        matched=m.group(0)[:160],
                        span=locate_span(text, m.group(0), m.span()),
                    )
                )
        return threats
