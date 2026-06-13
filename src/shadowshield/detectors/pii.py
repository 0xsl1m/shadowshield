"""PII detection — stop personal data leaking, especially in model output.

A dependency-free, precision-tuned PII detector. The headline trick is that
credit-card candidates are validated with the **Luhn checksum** before flagging,
which removes the bulk of false positives that plague naive 16-digit regexes
(order numbers, GUIDs, etc.).

PII is treated asymmetrically by direction: on **output** it's a leak (the model
is emitting someone's data) and scored higher; on **input** it's usually the user
volunteering their own data, so it's informational (LOW) unless you raise it.

For maximum accuracy you can install Microsoft Presidio (``pip install
shadowshield[pii]``) and enable it via options; the built-in regex layer always
runs and needs no dependencies.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..core.types import Direction, Severity, Threat, ThreatCategory
from .base import Detector, ScanContext, register_detector


@dataclass(frozen=True)
class PIIPattern:
    kind: str
    pattern: re.Pattern[str]
    base_score: float


_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_PHONE = re.compile(r"(?<!\d)(?:\+?1[\s.\-]?)?(?:\(\d{3}\)|\d{3})[\s.\-]\d{3}[\s.\-]\d{4}(?!\d)")
# Candidate card: 13–19 digits possibly separated by spaces/dashes.
_CARD_CANDIDATE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

_SIMPLE_PATTERNS: tuple[PIIPattern, ...] = (
    PIIPattern("email", _EMAIL, 0.6),
    PIIPattern("ssn", _SSN, 0.85),
    PIIPattern("phone", _PHONE, 0.55),
    PIIPattern("ipv4", _IPV4, 0.4),
)


def _luhn_valid(digits: str) -> bool:
    """Standard Luhn checksum — separates real card numbers from random digits."""
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# Presidio entity types -> our pii_kind labels (others pass through lowercased).
_PRESIDIO_KIND = {
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "CREDIT_CARD": "credit_card",
    "US_SSN": "ssn",
    "IP_ADDRESS": "ipv4",
    "PERSON": "person",
    "LOCATION": "location",
    "IBAN_CODE": "iban",
    "US_PASSPORT": "passport",
    "MEDICAL_LICENSE": "medical_license",
}


@register_detector
class PIIDetector(Detector):
    """Detects emails, SSNs, phones, IPs, and Luhn-valid credit-card numbers.

    Options (``DetectorConfig.options``):
        kinds: iterable of PII kinds to flag (default: all). E.g. ``["ssn",
            "credit_card"]`` to ignore emails/phones if those are expected.
        backend: ``"regex"`` (default, zero-dep), ``"presidio"`` (Microsoft
            Presidio NER+checksum recognizers — broader coverage, needs the
            ``[pii]`` extra), or ``"both"``. Presidio failures fall back to regex.
        presidio_score: minimum Presidio confidence to flag (default 0.5).
    """

    name = "pii"
    _analyzer: Any = None  # cached Presidio AnalyzerEngine

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        enabled = context.options.get("kinds")
        backend = context.options.get("backend", "regex")
        threats: list[Threat] = []

        if backend in ("regex", "both"):
            threats.extend(self._regex_threats(text, enabled, context))
        if backend in ("presidio", "both"):
            threats.extend(self._presidio_threats(text, enabled, context))
        return threats

    def _regex_threats(
        self, text: str, enabled: Iterable[str] | None, context: ScanContext
    ) -> list[Threat]:
        threats: list[Threat] = []
        for pii in _SIMPLE_PATTERNS:
            if enabled is not None and pii.kind not in enabled:
                continue
            for m in pii.pattern.finditer(text):
                threats.append(self._make(pii.kind, pii.base_score, m.span(), context))
        if enabled is None or "credit_card" in enabled:
            for m in _CARD_CANDIDATE.finditer(text):
                digits = re.sub(r"[ -]", "", m.group(0))
                if 13 <= len(digits) <= 19 and _luhn_valid(digits):
                    threats.append(self._make("credit_card", 0.85, m.span(), context))
        return threats

    def _presidio_threats(
        self, text: str, enabled: Iterable[str] | None, context: ScanContext
    ) -> list[Threat]:
        analyzer = self._ensure_analyzer()
        if analyzer is None:  # presidio unavailable -> fail safe to regex
            return self._regex_threats(text, enabled, context)
        min_score = float(context.options.get("presidio_score", 0.5))
        out: list[Threat] = []
        for res in analyzer.analyze(text=text, language="en"):
            if res.score < min_score:
                continue
            kind = _PRESIDIO_KIND.get(res.entity_type, res.entity_type.lower())
            if enabled is not None and kind not in enabled:
                continue
            out.append(self._make(kind, float(res.score), (res.start, res.end), context))
        return out

    @classmethod
    def _ensure_analyzer(cls) -> Any:
        if cls._analyzer is not None:
            return cls._analyzer
        try:
            from presidio_analyzer import AnalyzerEngine
        except ImportError:
            return None
        try:
            cls._analyzer = AnalyzerEngine()
        except Exception:  # spaCy model missing / init failure -> fall back
            return None
        return cls._analyzer

    @staticmethod
    def _make(kind: str, score: float, span: tuple[int, int], context: ScanContext) -> Threat:
        # Output-side PII is a leak (raise it); input-side is usually the user's
        # own data, so keep it strictly informational (FLAG, never sanitize/block)
        # by capping the score into the LOW band — avoids over-defending users
        # who volunteer their own email/phone.
        if context.direction is Direction.OUTPUT:
            severity = Severity.HIGH if score >= 0.8 else Severity.MEDIUM
            effective_score = score
            note = "leaving in model output"
        else:
            severity = Severity.LOW
            effective_score = min(score, 0.3)
            note = "present in input"
        return Threat(
            category=ThreatCategory.PII_LEAK,
            severity=severity,
            score=effective_score,
            detector="pii",
            message=f"Possible {kind.replace('_', ' ')} ({note}).",
            # Never copy the PII value into the threat/audit record — only its span.
            matched=None,
            span=span,
            metadata={"pii_kind": kind},
        )
