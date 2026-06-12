"""Shared, dependency-light value types used across every ShadowShield layer.

These types are the *lingua franca* of the framework: detectors emit
:class:`Threat` objects, the engine aggregates them into a :class:`ScanResult`,
the policy turns severity into a :class:`Decision`, and responders act on it.

Everything here is a plain dataclass / enum so the types stay importable with
zero heavy dependencies and are trivially serialisable for logging.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Direction(str, enum.Enum):
    """Which side of the LLM boundary a piece of text is on.

    ``INPUT`` is untrusted content flowing *toward* the model (user prompts,
    retrieved documents, tool results). ``OUTPUT`` is content flowing *back*
    from the model toward the user / downstream tools.
    """

    INPUT = "input"
    OUTPUT = "output"


class ThreatCategory(str, enum.Enum):
    """Taxonomy of the threats ShadowShield reasons about."""

    PROMPT_INJECTION = "prompt_injection"
    INDIRECT_INJECTION = "indirect_injection"
    JAILBREAK = "jailbreak"
    ROLE_MANIPULATION = "role_manipulation"
    DELIMITER_ATTACK = "delimiter_attack"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    DATA_EXFILTRATION = "data_exfiltration"
    SECRET_LEAK = "secret_leak"
    PII_LEAK = "pii_leak"
    CANARY_TOKEN = "canary_token"
    ANOMALY = "anomaly"
    UNKNOWN = "unknown"


class Severity(enum.IntEnum):
    """Ordered severity. ``IntEnum`` so thresholds compare naturally.

    The numeric value doubles as a coarse weight when aggregating scores.
    """

    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_score(cls, score: float) -> Severity:
        """Map a 0..1 confidence score onto a severity band."""
        if score >= 0.85:
            return cls.CRITICAL
        if score >= 0.65:
            return cls.HIGH
        if score >= 0.40:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.NONE


class Decision(str, enum.Enum):
    """What the policy decided should happen to a scanned payload."""

    ALLOW = "allow"
    """Clean. Pass through untouched."""

    FLAG = "flag"
    """Pass through, but record/alert — suspicious yet below the action bar."""

    SANITIZE = "sanitize"
    """Neutralise the dangerous parts and continue with the cleaned text."""

    BLOCK = "block"
    """Refuse. The payload must not reach the model / user."""

    ESCALATE = "escalate"
    """Hand off to a human / out-of-band review (never silently auto-acted)."""


@dataclass(slots=True)
class Threat:
    """A single finding produced by one detector.

    Attributes:
        category: The kind of attack this represents.
        severity: How dangerous the finding is on its own.
        score: Detector confidence in ``[0.0, 1.0]``.
        detector: Name of the detector that raised it (for audit/debug).
        message: Human-readable explanation.
        matched: The offending substring, if the detector isolated one.
        span: ``(start, end)`` indices of ``matched`` within the scanned text.
        metadata: Arbitrary structured extras (pattern id, decoded payload…).
    """

    category: ThreatCategory
    severity: Severity
    score: float
    detector: str
    message: str
    matched: str | None = None
    span: tuple[int, int] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Clamp defensively — a buggy detector should never poison aggregation.
        self.score = max(0.0, min(1.0, float(self.score)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "severity": self.severity.label,
            "score": round(self.score, 4),
            "detector": self.detector,
            "message": self.message,
            "matched": self.matched,
            "span": list(self.span) if self.span else None,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class ScanResult:
    """The unified verdict for one scanned payload.

    A ``ScanResult`` is what both ``Shield.scan`` and the middleware return. It
    carries the original text, every :class:`Threat` found, the aggregate score
    and severity, the policy :class:`Decision`, and — when a responder acted —
    the cleaned text.

    The convenience flags (:pyattr:`is_safe`, :pyattr:`blocked`) and
    :pyattr:`safe_text` exist so callers rarely have to inspect the enum
    directly.
    """

    text: str
    direction: Direction
    threats: list[Threat] = field(default_factory=list)
    score: float = 0.0
    severity: Severity = Severity.NONE
    decision: Decision = Decision.ALLOW
    sanitized_text: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_safe(self) -> bool:
        """True when the payload may flow through without intervention."""
        return self.decision in (Decision.ALLOW, Decision.FLAG)

    @property
    def blocked(self) -> bool:
        return self.decision == Decision.BLOCK

    @property
    def safe_text(self) -> str:
        """The text a caller should actually use downstream.

        Returns the sanitized text if a responder produced one, otherwise the
        original. For a blocked result this is still the original text — callers
        must check :pyattr:`blocked` / :pyattr:`is_safe` before using it.
        """
        return self.sanitized_text if self.sanitized_text is not None else self.text

    @property
    def categories(self) -> list[ThreatCategory]:
        """Distinct threat categories present, highest-severity first."""
        seen: dict[ThreatCategory, Severity] = {}
        for t in self.threats:
            if t.category not in seen or t.severity > seen[t.category]:
                seen[t.category] = t.severity
        return [c for c, _ in sorted(seen.items(), key=lambda kv: kv[1], reverse=True)]

    def top_threat(self) -> Threat | None:
        if not self.threats:
            return None
        return max(self.threats, key=lambda t: (t.severity, t.score))

    def to_dict(self) -> dict[str, Any]:
        return {
            "direction": self.direction.value,
            "decision": self.decision.value,
            "score": round(self.score, 4),
            "severity": self.severity.label,
            "is_safe": self.is_safe,
            "blocked": self.blocked,
            "threats": [t.to_dict() for t in self.threats],
            "sanitized": self.sanitized_text is not None,
            "metadata": self.metadata,
        }


class ShadowShieldError(Exception):
    """Base class for all ShadowShield exceptions."""


class ThreatBlockedError(ShadowShieldError):
    """Raised when a blocked payload is encountered in raise-on-block mode.

    Carries the full :class:`ScanResult` so callers can inspect exactly what
    tripped the shield.
    """

    def __init__(self, result: ScanResult, message: str | None = None) -> None:
        self.result = result
        top = result.top_threat()
        detail = message or (top.message if top else "blocked by ShadowShield")
        super().__init__(f"ShadowShield blocked {result.direction.value}: {detail}")
