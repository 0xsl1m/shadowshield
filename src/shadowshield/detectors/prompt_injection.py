"""The flagship detector: classic & instruction-override prompt injection.

This is ShadowShield's strongest, most-tuned layer. It targets the family of
attacks where untrusted text tries to *override the system's instructions* —
"ignore previous instructions", "you are now …", fake system blocks, and the
multi-turn / indirect variants where the override arrives via retrieved content
rather than the user's own message.

It works on the *normalised* text (so zero-width-split and homoglyph variants of
"ignore" are caught) and also re-scans any base64/hex payloads the engine
decoded, so an instruction hidden inside an encoded blob is judged on its
decoded meaning.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.types import Direction, Severity, Threat, ThreatCategory
from .base import Detector, ScanContext, register_detector


@dataclass(frozen=True)
class Signature:
    """A compiled regex signature with its threat classification."""

    pattern: re.Pattern[str]
    category: ThreatCategory
    severity: Severity
    score: float
    message: str


def _sig(
    regex: str,
    category: ThreatCategory,
    severity: Severity,
    score: float,
    message: str,
) -> Signature:
    return Signature(re.compile(regex, re.IGNORECASE), category, severity, score, message)


# Instruction-override family — the core of prompt injection.
_OVERRIDE_SIGNATURES: tuple[Signature, ...] = (
    _sig(
        r"\b(?:ignore|disregard|forget|override|bypass|skip|drop)\b[\w\s,'’]{0,40}?"
        r"\b(?:previous|prior|above|earlier|all|the|your|any|those|these|"
        r"system|current|existing|original)\b[\w\s,'’]{0,20}?"
        r"\b(?:instruction|instructions|prompt|prompts|rule|rules|context|message|"
        r"guideline|guidelines|directive|directives|policy|persona|constraint|constraints)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.9,
        "Instruction-override attempt ('ignore/disregard previous instructions').",
    ),
    _sig(
        r"\b(?:ignore|disregard|forget)\b[\w\s,'’]{0,15}?\b(?:everything|all)\b"
        r"[\w\s,'’]{0,20}?\b(?:above|before|told|said|prior|earlier|learned|taught)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.85,
        "Instruction-override attempt ('ignore/forget everything above/before').",
    ),
    _sig(
        r"\b(?:stop|cease|quit)\s+(?:following|obeying|listening to|adhering to)\b"
        r"[\w\s,'’]{0,25}?\b(?:system|instruction|instructions|rule|rules|prompt|"
        r"guidelines?|message|prior|previous)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.82,
        "Instruction-override attempt ('stop following the system message').",
    ),
    _sig(
        r"\bnew\b[\w\s]{0,10}?\b(?:instruction|instructions|rules|directive|task)\b\s*[:\-]",
        ThreatCategory.PROMPT_INJECTION,
        Severity.MEDIUM,
        0.6,
        "Attempt to inject a new instruction set.",
    ),
    _sig(
        r"\b(?:from now on|starting now|henceforth|going forward)\b[\w\s,]{0,30}?"
        r"\byou\b[\w\s]{0,10}?\b(?:are|will|must|should|shall)\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.65,
        "Behavioural reassignment ('from now on you will …').",
    ),
    _sig(
        r"\b(?:the\s+)?(?:real|actual|true)\s+(?:user|instructions?|system)\b[\w\s]{0,12}?"
        r"\b(?:say|says|is|are|wants?)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.8,
        "Authority-spoofing ('the real user/system says …').",
    ),
    _sig(
        r"\byou are (?:now\s+)?(?:a |an |the )?"
        r"(?:dan|stan|dude|aim|jailbroken|unrestricted|unfiltered|an? evil|"
        r"in developer mode|no longer)\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.HIGH,
        0.75,
        "Persona reassignment to an unrestricted/jailbreak identity.",
    ),
    _sig(
        r"\byou are now\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.55,
        "Identity reassignment ('you are now …').",
    ),
    _sig(
        r"\byou\b[\w\s]{0,8}?\b(?:follow|obey|listen to|answer to|comply with)\b\s+only\b",
        ThreatCategory.ROLE_MANIPULATION,
        Severity.MEDIUM,
        0.6,
        "Exclusive-obedience reassignment ('you follow only my rules').",
    ),
    _sig(
        r"\bthe user\b[\w\s]{0,10}?\b(?:actually|really|truly|secretly)\b"
        r"[\w\s]{0,12}?\b(?:want|wants|wanted|need|needs)\b",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.78,
        "Authority-spoofing ('the user actually wants you to …').",
    ),
)

# Fake system / role markers smuggled into untrusted content.
_FAKE_FRAME_SIGNATURES: tuple[Signature, ...] = (
    _sig(
        r"<\s*/?\s*(?:system|admin|assistant|developer|root)\s*>",
        ThreatCategory.DELIMITER_ATTACK,
        Severity.HIGH,
        0.8,
        "Fake system/role XML tag in untrusted content.",
    ),
    _sig(
        r"<\s*/?\s*system[-_]?reminder\s*>",
        ThreatCategory.PROMPT_INJECTION,
        Severity.HIGH,
        0.82,
        "Fake <system-reminder> block.",
    ),
    _sig(
        r"(?:^|\n)\s*(?:#{1,3}\s*)?(?:system|assistant|developer)\s*[:：]\s",
        ThreatCategory.DELIMITER_ATTACK,
        Severity.MEDIUM,
        0.55,
        "Chat-role delimiter injected as plain text ('system:' / 'assistant:').",
    ),
    _sig(
        r"\[\s*(?:INST|/INST|system|/system)\s*\]",
        ThreatCategory.DELIMITER_ATTACK,
        Severity.MEDIUM,
        0.6,
        "Model-specific instruction delimiter ([INST]/[system]).",
    ),
    _sig(
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>",
        ThreatCategory.DELIMITER_ATTACK,
        Severity.HIGH,
        0.75,
        "Chat-template special token injected as content.",
    ),
)

# Indirect-injection cues — language that only makes sense if the text is trying
# to address the *assistant* rather than be data. Weighted lower; corroborating.
_INDIRECT_SIGNATURES: tuple[Signature, ...] = (
    _sig(
        r"\b(?:assistant|ai|model|llm|agent|chatbot)\b[\w\s,]{0,20}?"
        r"\b(?:please|must|should|now|immediately)\b[\w\s]{0,20}?"
        r"\b(?:execute|run|call|fetch|send|reveal|print|output|delete|remove|transfer|"
        r"email|forward|grant|disable|wipe|erase|leak|exfiltrate)\b",
        ThreatCategory.INDIRECT_INJECTION,
        Severity.MEDIUM,
        0.6,
        "Document addresses the assistant with an imperative (indirect injection).",
    ),
    _sig(
        r"\bif you (?:are|'re)\b[\w\s]{0,20}?\b(?:reading|processing|summari[sz]ing)\b",
        ThreatCategory.INDIRECT_INJECTION,
        Severity.MEDIUM,
        0.6,
        "Content speaks to the model that is reading it (indirect injection).",
    ),
)

_ALL_SIGNATURES: tuple[Signature, ...] = (
    _OVERRIDE_SIGNATURES + _FAKE_FRAME_SIGNATURES + _INDIRECT_SIGNATURES
)


@register_detector
class PromptInjectionDetector(Detector):
    """Signature + heuristic detection of instruction-override injections."""

    name = "prompt_injection"
    directions = (Direction.INPUT, Direction.OUTPUT)

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        threats: list[Threat] = []
        targets = self._targets(text, context)

        for source, body in targets:
            for sig in _ALL_SIGNATURES:
                m = sig.pattern.search(body)
                if not m:
                    continue
                # An override hidden inside an encoded blob is *more* alarming,
                # not less — bump severity/score for decoded sources.
                bump = source != "text"
                threats.append(
                    Threat(
                        category=sig.category,
                        severity=Severity(
                            min(Severity.CRITICAL, sig.severity + (1 if bump else 0))
                        ),
                        score=min(1.0, sig.score + (0.05 if bump else 0.0)),
                        detector=self.name,
                        message=(f"{sig.message}" + (f" (decoded from {source})" if bump else "")),
                        matched=m.group(0)[:160],
                        span=m.span() if source == "text" else None,
                        metadata={"source": source},
                    )
                )

        # Obfuscation is itself weak evidence when it co-occurs with overrides.
        if threats and (context.normalized.had_invisible or context.normalized.had_confusables):
            threats.append(
                Threat(
                    category=ThreatCategory.ENCODING_OBFUSCATION,
                    severity=Severity.LOW,
                    score=0.4,
                    detector=self.name,
                    message="Override text was obfuscated with invisible/look-alike characters.",
                    metadata={
                        "invisible": context.normalized.had_invisible,
                        "confusables": context.normalized.had_confusables,
                    },
                )
            )
        return threats

    @staticmethod
    def _targets(text: str, context: ScanContext) -> list[tuple[str, str]]:
        """The bodies to scan: the normalised text plus each decoded segment."""
        targets: list[tuple[str, str]] = [("text", context.normalized.normalized)]
        targets.extend((seg.encoding, seg.decoded) for seg in context.decoded_segments)
        return targets
