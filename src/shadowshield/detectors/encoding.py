"""Encoding / obfuscation detection.

This detector flags the *carrier* techniques attackers use to smuggle payloads
past naive keyword filters, independent of what the payload says:

- Invisible / bidirectional control characters splitting or reordering text.
- Homoglyph (confusable) substitution.
- Hidden base64 / hex blobs that decode to readable text.

The decoded *content* is judged by ``prompt_injection`` / ``exfiltration``; here
we score the suspicious *presence* of concealment. High character-concealment in
otherwise-plain text is a strong signal on its own.
"""

from __future__ import annotations

from ..core.types import Severity, Threat, ThreatCategory
from .base import Detector, ScanContext, register_detector


@register_detector
class EncodingObfuscationDetector(Detector):
    """Flags invisible chars, homoglyphs, and decodable hidden blobs."""

    name = "encoding_obfuscation"

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        threats: list[Threat] = []
        norm = context.normalized

        if norm.had_invisible:
            threats.append(
                Threat(
                    category=ThreatCategory.ENCODING_OBFUSCATION,
                    severity=Severity.MEDIUM,
                    score=0.55,
                    detector=self.name,
                    message="Invisible / bidirectional control characters present.",
                    metadata={"technique": "invisible_chars"},
                )
            )

        if norm.had_confusables:
            threats.append(
                Threat(
                    category=ThreatCategory.ENCODING_OBFUSCATION,
                    severity=Severity.LOW,
                    score=0.4,
                    detector=self.name,
                    message="Homoglyph / confusable look-alike characters present.",
                    metadata={"technique": "homoglyphs"},
                )
            )

        for seg in context.decoded_segments:
            threats.append(
                Threat(
                    category=ThreatCategory.ENCODING_OBFUSCATION,
                    severity=Severity.MEDIUM,
                    score=0.5,
                    detector=self.name,
                    message=f"Hidden {seg.encoding} payload decodes to readable text.",
                    matched=seg.source[:120],
                    span=seg.span,
                    metadata={"technique": seg.encoding, "decoded_preview": seg.decoded[:120]},
                )
            )

        return threats
