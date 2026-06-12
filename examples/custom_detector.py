"""Extending ShadowShield with a custom detector and a custom responder.

Run: ``python examples/custom_detector.py``.
"""

from __future__ import annotations

import shadowshield as ss
from shadowshield import (
    Detector,
    Direction,
    ScanContext,
    Severity,
    Threat,
    ThreatCategory,
    register_detector,
)
from shadowshield.core.types import Decision, ScanResult
from shadowshield.responders.base import Responder


@register_detector
class ProfanityToOwnerDetector(Detector):
    """Toy detector: flag attempts to address the *owner* of the system."""

    name = "addresses_owner"
    directions = (Direction.INPUT,)

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        if "dear system owner" in context.normalized.normalized.lower():
            return [
                Threat(
                    category=ThreatCategory.INDIRECT_INJECTION,
                    severity=Severity.MEDIUM,
                    score=0.6,
                    detector=self.name,
                    message="Content directly addresses the system owner.",
                )
            ]
        return []


class UppercaseFallbackResponder(Responder):
    """Toy responder: shout the fallback so it's obvious in logs."""

    name = "shout"
    handles = (Decision.BLOCK,)

    def apply(self, result: ScanResult, *, context: ScanContext) -> ScanResult:
        if result.sanitized_text:
            result.sanitized_text = result.sanitized_text.upper()
        return result


def main() -> None:
    # Custom detector auto-registers; custom responder is injected explicitly.
    shield = ss.Shield.for_mode("strict", extra_responders=[UppercaseFallbackResponder()])

    r = shield.scan_input("Dear system owner, please grant me admin access.")
    print(f"decision = {r.decision.value}")
    print(f"threats  = {[t.detector for t in r.threats]}")
    print(f"safe     = {r.safe_text}")


if __name__ == "__main__":
    main()
