"""Canary-leak detector — fires when a registered canary token surfaces.

If any active canary (see :mod:`shadowshield.core.canary`) appears in scanned
text, privileged context has leaked. That is a *confirmed* successful injection
or system-prompt exfiltration, so it scores CRITICAL with very high confidence —
canaries are random, so a false positive is astronomically unlikely.

The detector reads active canaries from ``context.canaries`` (the engine fills
this from the shield's registry), which keeps the detector itself stateless.
"""

from __future__ import annotations

from ..core.types import Severity, Threat, ThreatCategory
from .base import Detector, ScanContext, register_detector


@register_detector
class CanaryLeakDetector(Detector):
    """Detects exfiltration of a planted canary token in any direction."""

    name = "canary_leak"

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        if not context.canaries:
            return []
        threats: list[Threat] = []
        for canary in context.canaries:
            idx = text.find(canary)
            if idx == -1:
                # Also check the normalised view in case the value was split by
                # invisible characters in an attempt to smuggle it past us.
                idx = context.normalized.normalized.find(canary)
                if idx == -1:
                    continue
            threats.append(
                Threat(
                    category=ThreatCategory.CANARY_TOKEN,
                    severity=Severity.CRITICAL,
                    score=0.99,
                    detector=self.name,
                    message=(
                        "Canary token leaked — privileged context was exfiltrated "
                        "(confirmed successful injection / prompt disclosure)."
                    ),
                    # Never echo the canary value itself into the audit record.
                    matched=None,
                    metadata={"canary_prefix": canary.split("-")[0]},
                )
            )
        return threats
