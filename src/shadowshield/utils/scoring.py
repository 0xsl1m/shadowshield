"""Aggregation of many per-detector threats into one payload-level verdict.

The aggregation philosophy is **noisy-or with severity weighting**: independent
detectors each raise the overall suspicion, but no single weak signal can be
washed out by averaging. A confident HIGH from one detector should dominate even
if ten other detectors stayed silent — averaging would dilute it, which is the
wrong failure mode for security.
"""

from __future__ import annotations

from ..core.types import Severity, Threat
from .text import truncate  # noqa: F401  (re-exported for convenience)


def aggregate_score(threats: list[Threat], weights: dict[str, float] | None = None) -> float:
    """Combine weighted detector scores via a noisy-or.

    Each threat contributes ``p_i = clamp(score * weight)``. The combined
    probability that *something* is wrong is ``1 - Π(1 - p_i)`` — monotonic,
    bounded in ``[0, 1]``, and order-independent. More corroborating detectors
    push the score up; one strong detector already pushes it high.
    """
    if not threats:
        return 0.0
    weights = weights or {}
    complement = 1.0
    for t in threats:
        w = weights.get(t.detector, 1.0)
        p = max(0.0, min(1.0, t.score * w))
        complement *= 1.0 - p
    return 1.0 - complement


def aggregate_severity(threats: list[Threat], score: float) -> Severity:
    """The payload severity is the max of the strongest finding and the
    score-implied band — so a pile of LOW findings that together score HIGH is
    treated as HIGH, and a lone CRITICAL is never downgraded by a low aggregate.
    """
    by_threat = max((t.severity for t in threats), default=Severity.NONE)
    by_score = Severity.from_score(score)
    return max(by_threat, by_score)
