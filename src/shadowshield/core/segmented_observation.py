"""Experimental bounded observations, never enforcement or protocol coverage.

This scans cheap detectors over windows only. It cannot establish detector
parity, recognize attacks longer than an overlap, or establish safe policy.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..detectors.base import ScanContext
from .segment_plan import SegmentBudgetExceeded, plan_segments
from .types import Direction, Severity, Threat


@dataclass(frozen=True, slots=True)
class SegmentFinding:
    detector: str
    category: str
    severity: Severity
    score: float
    span: tuple[int, int] | None


@dataclass(frozen=True, slots=True)
class SegmentObservation:
    status: str
    reason: str
    window_count: int = 0
    findings: tuple[SegmentFinding, ...] = ()


def observe_windows(
    text: str,
    *,
    direction: Direction,
    scan: Callable[[str, ScanContext], list[Threat]],
    chunk_chars: int,
    overlap_chars: int = 1024,
    max_segments: int = 16,
    max_scan_chars: int = 1_000_000,
    max_findings: int = 512,
) -> SegmentObservation:
    """Discard all partial results on failure; never retain content or errors."""
    try:
        spans = plan_segments(
            len(text),
            chunk_chars=chunk_chars,
            overlap_chars=min(overlap_chars, chunk_chars // 4),
            max_segments=max_segments,
            max_scan_chars=max_scan_chars,
        )
    except SegmentBudgetExceeded:
        return SegmentObservation("unavailable", "budget_exceeded")
    except Exception:
        return SegmentObservation("unavailable", "invalid_bounds")
    located: dict[tuple[str, str, tuple[int, int]], SegmentFinding] = {}
    unlocated: list[SegmentFinding] = []
    try:
        for start, end in spans:
            window = text[start:end]
            context = ScanContext.build(window, direction=direction)
            if context.metadata.get("decoded_segments_truncated"):
                return SegmentObservation("unavailable", "decoded_segments_truncated")
            threats = scan(window, context)
            if context.detector_errors or context.metadata.get("findings_truncated"):
                return SegmentObservation("unavailable", "scanner_incomplete")
            for threat in threats:
                span = threat.span
                if span is not None:
                    if (
                        not isinstance(span, tuple)
                        or len(span) != 2
                        or any(type(i) is not int for i in span)
                        or not 0 <= span[0] < span[1] <= len(window)
                    ):
                        return SegmentObservation("unavailable", "invalid_finding_span")
                    if threat.matched is None or window[span[0] : span[1]] != threat.matched:
                        span = None
                    else:
                        span = (start + span[0], start + span[1])
                finding = SegmentFinding(
                    threat.detector, threat.category.value, threat.severity, threat.score, span
                )
                if span is None:
                    unlocated.append(finding)
                else:
                    key = (finding.detector, finding.category, span)
                    old = located.get(key)
                    if old is None or (finding.severity, finding.score) > (old.severity, old.score):
                        located[key] = finding
                if len(located) + len(unlocated) > max_findings:
                    return SegmentObservation("unavailable", "findings_budget_exceeded")
    except Exception:
        return SegmentObservation("unavailable", "scanner_error")
    return SegmentObservation(
        "observed", "cheap_detectors_only", len(spans), tuple(located.values()) + tuple(unlocated)
    )
