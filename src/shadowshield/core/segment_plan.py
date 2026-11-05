"""Bounded planning for complete overlapping text inspection.

This module only produces spans. It does not alter the engine or proxy and
does not make a decision about whether text is trusted or safe.
"""

from __future__ import annotations


class SegmentBudgetExceeded(ValueError):
    """A complete segment plan would exceed an explicit work bound."""


def plan_segments(
    length: int,
    *,
    chunk_chars: int,
    overlap_chars: int,
    max_segments: int,
    max_scan_chars: int,
) -> tuple[tuple[int, int], ...]:
    """Plan full coverage, counting overlapped characters against the work cap.

    The caller must treat a budget exception as incomplete coverage. An
    overlap provides bounded context, not a guarantee of detecting attacks
    longer than the overlap or of detecting every attack inside a segment.
    """
    fields = (length, chunk_chars, overlap_chars, max_segments, max_scan_chars)
    if any(type(value) is not int for value in fields):
        raise TypeError("segment bounds must be integers")
    if length < 0 or chunk_chars <= 0 or not 0 <= overlap_chars < chunk_chars:
        raise ValueError("invalid length, chunk size or overlap")
    if max_segments <= 0 or max_scan_chars <= 0:
        raise ValueError("work bounds must be positive")
    if not length:
        return ()

    stride = chunk_chars - overlap_chars
    count = 1 if length <= chunk_chars else 1 + (length - chunk_chars + stride - 1) // stride
    if count > max_segments:
        raise SegmentBudgetExceeded("segment count exceeds work bound")
    last_start = (count - 1) * stride
    work = (count - 1) * chunk_chars + length - last_start
    if work > max_scan_chars:
        raise SegmentBudgetExceeded("scanned characters exceed work bound")
    return tuple(
        (index * stride, min(index * stride + chunk_chars, length)) for index in range(count)
    )
