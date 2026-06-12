"""Internal utilities — text normalisation, logging, and score aggregation."""

from .logging import AuditLog, configure_logging
from .scoring import aggregate_score, aggregate_severity
from .text import (
    DecodedSegment,
    NormalizedText,
    extract_encoded_segments,
    normalize,
    truncate,
)

__all__ = [
    "AuditLog",
    "configure_logging",
    "aggregate_score",
    "aggregate_severity",
    "DecodedSegment",
    "NormalizedText",
    "extract_encoded_segments",
    "normalize",
    "truncate",
]
