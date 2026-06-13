"""PII backend selection: regex (default), presidio, both — and the fail-safe
fallback to regex when Presidio isn't installed.
"""

from __future__ import annotations

import importlib.util

from shadowshield import Direction, ThreatCategory
from shadowshield.detectors import ScanContext
from shadowshield.detectors.pii import PIIDetector


def _scan(text: str, direction=Direction.OUTPUT, **options):
    det = PIIDetector()
    ctx = ScanContext.build(text, direction=direction)
    ctx.options = options
    return det.scan(text, context=ctx)


def test_regex_backend_default_detects_email() -> None:
    threats = _scan("reach me at alice@example.com")
    assert any(t.metadata.get("pii_kind") == "email" for t in threats)
    assert all(t.category is ThreatCategory.PII_LEAK for t in threats)


def test_presidio_backend_falls_back_to_regex_when_missing() -> None:
    # Presidio is an optional dep; without it the backend must fail safe to regex
    # (still detect, never crash).
    threats = _scan("card 4111 1111 1111 1111", backend="presidio")
    if importlib.util.find_spec("presidio_analyzer") is None:
        assert any(t.metadata.get("pii_kind") == "credit_card" for t in threats)


def test_both_backend_detects() -> None:
    threats = _scan("email bob@example.com", backend="both")
    assert any(t.metadata.get("pii_kind") == "email" for t in threats)


def test_kinds_filter_restricts_output() -> None:
    threats = _scan("email a@b.com and ssn 123-45-6789", kinds=["ssn"])
    kinds = {t.metadata.get("pii_kind") for t in threats}
    assert "ssn" in kinds
    assert "email" not in kinds


def test_analyzer_cache_returns_none_without_presidio() -> None:
    if importlib.util.find_spec("presidio_analyzer") is None:
        assert PIIDetector._ensure_analyzer() is None
