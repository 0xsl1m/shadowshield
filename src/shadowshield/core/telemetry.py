"""Content-free telemetry — export scan *metadata* with no payload leakage.

The privacy guarantee ("we never see your payloads") is enforced **by type**, not by a
config flag: :class:`TelemetryEvent` / :class:`ThreatMeta` simply have no field that can
hold raw payload text. The single sanctioned path from a :class:`ScanResult` to an
exportable event is :func:`to_telemetry`, which drops ``matched`` substrings, hashes the
caller identity and any canary id, and keeps span *lengths/offsets* rather than content.

See docs/REPORTER_SDK_SPEC.md. A property test asserts that a known secret in a scanned
payload never appears in the serialized event.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

from .types import ScanResult, ThreatCategory

SCHEMA_VERSION = 1


def _sha256_hex(value: str, *, salt: str = "") -> str:
    return hashlib.sha256((salt + value).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ThreatMeta:
    """Per-finding metadata — content-free by construction."""

    category: str
    detector: str
    severity: str
    score: float
    span_len: int = 0
    span_offset: int | None = None
    canary_prefix: str | None = None


@dataclass(frozen=True, slots=True)
class TelemetryEvent:
    """One scan's exportable metadata. No field can carry raw payload text."""

    schema_version: int
    ts: float
    direction: str
    decision: str
    severity: str
    score: float
    blocked: bool
    latency_ms: float
    text_len: int
    threats: list[ThreatMeta] = field(default_factory=list)
    identity_hash: str | None = None
    text_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def to_telemetry(
    result: ScanResult,
    *,
    ts: float,
    latency_ms: float = 0.0,
    identity: str | None = None,
    tenant_salt: str | None = None,
    include_text_hash: bool = False,
) -> TelemetryEvent:
    """Map a :class:`ScanResult` to a content-free :class:`TelemetryEvent`.

    ``identity`` is hashed with ``tenant_salt`` (and only emitted when a salt is given, so
    a raw identifier can never leak). ``include_text_hash`` adds a salted hash of the text
    for dedup — off by default. No ``matched`` substring, message, or decoded payload is
    ever copied.
    """
    metas: list[ThreatMeta] = []
    for t in result.threats:
        if t.span is not None:
            span_len = max(0, t.span[1] - t.span[0])
            span_offset: int | None = t.span[0]
        else:
            span_len = len(t.matched) if t.matched else 0
            span_offset = None
        # The canary detector intentionally never stores the token value; the prefix is a
        # non-sensitive label (e.g. "ss-canary"). Per-canary identification would need a
        # detector change and is out of scope here.
        canary_prefix: str | None = None
        if t.category is ThreatCategory.CANARY_TOKEN:
            cp = t.metadata.get("canary_prefix")
            canary_prefix = str(cp) if cp is not None else None
        metas.append(
            ThreatMeta(
                category=t.category.value,
                detector=t.detector,
                severity=t.severity.label,
                score=round(t.score, 4),
                span_len=span_len,
                span_offset=span_offset,
                canary_prefix=canary_prefix,
            )
        )

    identity_hash: str | None = None
    if identity is not None and tenant_salt is not None:
        identity_hash = _sha256_hex(identity, salt=tenant_salt)[:32]

    text_hash: str | None = None
    if include_text_hash:
        text_hash = _sha256_hex(result.text, salt=tenant_salt or "")

    return TelemetryEvent(
        schema_version=SCHEMA_VERSION,
        ts=ts,
        direction=result.direction.value,
        decision=result.decision.value,
        severity=result.severity.label,
        score=round(result.score, 4),
        blocked=result.blocked,
        latency_ms=round(latency_ms, 3),
        text_len=len(result.text),
        threats=metas,
        identity_hash=identity_hash,
        text_sha256=text_hash,
    )
