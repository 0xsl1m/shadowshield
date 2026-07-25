"""Opt-in reporter — queue content-free telemetry for explicit batch delivery.

The reporter enqueues :class:`~shadowshield.core.telemetry.TelemetryEvent` objects on a
bounded queue. Call :meth:`Reporter.flush` from application lifecycle code or a scheduler
to deliver batches. It is **fail-open for the app** (a down collector never blocks or
crashes a scan) and **fail-closed for data** (identity is only emitted when a tenant salt
is set; nothing but content-free metadata leaves).

Off unless explicitly attached. For tests, inject a ``transport`` callable instead of
hitting the network, and call :meth:`flush` synchronously.

    reporter = Reporter("https://collector.example/ingest", api_key="...", tenant_salt="t1")
    attach_reporter(shield, reporter)   # every scan now queues telemetry
    reporter.flush()                    # call from your scheduler/shutdown hook
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .core.telemetry import TelemetryEvent, to_telemetry
from .core.types import ScanResult

if TYPE_CHECKING:
    from .core.shield import Shield

Transport = Callable[[list[dict[str, Any]]], None]


class Reporter:
    """Bounded, batched, non-blocking telemetry sender."""

    def __init__(
        self,
        endpoint: str | None = None,
        *,
        api_key: str | None = None,
        tenant_salt: str | None = None,
        sample_rate: float = 1.0,
        max_batch: int = 200,
        queue_max: int = 10_000,
        include_text_hash: bool = False,
        transport: Transport | None = None,
    ) -> None:
        if max_batch <= 0:
            raise ValueError("max_batch must be greater than zero")
        if queue_max <= 0:
            raise ValueError("queue_max must be greater than zero")
        self.endpoint = endpoint
        self.api_key = api_key
        self.tenant_salt = tenant_salt
        self.sample_rate = max(0.0, min(1.0, sample_rate))
        self.max_batch = max_batch
        self.include_text_hash = include_text_hash
        self._q: deque[TelemetryEvent] = deque(maxlen=queue_max)
        self._lock = threading.Lock()
        self._dropped = 0
        self._sent = 0
        self._transport = transport or self._http_transport
        self._sample_scale = 1_000_000
        self._sample_units = round(self.sample_rate * self._sample_scale)
        self._sample_credit = 0

    # -- enqueue -------------------------------------------------------- #
    def record(self, result: Any, *, latency_ms: float = 0.0, identity: str | None = None) -> None:
        """Map a ScanResult to a content-free event and enqueue it (non-blocking)."""
        if self.sample_rate <= 0.0:
            return
        # Deterministic fractional accumulator: over N records this selects
        # floor(N * sample_rate), without the reciprocal-rounding bias.
        if self.sample_rate < 1.0:
            with self._lock:
                self._sample_credit += self._sample_units
                if self._sample_credit < self._sample_scale:
                    return
                self._sample_credit -= self._sample_scale
        event = to_telemetry(
            result,
            ts=time.time(),
            latency_ms=latency_ms,
            identity=identity,
            tenant_salt=self.tenant_salt,
            include_text_hash=self.include_text_hash,
        )
        with self._lock:
            if len(self._q) == self._q.maxlen:
                self._dropped += 1
            self._q.append(event)

    # -- flush ---------------------------------------------------------- #
    def flush(self) -> int:
        """Send queued events in batches. Returns the count sent. Never raises."""
        sent = 0
        while True:
            with self._lock:
                if not self._q:
                    break
                batch = [self._q.popleft() for _ in range(min(self.max_batch, len(self._q)))]
            payload = [e.to_dict() for e in batch]
            try:
                self._transport(payload)
            except Exception:
                # Fail-open: drop the batch rather than block/crash the caller.
                with self._lock:
                    self._dropped += len(batch)
                break
            sent += len(payload)
            with self._lock:
                self._sent += len(payload)
        return sent

    @property
    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"queued": len(self._q), "sent": self._sent, "dropped": self._dropped}

    # -- default HTTP transport ---------------------------------------- #
    def _http_transport(self, payload: list[dict[str, Any]]) -> None:  # pragma: no cover
        if not self.endpoint:
            raise RuntimeError("reporter endpoint is not configured")
        import httpx

        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        response = httpx.post(
            self.endpoint,
            json={"events": payload},
            headers=headers,
            timeout=5.0,
        )
        response.raise_for_status()


def attach_reporter(shield: Shield, reporter: Reporter) -> Shield:
    """Register ``reporter`` as a result observer so every scan reports telemetry.

    Routed through the engine chokepoint, so ``scan``/``guard``/``filter`` and their async
    variants are all covered. Reporting failures never affect the scan result (the engine
    swallows observer errors). Returns the same shield.
    """

    def _observe(result: ScanResult, latency_ms: float, identity: str | None) -> None:
        reporter.record(result, latency_ms=latency_ms, identity=identity)

    shield.add_result_observer(_observe)
    return shield
