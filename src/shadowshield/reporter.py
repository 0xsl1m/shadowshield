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
from math import isfinite
from types import TracebackType
from typing import TYPE_CHECKING, Any

from .core.telemetry import TelemetryEvent, to_telemetry
from .core.types import ScanResult

if TYPE_CHECKING:
    from .core.shield import Shield

Transport = Callable[[list[dict[str, Any]]], None]

_MAX_RETRIES = 3
_MAX_RETRY_BACKOFF = 1.0


class Reporter:
    """Bounded, batched, non-blocking telemetry sender.

    Optional retries are immediate and bounded. A transport that accepts a batch
    and then raises may cause that batch to be delivered more than once, so
    collectors should tolerate at-least-once delivery when retries are enabled.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        *,
        api_key: str | None = None,
        tenant_salt: str | None = None,
        sample_rate: float = 1.0,
        max_batch: int = 200,
        queue_max: int = 10_000,
        max_retries: int = 0,
        retry_backoff: float = 0.1,
        include_text_hash: bool = False,
        transport: Transport | None = None,
    ) -> None:
        if max_batch <= 0:
            raise ValueError("max_batch must be greater than zero")
        if queue_max <= 0:
            raise ValueError("queue_max must be greater than zero")
        if (
            isinstance(max_retries, bool)
            or not isinstance(max_retries, int)
            or not 0 <= max_retries <= _MAX_RETRIES
        ):
            raise ValueError(f"max_retries must be an integer between 0 and {_MAX_RETRIES}")
        if isinstance(retry_backoff, bool) or not isinstance(retry_backoff, (int, float)):
            raise ValueError("retry_backoff must be a finite non-negative number")
        try:
            normalized_retry_backoff = float(retry_backoff)
        except (OverflowError, ValueError) as exc:
            raise ValueError("retry_backoff must be a finite non-negative number") from exc
        if not isfinite(normalized_retry_backoff) or normalized_retry_backoff < 0:
            raise ValueError("retry_backoff must be a finite non-negative number")
        self.endpoint = endpoint
        self.api_key = api_key
        self.tenant_salt = tenant_salt
        self.sample_rate = max(0.0, min(1.0, sample_rate))
        self.max_batch = max_batch
        self.max_retries = max_retries
        self.retry_backoff = normalized_retry_backoff
        self.include_text_hash = include_text_hash
        self._q: deque[TelemetryEvent] = deque(maxlen=queue_max)
        self._lock = threading.Lock()
        self._record_done = threading.Condition(self._lock)
        self._flush_lock = threading.Lock()
        self._closed = False
        self._records_in_flight = 0
        self._dropped = 0
        self._sent = 0
        self._transport = transport or self._http_transport
        self._sample_scale = 1_000_000
        self._sample_units = round(self.sample_rate * self._sample_scale)
        self._sample_credit = 0

    # -- enqueue -------------------------------------------------------- #
    def record(self, result: Any, *, latency_ms: float = 0.0, identity: str | None = None) -> None:
        """Map a ScanResult to a content-free event and enqueue it (non-blocking)."""
        with self._lock:
            if self._closed or self.sample_rate <= 0.0:
                return
            # Deterministic fractional accumulator: over N records this selects
            # floor(N * sample_rate), without the reciprocal-rounding bias.
            if self.sample_rate < 1.0:
                self._sample_credit += self._sample_units
                if self._sample_credit < self._sample_scale:
                    return
                self._sample_credit -= self._sample_scale
            self._records_in_flight += 1

        event: TelemetryEvent | None = None
        try:
            event = to_telemetry(
                result,
                ts=time.time(),
                latency_ms=latency_ms,
                identity=identity,
                tenant_salt=self.tenant_salt,
                include_text_hash=self.include_text_hash,
            )
        finally:
            with self._record_done:
                if event is None:
                    self._dropped += 1
                else:
                    if len(self._q) == self._q.maxlen:
                        self._dropped += 1
                    self._q.append(event)
                self._records_in_flight -= 1
                self._record_done.notify_all()

    # -- flush ---------------------------------------------------------- #
    def flush(self) -> int:
        """Send a finite queue snapshot. Returns the count sent. Never raises.

        Events recorded after this call takes its snapshot remain queued for the
        next flush, so a continuously active producer cannot make one call run
        forever. Concurrent flushes are serialized.
        """
        with self._flush_lock:
            with self._lock:
                if self._closed:
                    return 0
                snapshot = list(self._q)
                self._q.clear()
            return self._flush_snapshot(snapshot)

    def _flush_snapshot(self, snapshot: list[TelemetryEvent]) -> int:
        """Flush an immutable entry snapshot with ``_flush_lock`` held."""
        sent = 0
        for offset in range(0, len(snapshot), self.max_batch):
            batch = snapshot[offset : offset + self.max_batch]
            payload = [e.to_dict() for e in batch]
            if not self._deliver(payload):
                # Fail-open: account for this batch and the unsent snapshot tail.
                with self._lock:
                    self._dropped += len(snapshot) - offset
                break
            sent += len(payload)
            with self._lock:
                self._sent += len(payload)
        return sent

    def _deliver(self, payload: list[dict[str, Any]]) -> bool:
        for attempt in range(self.max_retries + 1):
            try:
                self._transport(payload)
            except Exception:
                if attempt == self.max_retries:
                    return False
                delay = min(self.retry_backoff * (2**attempt), _MAX_RETRY_BACKOFF)
                if delay:
                    time.sleep(delay)
            else:
                return True
        return False  # pragma: no cover - loop always returns

    def close(self) -> int:
        """Stop accepting events, flush the current queue, and drop any unsent.

        Returns the number delivered by this call. The operation is idempotent;
        after it returns, the queue is empty and :meth:`record` is a no-op.
        """
        with self._flush_lock:
            with self._record_done:
                if self._closed:
                    return 0
                self._closed = True
                while self._records_in_flight:
                    self._record_done.wait()
                snapshot = list(self._q)
                self._q.clear()
            return self._flush_snapshot(snapshot)

    def __enter__(self) -> Reporter:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

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
