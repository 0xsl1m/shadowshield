"""Adaptive rate limiting — throttle identities that keep tripping the shield.

A single injection attempt is noise; a stream of them from one session/user is an
*attack in progress*. This responder maintains a sliding-window counter per
identity and escalates a result to ``BLOCK`` once an identity exceeds its budget,
even if the individual payload would otherwise pass.

It is a pre-pass in the engine (runs before the policy is finalised) so it can
*raise* the decision. State is in-memory and process-local by default; for a
multi-process deployment, subclass and back :meth:`_hits` with Redis/Memcached.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable

from ..core.config import RateLimitConfig
from ..core.types import Decision, ScanResult, Severity, Threat, ThreatCategory
from ..detectors.base import ScanContext
from .base import Responder


class RateLimitResponder(Responder):
    """Sliding-window per-identity throttle that can escalate to BLOCK."""

    name = "rate_limiter"
    # It can act on anything — it runs as an engine pre-pass, not a decision
    # handler — so ``handles`` is left empty and the engine calls it directly.
    handles = ()

    def __init__(
        self, config: RateLimitConfig, *, clock: Callable[[], float] | None = None
    ) -> None:
        self._config = config
        # Injectable clock keeps the limiter unit-testable without real time.
        self._now = clock or time.monotonic
        self._events: OrderedDict[str, deque[float]] = OrderedDict()
        # New identities seen after the cardinality cap share a bounded overflow
        # budget. This preserves existing histories and prevents identity
        # rotation from evicting an attacker's own accumulated hits.
        self._overflow_events: deque[float] = deque(maxlen=config.max_events + 1)
        # The sliding-window state is shared across threads (the async API runs
        # scans in a thread pool), so the read-modify-write must be atomic — a
        # racy limiter would silently fail open.
        self._lock = threading.Lock()

    def check(self, result: ScanResult, *, context: ScanContext) -> ScanResult:
        """Record this event and escalate to BLOCK if over budget.

        Returns the (possibly escalated) result. Safe to call on every scan and
        thread-safe under concurrent scans.
        """
        if not self._config.enabled:
            return result
        identity = context.identity or "anonymous"
        if len(identity) > 256:
            import hashlib

            identity = "sha256:" + hashlib.sha256(identity.encode("utf-8")).hexdigest()

        # Optionally only count suspicious events toward the budget.
        countable = (not self._config.count_only_threats) or bool(result.threats)

        now = self._now()
        window_start = now - self._config.window_seconds
        with self._lock:
            hits = self._events.get(identity)
            overflow = False
            if hits is None:
                # Clean traffic must not allocate permanent state for arbitrary
                # attacker-selected identities.
                if not countable:
                    return result
                if len(self._events) >= self._config.max_identities:
                    oldest_identity, oldest_hits = next(iter(self._events.items()))
                    while oldest_hits and oldest_hits[0] < window_start:
                        oldest_hits.popleft()
                    if not oldest_hits:
                        del self._events[oldest_identity]
                if len(self._events) >= self._config.max_identities:
                    hits = self._overflow_events
                    overflow = True
                else:
                    hits = deque(maxlen=self._config.max_events + 1)
                    self._events[identity] = hits
            else:
                self._events.move_to_end(identity)
            while hits and hits[0] < window_start:
                hits.popleft()
            if not hits and not countable:
                if not overflow:
                    del self._events[identity]
                return result
            if countable:
                hits.append(now)
            over_budget = len(hits) > self._config.max_events
            window_hits = len(hits)

        if over_budget:
            result.decision = Decision.BLOCK
            result.severity = max(result.severity, Severity.HIGH)
            result.threats.append(
                Threat(
                    category=ThreatCategory.ANOMALY,
                    severity=Severity.HIGH,
                    score=0.8,
                    detector=self.name,
                    message=(
                        f"Identity exceeded {self._config.max_events} flagged events / "
                        f"{self._config.window_seconds:.0f}s — throttled."
                    ),
                    metadata={"window_hits": window_hits},
                )
            )
            result.metadata["rate_limited"] = True
        return result

    def apply(self, result: ScanResult, *, context: ScanContext) -> ScanResult:
        # Not used as a decision-handler; delegate to check() for completeness.
        return self.check(result, context=context)
