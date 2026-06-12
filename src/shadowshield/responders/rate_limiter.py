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
from collections import defaultdict, deque
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
        self._events: dict[str, deque[float]] = defaultdict(deque)
        # The sliding-window state is shared across threads (the async API runs
        # scans in a thread pool), so the read-modify-write must be atomic — a
        # racy limiter would silently fail open.
        self._lock = threading.Lock()

    def _hits(self, identity: str) -> deque[float]:
        return self._events[identity]

    def check(self, result: ScanResult, *, context: ScanContext) -> ScanResult:
        """Record this event and escalate to BLOCK if over budget.

        Returns the (possibly escalated) result. Safe to call on every scan and
        thread-safe under concurrent scans.
        """
        if not self._config.enabled:
            return result
        identity = context.identity or "anonymous"

        # Optionally only count suspicious events toward the budget.
        countable = (not self._config.count_only_threats) or bool(result.threats)

        now = self._now()
        window_start = now - self._config.window_seconds
        with self._lock:
            hits = self._hits(identity)
            while hits and hits[0] < window_start:
                hits.popleft()
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
                        f"Identity '{identity}' exceeded {self._config.max_events} "
                        f"flagged events / {self._config.window_seconds:.0f}s — throttled."
                    ),
                    metadata={"identity": identity, "window_hits": window_hits},
                )
            )
            result.metadata["rate_limited"] = True
        return result

    def apply(self, result: ScanResult, *, context: ScanContext) -> ScanResult:
        # Not used as a decision-handler; delegate to check() for completeness.
        return self.check(result, context=context)
