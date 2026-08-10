"""Incremental stream scanning — cut a malicious stream *mid-flight*.

``Shield.scan`` evaluates a complete string. Modern LLM apps stream tokens, so
whole-string scanning forces a bad trade: buffer the entire completion (adds
latency, defeats streaming) or scan nothing. :class:`StreamScanner` closes that
gap:

- Chunks are appended to a bounded pending buffer.
- Every ``scan_interval_chars`` of new text, the buffer (plus a carry-over from
  the previous window so signatures/secrets split across chunk boundaries still
  match) is scanned through the normal engine — same detectors, same policy.
- The first BLOCK/ESCALATE decision is **terminal**: ``feed`` returns the
  result immediately so the caller can cut the stream before the rest of a
  leaked secret or injected payload is emitted/sent.
- ``finalize`` flushes the tail and returns the worst verdict seen, so a clean
  stream yields one final ALLOW-style result.

Memory is bounded: only the carry-over plus not-yet-scanned text is retained,
never the whole stream. The scanner is deliberately sync (engine scans are
CPU-bound); async callers can ``await asyncio.to_thread(scanner.feed, chunk)``.
"""

from __future__ import annotations

from ..core.types import Decision, Direction, ScanResult
from .shield import Shield

#: Decisions that terminate the stream immediately.
TERMINAL_DECISIONS = frozenset({Decision.BLOCK, Decision.ESCALATE})

#: Total order for "worst verdict seen" aggregation (mirrors the engine's rank).
_DECISION_RANK: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.FLAG: 1,
    Decision.SANITIZE: 2,
    Decision.BLOCK: 3,
    Decision.ESCALATE: 4,
}


class StreamScanner:
    """Incrementally scan a streamed payload with early-block semantics.

    Args:
        shield: the :class:`Shield` whose engine/policy performs each scan.
        direction: scan direction (default OUTPUT — the common case is guarding
            a model's streamed completion).
        identity: optional caller identity forwarded to the engine (rate limits).
        scan_interval_chars: scan after at least this much new text arrives.
        carry_chars: overlap retained between scan windows so signatures,
            base64 blobs, and secrets split across chunk boundaries still match.
            Must exceed the longest pattern an attacker could split.
        block_on: decisions that terminate the stream (default BLOCK+ESCALATE).
    """

    def __init__(
        self,
        shield: Shield,
        *,
        direction: Direction = Direction.OUTPUT,
        identity: str | None = None,
        scan_interval_chars: int = 256,
        carry_chars: int = 2_048,
        block_on: frozenset[Decision] = TERMINAL_DECISIONS,
    ) -> None:
        if scan_interval_chars <= 0:
            raise ValueError("scan_interval_chars must be greater than zero")
        if carry_chars < 0:
            raise ValueError("carry_chars must be non-negative")
        self._shield = shield
        self._direction = direction
        self._identity = identity
        self._scan_interval = scan_interval_chars
        self._carry_chars = carry_chars
        self._block_on = block_on
        self._pending: list[str] = []
        self._pending_len = 0
        self._carry = ""
        self._terminal: ScanResult | None = None
        self._worst: ScanResult | None = None
        self._finalized = False

    # ------------------------------------------------------------------ #
    @property
    def blocked(self) -> bool:
        """True once the stream has been terminally blocked."""
        return self._terminal is not None

    @property
    def terminal_result(self) -> ScanResult | None:
        """The result that terminated the stream, if any."""
        return self._terminal

    def feed(self, chunk: str) -> ScanResult | None:
        """Append one chunk; return the terminal result the moment it blocks.

        Returns ``None`` while the stream is still clean (or no scan interval
        has elapsed). After termination, subsequent calls return the same
        terminal result — streaming loops can keep draining without special
        casing. Feeding after :meth:`finalize` raises :class:`RuntimeError`.
        """
        if self._finalized:
            raise RuntimeError("cannot feed a finalized stream scanner")
        if self._terminal is not None:
            return self._terminal
        if not chunk:
            return None
        self._pending.append(chunk)
        self._pending_len += len(chunk)
        if self._pending_len < self._scan_interval:
            return None
        return self._scan_window()

    def finalize(self) -> ScanResult:
        """Flush the tail and return the worst verdict seen over the stream.

        Idempotent: repeated calls return the same aggregate result. A stream
        that was blocked mid-flight returns the terminal result.
        """
        if self._terminal is not None:
            self._finalized = True
            return self._terminal
        if self._finalized:
            assert self._worst is not None
            return self._worst
        self._finalized = True
        self._scan_window(final=True)
        if self._terminal is not None:
            return self._terminal
        assert self._worst is not None
        return self._worst

    # ------------------------------------------------------------------ #
    def _scan_window(self, *, final: bool = False) -> ScanResult | None:
        body = self._carry + "".join(self._pending)
        self._pending = []
        self._pending_len = 0
        if not body.strip():
            if final and self._worst is None:
                # Empty stream: one canonical empty scan so callers always get
                # a real ScanResult out of finalize().
                self._worst = self._shield.scan(
                    "", direction=self._direction, identity=self._identity
                )
            return None
        # Slide the carry window forward for the next scan.
        self._carry = body[-self._carry_chars :] if self._carry_chars else ""
        result = self._shield.scan(body, direction=self._direction, identity=self._identity)
        self._record(result)
        return self._terminal

    def _record(self, result: ScanResult) -> None:
        if result.decision in self._block_on:
            self._terminal = result
        if (
            self._worst is None
            or _DECISION_RANK[result.decision] > _DECISION_RANK[self._worst.decision]
        ):
            self._worst = result
