"""Conversation history and the :class:`ShieldedSession` context manager.

Multi-turn and indirect injections only reveal themselves across a *conversation*
— a single message can look benign while the sequence sets up an attack. The
:class:`ConversationHistory` gives detectors that cross-turn view, and
:class:`ShieldedSession` binds a stable identity + history to a shield so rate
limiting and history analysis work without the caller threading state by hand.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING

from .types import Direction, ScanResult

if TYPE_CHECKING:
    from .shield import Shield


@dataclass(slots=True)
class Turn:
    """One scanned message in a conversation."""

    direction: Direction
    text: str
    result: ScanResult


@dataclass
class ConversationHistory:
    """A bounded record of recent turns for cross-turn analysis.

    Bounded (``maxlen``) so memory stays flat over long-running agents. Detectors
    receive this read-only view via :class:`~shadowshield.detectors.base.ScanContext`.
    """

    maxlen: int = 50
    turns: deque[Turn] = field(default_factory=lambda: deque(maxlen=50))

    def __post_init__(self) -> None:
        if self.turns.maxlen != self.maxlen:
            self.turns = deque(self.turns, maxlen=self.maxlen)

    def add(self, direction: Direction, text: str, result: ScanResult) -> None:
        self.turns.append(Turn(direction, text, result))

    @property
    def flagged_count(self) -> int:
        """How many recorded turns were not clean — a multi-turn pressure gauge."""
        return sum(1 for t in self.turns if not t.result.is_safe or t.result.threats)

    def recent_text(self, n: int = 5, direction: Direction | None = None) -> list[str]:
        items = [t for t in self.turns if direction is None or t.direction == direction]
        return [t.text for t in list(items)[-n:]]


class ShieldedSession:
    """Stateful, per-conversation wrapper around a :class:`Shield`.

    Use as a context manager::

        with shield.session(identity="user-42") as s:
            clean = s.guard_input(user_msg)
            reply = s.guard_output(model_reply)

    All scans within the session share one identity (for rate limiting) and one
    :class:`ConversationHistory` (for multi-turn detection), and are recorded for
    inspection afterwards.
    """

    def __init__(
        self,
        shield: Shield,
        *,
        identity: str | None = None,
        history_size: int = 50,
        objective: str | None = None,
    ) -> None:
        self._shield = shield
        self.identity = identity
        # The user's stated goal for this conversation. When set (and an
        # alignment judge is wired into the shield), output scans run the
        # agent-trace alignment audit to catch goal hijacking.
        self.objective = objective
        self.history = ConversationHistory(maxlen=history_size)

    def set_objective(self, objective: str) -> None:
        """Set/replace the user's objective for alignment auditing."""
        self.objective = objective

    # -- scanning ------------------------------------------------------- #
    def scan_input(self, text: str) -> ScanResult:
        result = self._shield.scan(
            text, direction=Direction.INPUT, identity=self.identity, history=self.history
        )
        self.history.add(Direction.INPUT, text, result)
        return result

    def scan_output(self, text: str) -> ScanResult:
        result = self._shield.scan(
            text,
            direction=Direction.OUTPUT,
            identity=self.identity,
            history=self.history,
            objective=self.objective,
        )
        self.history.add(Direction.OUTPUT, text, result)
        return result

    def guard_input(self, text: str) -> str:
        """Scan input and return safe text, raising on a block (strict ergonomics)."""
        return self._shield.guard(
            text, direction=Direction.INPUT, identity=self.identity, history=self.history
        )

    def guard_output(self, text: str) -> str:
        return self._shield.guard(
            text,
            direction=Direction.OUTPUT,
            identity=self.identity,
            history=self.history,
            objective=self.objective,
        )

    # -- context manager ------------------------------------------------ #
    def __enter__(self) -> ShieldedSession:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        return None
