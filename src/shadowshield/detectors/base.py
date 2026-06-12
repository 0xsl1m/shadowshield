"""Detector base class, the shared scan context, and the registry.

A *detector* is a pure, stateless function of (text, context) -> threats. Keeping
detectors stateless makes them trivially testable, parallelisable, and safe to
share across sessions. Anything stateful (history, rate counters) lives on the
:class:`ScanContext` the engine hands in.
"""

from __future__ import annotations

import abc
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from ..core.types import Direction, Threat
from ..utils.text import DecodedSegment, NormalizedText, extract_encoded_segments, normalize

if TYPE_CHECKING:
    from ..core.session import ConversationHistory


@dataclass
class ScanContext:
    """Everything a detector needs beyond the raw text.

    The engine builds one context per scan and reuses the expensive normalised
    view / decoded segments across all detectors, so each detector pays that
    cost zero times.

    Attributes:
        direction: Whether this is model input or output.
        normalized: De-obfuscated view of the text (see :func:`utils.text.normalize`).
        decoded_segments: Any base64/hex payloads found hidden in the text.
        history: Conversation history for multi-turn / indirect-injection checks.
        options: The active detector's per-deployment ``options`` dict.
        identity: Opaque caller identity (session/user id) for rate limiting.
        metadata: Free-form scratch space shared across detectors in one scan.
    """

    direction: Direction
    normalized: NormalizedText
    decoded_segments: list[DecodedSegment] = field(default_factory=list)
    history: ConversationHistory | None = None
    options: dict[str, Any] = field(default_factory=dict)
    identity: str | None = None
    canaries: tuple[str, ...] = ()
    objective: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        text: str,
        *,
        direction: Direction,
        history: ConversationHistory | None = None,
        identity: str | None = None,
        canaries: tuple[str, ...] = (),
        objective: str | None = None,
    ) -> ScanContext:
        return cls(
            direction=direction,
            normalized=normalize(text),
            decoded_segments=extract_encoded_segments(text),
            history=history,
            identity=identity,
            canaries=canaries,
            objective=objective,
        )


class Detector(abc.ABC):
    """Base class for all detectors.

    Subclasses set a unique :pyattr:`name` and implement :meth:`scan`. They may
    declare which :pyattr:`directions` they apply to (default: both) — the engine
    skips a detector whose directions don't include the current one.
    """

    #: Unique, stable identifier. Used in config, weights, and audit logs.
    name: str = "detector"

    #: Which directions this detector is meaningful for.
    directions: tuple[Direction, ...] = (Direction.INPUT, Direction.OUTPUT)

    def applies_to(self, direction: Direction) -> bool:
        return direction in self.directions

    @abc.abstractmethod
    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        """Return zero or more :class:`Threat` findings for ``text``.

        Implementations should prefer ``context.normalized.normalized`` for
        matching (de-obfuscated) but report spans/excerpts against the original
        ``text`` where possible so audit logs are meaningful.
        """
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<Detector {self.name!r}>"


# ---------------------------------------------------------------------- #
# Registry
# ---------------------------------------------------------------------- #
_REGISTRY: dict[str, type[Detector]] = {}


def register_detector(cls: type[Detector]) -> type[Detector]:
    """Class decorator that makes a detector discoverable by the engine.

    Raises if two detectors claim the same :pyattr:`name`, which would otherwise
    silently shadow one another.
    """
    name = cls.name
    if name in _REGISTRY and _REGISTRY[name] is not cls:
        raise ValueError(
            f"Detector name collision: {name!r} already registered by "
            f"{_REGISTRY[name].__module__}.{_REGISTRY[name].__qualname__}"
        )
    _REGISTRY[name] = cls
    return cls


def registered_detectors() -> dict[str, type[Detector]]:
    """A copy of the current registry (name -> class)."""
    return dict(_REGISTRY)


def build_detectors(
    *,
    is_enabled: Callable[[str], bool],
) -> list[Detector]:
    """Instantiate every registered detector that ``is_enabled`` approves."""
    return [cls() for name, cls in _REGISTRY.items() if is_enabled(name)]
