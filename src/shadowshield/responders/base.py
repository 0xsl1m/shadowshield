"""Responder base class — the ShadowClaw-inspired active-defense half.

Where detectors *observe*, responders *act*: sanitize, block, isolate, throttle,
or substitute a safe fallback. The engine selects responders by the policy
:class:`~shadowshield.core.types.Decision` and applies them in order, each
returning a (possibly mutated) :class:`ScanResult`.

Responders must be **idempotent and non-raising** on the request path — a defense
that throws is a denial-of-service against your own app. Failures degrade to
"leave the result as-is" rather than crashing.
"""

from __future__ import annotations

import abc

from ..core.types import Decision, ScanResult
from ..detectors.base import ScanContext


class Responder(abc.ABC):
    """Base class for active-defense actions."""

    #: Unique identifier (audit/debug).
    name: str = "responder"

    #: Decisions this responder reacts to. The engine only calls a responder
    #: whose :pyattr:`handles` includes the result's decision.
    handles: tuple[Decision, ...] = ()

    def applies(self, result: ScanResult) -> bool:
        return result.decision in self.handles

    @abc.abstractmethod
    def apply(self, result: ScanResult, *, context: ScanContext) -> ScanResult:
        """Mutate-and-return ``result`` to enact the defense."""
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<Responder {self.name!r}>"
