"""Blocking & fallback responder.

When the policy decides ``BLOCK``, the payload must not reach the model (input)
or the user (output). This responder records the block and supplies a safe,
non-leaky fallback message so callers always have *something* benign to return
instead of the dangerous content.

The fallback is intentionally generic — it never echoes the offending text or the
specific detector internals to the end user, only to the audit log.
"""

from __future__ import annotations

from ..core.types import Decision, Direction, ScanResult
from ..detectors.base import ScanContext
from .base import Responder

DEFAULT_INPUT_FALLBACK = (
    "Your request could not be processed because it appears to contain "
    "instructions that conflict with this system's safety policy."
)
DEFAULT_OUTPUT_FALLBACK = (
    "The response was withheld because it may have contained unsafe or sensitive content."
)


class BlockResponder(Responder):
    """Marks a blocked result and attaches a safe fallback message."""

    name = "blocker"
    handles = (Decision.BLOCK,)

    def __init__(
        self,
        input_fallback: str = DEFAULT_INPUT_FALLBACK,
        output_fallback: str = DEFAULT_OUTPUT_FALLBACK,
    ) -> None:
        self._input_fallback = input_fallback
        self._output_fallback = output_fallback

    def apply(self, result: ScanResult, *, context: ScanContext) -> ScanResult:
        fallback = (
            self._input_fallback if result.direction is Direction.INPUT else self._output_fallback
        )
        # ``sanitized_text`` doubles as "the safe text to use instead". For a
        # block that is the fallback, never the original payload.
        result.sanitized_text = fallback
        result.metadata["blocked_by"] = self.name
        result.metadata["fallback"] = True
        return result
