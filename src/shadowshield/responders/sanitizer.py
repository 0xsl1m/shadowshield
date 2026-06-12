"""Sanitizing responder — neutralise dangerous content instead of dropping it.

Sanitization is the graceful middle ground between allow and block: keep the
*benign* meaning of a payload while defanging the parts that attack the model.
Two mechanisms:

1. **Span redaction.** Every threat that isolated a substring (``span``) is
   replaced with a typed placeholder, e.g. ``[redacted:prompt_injection]``. The
   surrounding legitimate text survives.
2. **Carrier stripping.** Invisible/bidi characters are always removed (they have
   no legitimate place in a prompt) regardless of whether a span was isolated.

The result is written to :pyattr:`ScanResult.sanitized_text`; the original is
preserved on :pyattr:`ScanResult.text` for audit.
"""

from __future__ import annotations

from ..core.types import Decision, ScanResult
from ..detectors.base import ScanContext
from ..utils.text import _INVISIBLE_RE  # internal: the invisible-char matcher
from .base import Responder


class SanitizeResponder(Responder):
    """Redacts offending spans and strips obfuscation carriers."""

    name = "sanitizer"
    handles = (Decision.SANITIZE,)

    def apply(self, result: ScanResult, *, context: ScanContext) -> ScanResult:
        text = result.text

        # Collect spans against the ORIGINAL text only (decoded-segment threats
        # carry no original span and are handled by stripping below).
        spans = sorted(
            ((t.span, t.category.value) for t in result.threats if t.span is not None),
            key=lambda s: s[0][0],
            reverse=True,  # replace right-to-left so earlier indices stay valid
        )

        for (start, end), category in spans:
            start = max(0, min(start, len(text)))
            end = max(start, min(end, len(text)))
            text = text[:start] + f"[redacted:{category}]" + text[end:]

        # Always strip invisible / bidirectional control characters.
        text = _INVISIBLE_RE.sub("", text)

        result.sanitized_text = text
        result.metadata["sanitized_by"] = self.name
        result.metadata["redactions"] = len(spans)
        return result
