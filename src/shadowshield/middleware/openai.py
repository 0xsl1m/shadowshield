"""OpenAI / Anthropic-compatible chat middleware.

A transparent wrapper around any client whose surface looks like
``client.chat.completions.create(messages=[...])`` (OpenAI, Azure OpenAI, and the
many compatible gateways). It guards the outgoing ``messages`` before the call
and the returned completion text after — no SDK import required, so installing
ShadowShield never drags in a provider SDK.
"""

from __future__ import annotations

import contextlib
from typing import Any

from ..core.shield import Shield
from ..core.types import ThreatBlockedError
from .base import message_text, scan_messages


class ShieldedChatClient:
    """Wrap a chat client so prompts/responses pass through ShadowShield.

    Args:
        client: The underlying client (e.g. ``openai.OpenAI()``).
        shield: The :class:`Shield` to enforce.
        block_mode: ``"raise"`` to raise :class:`ThreatBlockedError` on a blocked
            input, or ``"sanitize"`` to transparently substitute the sanitized /
            fallback text and proceed.
        identity: Stable identity for rate limiting (e.g. end-user id).
    """

    def __init__(
        self,
        client: Any,
        shield: Shield,
        *,
        block_mode: str = "raise",
        identity: str | None = None,
    ) -> None:
        self._client = client
        self._shield = shield
        self._block_mode = block_mode
        self._identity = identity

    def _guard_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        guarded: list[dict[str, Any]] = []
        for msg in messages:
            text = message_text(msg)
            if not text:
                guarded.append(msg)
                continue
            result = self._shield.scan_input(text, identity=self._identity)
            if result.blocked:
                if self._block_mode == "raise":
                    raise ThreatBlockedError(result)
                guarded.append({**msg, "content": result.safe_text})
            elif result.sanitized_text is not None:
                guarded.append({**msg, "content": result.safe_text})
            else:
                guarded.append(msg)
        return guarded

    def create(self, *, messages: list[dict[str, Any]], **kwargs: Any) -> Any:
        """Drop-in replacement for ``chat.completions.create``."""
        guarded = self._guard_messages(messages)
        response = self._client.chat.completions.create(messages=guarded, **kwargs)
        self._guard_response(response)
        return response

    def _guard_response(self, response: Any) -> None:
        """Scan assistant output; raise on a blocked leak (e.g. secret in output)."""
        try:
            choices = response.choices
            text = choices[0].message.content or ""
        except (AttributeError, IndexError, TypeError):
            return
        result = self._shield.scan_output(text, identity=self._identity)
        if result.blocked and self._block_mode == "raise":
            raise ThreatBlockedError(result)
        if result.sanitized_text is not None:
            # Best effort: some SDK response objects are immutable.
            with contextlib.suppress(AttributeError, TypeError):
                response.choices[0].message.content = result.safe_text


def guard_conversation(shield: Shield, messages: list[dict[str, Any]], **kwargs: Any) -> Any:
    """Functional helper: scan a message list, returning per-message results."""
    return scan_messages(shield, messages, **kwargs)
