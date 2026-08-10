"""Anthropic Messages API middleware.

A transparent wrapper around any client whose surface looks like
``client.messages.create(model=..., max_tokens=..., system=..., messages=[...])``
(the official ``anthropic`` SDK and compatible gateways). It guards the outgoing
``system`` prompt and ``messages`` before the call and the returned text blocks
after — duck-typed, so installing ShadowShield never drags in the provider SDK.
"""

from __future__ import annotations

from typing import Any

from ..core.shield import Shield
from ..core.types import ThreatBlockedError
from .base import message_text


def _system_text(system: Any) -> str:
    """Extract scannable text from an Anthropic ``system`` parameter."""
    if isinstance(system, str):
        return system
    if isinstance(system, list):  # list of TextBlock-like dicts
        return "\n".join(
            str(block.get("text", ""))
            for block in system
            if isinstance(block, dict) and block.get("type") in (None, "text")
        )
    return ""


def _response_block_texts(response: Any) -> list[str]:
    """Pull text out of an Anthropic response's content blocks."""
    texts: list[str] = []
    for block in getattr(response, "content", None) or []:
        text = block.get("text") if isinstance(block, dict) else getattr(block, "text", None)
        if isinstance(text, str) and text:
            texts.append(text)
    return texts


class ShieldedAnthropicClient:
    """Wrap an Anthropic-style client so prompts and replies are guarded.

    Args:
        client: The underlying client (e.g. ``anthropic.Anthropic()``).
        shield: The :class:`Shield` to enforce.
        block_mode: ``"raise"`` to raise :class:`ThreatBlockedError` on a blocked
            payload, or ``"sanitize"`` to substitute the sanitized / fallback
            text and proceed.
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
        if block_mode not in ("raise", "sanitize"):
            raise ValueError("block_mode must be 'raise' or 'sanitize'")
        self._client = client
        self._shield = shield
        self._block_mode = block_mode
        self._identity = identity

    # ------------------------------------------------------------------ #
    def _act_on_input(self, text: str) -> str | None:
        """Return the text to send (possibly sanitized), or None to raise."""
        result = self._shield.scan_input(text, identity=self._identity)
        if result.blocked and self._block_mode == "raise":
            raise ThreatBlockedError(result)
        return result.safe_text

    def _guard_kwargs(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        guarded = dict(kwargs)
        system = guarded.get("system")
        system_text = _system_text(system)
        if system_text:
            safe = self._act_on_input(system_text)
            if safe != system_text:
                guarded["system"] = safe
        messages = guarded.get("messages")
        if isinstance(messages, list):
            new_messages = []
            for msg in messages:
                text = message_text(msg)
                if not text:
                    new_messages.append(msg)
                    continue
                safe = self._act_on_input(text)
                if safe != text and isinstance(msg, dict) and isinstance(msg.get("content"), str):
                    new_messages.append({**msg, "content": safe})
                else:
                    new_messages.append(msg)
            guarded["messages"] = new_messages
        return guarded

    def _guard_response(self, response: Any) -> None:
        for text in _response_block_texts(response):
            result = self._shield.scan_output(text, identity=self._identity)
            if result.blocked and self._block_mode == "raise":
                raise ThreatBlockedError(result)

    # ------------------------------------------------------------------ #
    def create(self, **kwargs: Any) -> Any:
        """Drop-in replacement for ``client.messages.create``."""
        guarded = self._guard_kwargs(kwargs)
        response = self._client.messages.create(**guarded)
        self._guard_response(response)
        return response

    @property
    def messages(self) -> Any:
        """Expose a ``.messages`` namespace mirroring the wrapped client."""
        return _MessagesNamespace(self)

    def __getattr__(self, item: str) -> Any:
        # Transparently proxy everything else to the wrapped client.
        return getattr(self._client, item)


class _MessagesNamespace:
    """Makes ``shielded.messages.create(...)`` work like the raw client."""

    def __init__(self, outer: ShieldedAnthropicClient) -> None:
        self._outer = outer

    def create(self, **kwargs: Any) -> Any:
        return self._outer.create(**kwargs)

    def __getattr__(self, item: str) -> Any:
        return getattr(self._outer._client.messages, item)


def guard_anthropic_conversation(
    shield: Shield,
    messages: list[dict[str, Any]],
    *,
    system: Any = None,
    identity: str | None = None,
) -> None:
    """Functional helper: raise :class:`ThreatBlockedError` if anything blocks."""
    texts = [_system_text(system)] if system is not None else []
    texts += [message_text(m) for m in messages]
    for text in texts:
        if not text:
            continue
        result = shield.scan_input(text, identity=identity)
        if result.blocked:
            raise ThreatBlockedError(result)
