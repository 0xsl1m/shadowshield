"""LiteLLM middleware.

LiteLLM exposes a single functional surface — ``litellm.completion(model=...,
messages=[...])`` — that normalises every provider to the OpenAI chat shape.
:func:`shielded_completion` wraps that callable (or any callable with the same
contract) so outgoing ``messages`` and the returned completion text both pass
through ShadowShield. LiteLLM itself is imported lazily, only when no explicit
callable is supplied.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import Any

from ..core.shield import Shield
from ..core.types import ThreatBlockedError
from .base import message_text


def shielded_completion(
    shield: Shield,
    completion: Callable[..., Any] | None = None,
    *,
    block_mode: str = "raise",
    identity: str | None = None,
) -> Callable[..., Any]:
    """Wrap a LiteLLM-style ``completion`` callable with input/output guarding.

    Args:
        shield: The :class:`Shield` to enforce.
        completion: The callable to wrap (default: ``litellm.completion``,
            imported lazily — requires ``pip install litellm``).
        block_mode: ``"raise"`` to raise :class:`ThreatBlockedError` on a blocked
            payload, or ``"sanitize"`` to substitute the sanitized / fallback
            text and proceed.
        identity: Stable identity for rate limiting.

    Returns:
        A callable with the same signature as ``completion``.
    """
    if completion is None:
        try:
            import litellm
        except ImportError as exc:
            raise ImportError(
                "shielded_completion requires litellm (pip install litellm) "
                "or an explicit completion callable"
            ) from exc
        completion = litellm.completion
    if block_mode not in ("raise", "sanitize"):
        raise ValueError("block_mode must be 'raise' or 'sanitize'")

    def _guard_messages(messages: list[Any]) -> list[Any]:
        guarded: list[Any] = []
        for msg in messages:
            text = message_text(msg)
            if not text:
                guarded.append(msg)
                continue
            result = shield.scan_input(text, identity=identity)
            if result.blocked and block_mode == "raise":
                raise ThreatBlockedError(result)
            if (
                result.safe_text != text
                and isinstance(msg, dict)
                and isinstance(msg.get("content"), str)
            ):
                guarded.append({**msg, "content": result.safe_text})
            else:
                guarded.append(msg)
        return guarded

    def _guard_response(response: Any) -> None:
        choices = getattr(response, "choices", None)
        if isinstance(response, dict):
            choices = response.get("choices")
        if not choices:
            return
        for choice in choices:
            message = (
                choice.get("message")
                if isinstance(choice, dict)
                else getattr(choice, "message", None)
            )
            text = message_text(message) if message is not None else ""
            if not text:
                continue
            result = shield.scan_output(text, identity=identity)
            if result.blocked and block_mode == "raise":
                raise ThreatBlockedError(result)
            if result.safe_text != text and message is not None:
                # Best effort: some response objects are immutable.
                if isinstance(message, dict):
                    message["content"] = result.safe_text
                else:
                    with contextlib.suppress(AttributeError, TypeError):
                        message.content = result.safe_text

    def guarded(*args: Any, **kwargs: Any) -> Any:
        if "messages" in kwargs and isinstance(kwargs["messages"], list):
            kwargs = {**kwargs, "messages": _guard_messages(kwargs["messages"])}
        response = completion(*args, **kwargs)
        _guard_response(response)
        return response

    return guarded


class ShieldedLiteLLM:
    """Class-style variant of :func:`shielded_completion` for symmetry with the
    other middleware adapters (and convenient attribute proxying)."""

    def __init__(
        self,
        shield: Shield,
        completion: Callable[..., Any] | None = None,
        *,
        block_mode: str = "raise",
        identity: str | None = None,
    ) -> None:
        self.completion = shielded_completion(
            shield, completion, block_mode=block_mode, identity=identity
        )
