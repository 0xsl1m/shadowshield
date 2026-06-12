"""Shared middleware helpers — chat-message scanning primitives.

All framework integrations reduce to the same job: pull the text out of whatever
message shape the framework uses, scan it in the right direction, and act on the
verdict. These helpers implement that once so each integration stays a thin
adapter.
"""

from __future__ import annotations

from typing import Any

from ..core.session import ConversationHistory
from ..core.shield import Shield
from ..core.types import Direction, ScanResult

# Roles whose content is untrusted *input* to the model.
_INPUT_ROLES = {"user", "tool", "function", "human"}
# Roles whose content is model *output*.
_OUTPUT_ROLES = {"assistant", "ai"}


def message_text(message: Any) -> str:
    """Best-effort extraction of text from a chat message (dict or object).

    Handles OpenAI-style dicts (``{"role", "content"}``), LangChain message
    objects (``.content``), and plain strings. Multi-part content lists are
    flattened to their text parts.
    """
    if isinstance(message, str):
        return message
    content = (
        message.get("content") if isinstance(message, dict) else getattr(message, "content", None)
    )
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # multimodal content parts
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and part.get("type") in (None, "text"):
                parts.append(str(part.get("text", "")))
        return "\n".join(parts)
    return str(content)


def message_direction(message: Any, default: Direction = Direction.INPUT) -> Direction:
    role = (
        message.get("role")
        if isinstance(message, dict)
        else getattr(message, "type", getattr(message, "role", None))
    )
    if role in _OUTPUT_ROLES:
        return Direction.OUTPUT
    if role in _INPUT_ROLES:
        return Direction.INPUT
    return default


def scan_messages(
    shield: Shield,
    messages: list[Any],
    *,
    identity: str | None = None,
    history: ConversationHistory | None = None,
) -> list[ScanResult]:
    """Scan every message in a conversation, each in its natural direction."""
    results: list[ScanResult] = []
    for msg in messages:
        text = message_text(msg)
        if not text:
            continue
        results.append(
            shield.scan(
                text,
                direction=message_direction(msg),
                identity=identity,
                history=history,
            )
        )
    return results
