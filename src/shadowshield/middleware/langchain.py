"""LangChain integration.

Provides two ergonomic entry points without importing LangChain at module load
(so the dependency stays optional):

- :func:`shield_runnable` — returns a ``RunnableLambda`` you can drop into any
  LCEL pipe (``shield_runnable(shield) | prompt | model``) to guard input.
- :class:`ShieldedChatModel` — wraps a chat model so both the prompt and the
  model's reply pass through ShadowShield on every ``invoke``.

Requires the ``langchain`` extra (``pip install shadowshield[langchain]``).
"""

from __future__ import annotations

from typing import Any

from ..core.shield import Shield
from ..core.types import Direction, ThreatBlockedError
from .base import message_text


def _require_langchain() -> Any:
    try:
        from langchain_core.runnables import RunnableLambda
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "LangChain integration requires the 'langchain' extra: "
            "pip install shadowshield[langchain]"
        ) from exc
    return RunnableLambda


def shield_runnable(shield: Shield, *, direction: Direction = Direction.INPUT) -> Any:
    """A ``RunnableLambda`` that guards string/prompt input flowing through LCEL.

    Raises :class:`ThreatBlockedError` on a blocked payload; otherwise passes the
    (possibly sanitized) text downstream.
    """
    RunnableLambda = _require_langchain()

    def _guard(value: Any) -> Any:
        text = value if isinstance(value, str) else message_text(value)
        if not text:
            return value
        return shield.guard(text, direction=direction)

    return RunnableLambda(_guard)


class ShieldedChatModel:
    """Wrap a LangChain chat model so prompts and replies are both guarded."""

    def __init__(
        self,
        model: Any,
        shield: Shield,
        *,
        identity: str | None = None,
        block_mode: str = "raise",
    ) -> None:
        self._model = model
        self._shield = shield
        self._identity = identity
        self._block_mode = block_mode

    def invoke(self, input: Any, *args: Any, **kwargs: Any) -> Any:
        text = message_text(input) if not isinstance(input, str) else input
        if text:
            res = self._shield.scan_input(text, identity=self._identity)
            if res.blocked and self._block_mode == "raise":
                raise ThreatBlockedError(res)
        output = self._model.invoke(input, *args, **kwargs)
        out_text = message_text(output)
        if out_text:
            out_res = self._shield.scan_output(out_text, identity=self._identity)
            if out_res.blocked and self._block_mode == "raise":
                raise ThreatBlockedError(out_res)
        return output

    def __getattr__(self, item: str) -> Any:
        # Transparently proxy everything else to the wrapped model.
        return getattr(self._model, item)
