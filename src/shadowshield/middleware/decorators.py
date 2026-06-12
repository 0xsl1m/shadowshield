"""Module-level convenience: a process-wide default shield + ``@protect``.

For quick scripts and notebooks you often don't want to thread a ``Shield``
instance everywhere. These helpers expose a lazily-created default shield and a
top-level :func:`protect` decorator that delegates to it. Production code should
prefer constructing and injecting an explicit :class:`Shield`.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..core.config import Mode
from ..core.shield import Shield

_default_shield: Shield | None = None


def get_default_shield() -> Shield:
    """Return (creating on first use) the process-wide default shield."""
    global _default_shield
    if _default_shield is None:
        _default_shield = Shield.for_mode(Mode.BALANCED)
    return _default_shield


def set_default_shield(shield: Shield) -> None:
    """Override the process-wide default shield (e.g. with a strict config)."""
    global _default_shield
    _default_shield = shield


def protect(func: Callable[..., Any] | None = None, **kwargs: Any) -> Any:
    """Top-level ``@protect`` decorator backed by the default shield.

    Accepts the same keyword arguments as :meth:`Shield.protect`.
    """
    return get_default_shield().protect(func, **kwargs)
