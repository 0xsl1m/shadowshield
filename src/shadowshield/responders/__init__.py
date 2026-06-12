"""Active-defense layer — the ShadowClaw-inspired half of ShadowShield."""

from .base import Responder
from .blocker import (
    DEFAULT_INPUT_FALLBACK,
    DEFAULT_OUTPUT_FALLBACK,
    BlockResponder,
)
from .isolator import IsolationResponder, spotlight
from .rate_limiter import RateLimitResponder
from .sanitizer import SanitizeResponder

__all__ = [
    "Responder",
    "SanitizeResponder",
    "BlockResponder",
    "RateLimitResponder",
    "IsolationResponder",
    "spotlight",
    "DEFAULT_INPUT_FALLBACK",
    "DEFAULT_OUTPUT_FALLBACK",
]
