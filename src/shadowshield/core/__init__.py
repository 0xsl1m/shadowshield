"""Core engine, configuration, session, and the unified :class:`Shield`."""

from .config import (
    DetectorConfig,
    LLMCheckConfig,
    LoggingConfig,
    Mode,
    PolicyConfig,
    RateLimitConfig,
    ShieldConfig,
)
from .engine import Engine
from .session import ConversationHistory, ShieldedSession
from .shield import Shield
from .types import (
    Decision,
    Direction,
    ScanResult,
    Severity,
    ShadowShieldError,
    Threat,
    ThreatBlockedError,
    ThreatCategory,
)

__all__ = [
    "Shield",
    "Engine",
    "ShieldConfig",
    "Mode",
    "PolicyConfig",
    "DetectorConfig",
    "LLMCheckConfig",
    "RateLimitConfig",
    "LoggingConfig",
    "ConversationHistory",
    "ShieldedSession",
    "Direction",
    "Decision",
    "Severity",
    "Threat",
    "ThreatCategory",
    "ScanResult",
    "ShadowShieldError",
    "ThreatBlockedError",
]
