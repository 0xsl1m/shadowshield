"""Configuration models for ShadowShield.

A single :class:`ShieldConfig` drives the whole framework. It can be built three
ways, in increasing order of specificity:

1. From a named *mode* — :func:`ShieldConfig.for_mode` (``strict`` /
   ``balanced`` / ``permissive``). This is the 90% path.
2. From a YAML/dict — :func:`ShieldConfig.from_yaml` / ``model_validate``.
3. By hand, overriding any field.

The config is intentionally validated with Pydantic so that a malformed
deployment config fails loudly at startup rather than silently weakening
protection at runtime.
"""

from __future__ import annotations

import enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from .types import Decision, Severity


class Mode(str, enum.Enum):
    """Preset risk postures.

    - ``STRICT``: security-first. Blocks aggressively, sanitizes by default,
      enables every detector including the optional LLM self-check hook.
    - ``BALANCED``: the sensible default. Sanitizes medium threats, blocks high+.
    - ``PERMISSIVE``: observability-first. Flags and logs, rarely blocks —
      useful for shadow-mode rollout where you measure before you enforce.
    """

    STRICT = "strict"
    BALANCED = "balanced"
    PERMISSIVE = "permissive"


class PolicyConfig(BaseModel):
    """Maps an aggregate :class:`Severity` to a :class:`Decision`.

    The engine computes a single severity for a payload, then looks it up here.
    Every band must be present; :func:`decide` walks from the payload's severity.
    """

    none: Decision = Decision.ALLOW
    low: Decision = Decision.FLAG
    medium: Decision = Decision.SANITIZE
    high: Decision = Decision.BLOCK
    critical: Decision = Decision.BLOCK

    def decide(self, severity: Severity) -> Decision:
        return {
            Severity.NONE: self.none,
            Severity.LOW: self.low,
            Severity.MEDIUM: self.medium,
            Severity.HIGH: self.high,
            Severity.CRITICAL: self.critical,
        }[severity]


class DetectorConfig(BaseModel):
    """Per-detector toggle + optional weight and overrides.

    ``weight`` scales a detector's contribution to the aggregate score, letting
    deployments trust some detectors more than others without code changes.
    """

    enabled: bool = True
    weight: float = Field(default=1.0, ge=0.0, le=5.0)
    options: dict[str, Any] = Field(default_factory=dict)


class LLMCheckConfig(BaseModel):
    """Optional lightweight LLM-based self-check ("is this an injection?").

    Disabled by default because it costs a model call. When enabled the engine
    invokes a user-supplied callable (see ``Shield(llm_judge=...)``); no network
    client is built into the core.
    """

    enabled: bool = False
    # Only consult the LLM when the cheap tiers already scored at/above this.
    # Avoids paying for a model call on obviously-clean traffic.
    min_score_to_invoke: float = Field(default=0.35, ge=0.0, le=1.0)
    timeout_seconds: float = Field(default=8.0, gt=0.0)


class RateLimitConfig(BaseModel):
    """Token-bucket style limit applied per identity (e.g. per session/user)."""

    enabled: bool = False
    max_events: int = Field(default=60, gt=0)
    window_seconds: float = Field(default=60.0, gt=0.0)
    # Count only flagged/blocked events toward the limit, not clean traffic.
    count_only_threats: bool = True


class LoggingConfig(BaseModel):
    enabled: bool = True
    # JSON lines audit sink. ``None`` -> stdout via structlog only.
    audit_path: str | None = None
    # Never write the raw offending payload to the audit log unless explicitly
    # opted in — payloads can contain secrets/PII.
    redact_payloads: bool = True
    level: str = "INFO"


class ShieldConfig(BaseModel):
    """The single source of truth for a :class:`~shadowshield.Shield`."""

    mode: Mode = Mode.BALANCED

    # When True, ``Shield.scan`` raises ``ThreatBlockedError`` on a BLOCK
    # decision instead of returning a result with ``blocked=True``. Off by
    # default so the library is non-throwing unless you opt in.
    raise_on_block: bool = False

    # Aggregate score at/above which the payload is considered "not safe" even
    # if no single detector hit CRITICAL. Lower = more cautious.
    block_threshold: float = Field(default=0.65, ge=0.0, le=1.0)

    # Hard cap on how many characters are scanned per payload. Oversized inputs
    # are scanned as a truncated prefix (bounding CPU work) and flagged — a guard
    # against resource-exhaustion from multi-megabyte payloads. 0 = unlimited.
    max_input_chars: int = Field(default=100_000, ge=0)

    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    detectors: dict[str, DetectorConfig] = Field(default_factory=dict)
    llm_check: LLMCheckConfig = Field(default_factory=LLMCheckConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    # Detectors named here are forced off regardless of their per-detector
    # config — a convenient kill-switch for noisy detectors in production.
    disabled_detectors: list[str] = Field(default_factory=list)

    model_config = {"extra": "forbid", "use_enum_values": False}

    @field_validator("logging")
    @classmethod
    def _normalise_level(cls, v: LoggingConfig) -> LoggingConfig:
        v.level = v.level.upper()
        return v

    @model_validator(mode="after")
    def _apply_mode_defaults(self) -> ShieldConfig:
        """Fill unset knobs from the chosen mode without clobbering overrides."""
        # Only applied when the caller didn't explicitly customise policy.
        return self

    # ------------------------------------------------------------------ #
    # Builders
    # ------------------------------------------------------------------ #
    @classmethod
    def for_mode(cls, mode: Mode | str = Mode.BALANCED, **overrides: Any) -> ShieldConfig:
        """Build a config from a preset mode, then apply keyword overrides."""
        mode = Mode(mode)
        base = _MODE_PRESETS[mode]()
        data = base.model_dump()
        data.update(overrides)
        return cls.model_validate(data)

    @classmethod
    def from_yaml(cls, path: str | Path) -> ShieldConfig:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if "mode" in raw and len(raw) > 1:
            # Treat YAML as overrides layered on top of the named mode preset.
            mode = raw.pop("mode")
            return cls.for_mode(mode, **raw)
        return cls.model_validate(raw)

    def detector_config(self, name: str) -> DetectorConfig:
        """Effective config for a detector, honouring the global kill-switch."""
        cfg = self.detectors.get(name, DetectorConfig())
        if name in self.disabled_detectors:
            return cfg.model_copy(update={"enabled": False})
        return cfg


# ---------------------------------------------------------------------- #
# Mode presets
# ---------------------------------------------------------------------- #
def _strict() -> ShieldConfig:
    return ShieldConfig(
        mode=Mode.STRICT,
        raise_on_block=False,
        block_threshold=0.45,
        policy=PolicyConfig(
            none=Decision.ALLOW,
            low=Decision.SANITIZE,
            medium=Decision.BLOCK,
            high=Decision.BLOCK,
            critical=Decision.BLOCK,
        ),
        llm_check=LLMCheckConfig(enabled=True, min_score_to_invoke=0.25),
        rate_limit=RateLimitConfig(enabled=True, max_events=30, window_seconds=60.0),
        logging=LoggingConfig(enabled=True, redact_payloads=True, level="INFO"),
    )


def _balanced() -> ShieldConfig:
    return ShieldConfig(
        mode=Mode.BALANCED,
        block_threshold=0.65,
        policy=PolicyConfig(
            none=Decision.ALLOW,
            low=Decision.FLAG,
            medium=Decision.SANITIZE,
            high=Decision.BLOCK,
            critical=Decision.BLOCK,
        ),
        llm_check=LLMCheckConfig(enabled=False),
        rate_limit=RateLimitConfig(enabled=False),
    )


def _permissive() -> ShieldConfig:
    return ShieldConfig(
        mode=Mode.PERMISSIVE,
        block_threshold=0.85,
        policy=PolicyConfig(
            none=Decision.ALLOW,
            low=Decision.FLAG,
            medium=Decision.FLAG,
            high=Decision.SANITIZE,
            critical=Decision.BLOCK,
        ),
        llm_check=LLMCheckConfig(enabled=False),
        rate_limit=RateLimitConfig(enabled=False),
    )


_MODE_PRESETS = {
    Mode.STRICT: _strict,
    Mode.BALANCED: _balanced,
    Mode.PERMISSIVE: _permissive,
}
