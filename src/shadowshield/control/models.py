"""Pydantic request models for the control-plane HTTP API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ..core.types import Direction


class ScanRequest(BaseModel):
    text: str = Field(max_length=100_000)
    direction: Direction = Direction.INPUT
    identity: str | None = Field(default=None, max_length=256)


class ConfigPatch(BaseModel):
    """Partial config update applied to the live shield."""

    mode: str | None = None
    block_threshold: float | None = None
    # name -> {"enabled": bool, "weight": float}
    detectors: dict[str, dict[str, Any]] | None = None


class PolicyBundleIn(BaseModel):
    """A (optionally signed) policy bundle pushed to the running shield."""

    config: dict[str, Any] = Field(default_factory=dict)
    version: int = Field(ge=1)
    issued_at: float = Field(gt=0)
    bundle_id: str = Field(min_length=1, max_length=128)
    signature: str | None = None
