"""Packaged default configuration (the annotated ``default.yaml``)."""

from __future__ import annotations

from pathlib import Path

DEFAULT_CONFIG_PATH = Path(__file__).with_name("default.yaml")


def default_config_text() -> str:
    """Return the annotated default YAML as a string (useful for ``init``)."""
    return DEFAULT_CONFIG_PATH.read_text(encoding="utf-8")


__all__ = ["DEFAULT_CONFIG_PATH", "default_config_text"]
