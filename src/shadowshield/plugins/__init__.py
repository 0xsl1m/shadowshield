"""Extension system — ship custom detectors and responders as plugins."""

from .base import ShadowShieldPlugin
from .manager import ENTRY_POINT_GROUP, PluginManager

__all__ = ["ShadowShieldPlugin", "PluginManager", "ENTRY_POINT_GROUP"]
