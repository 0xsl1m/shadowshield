"""Plugin contract — bundle custom detectors/responders as installable packages.

A plugin is just an object exposing ``detectors()`` and/or ``responders()``.
Distribute it as its own package and advertise it through the
``shadowshield.plugins`` entry-point group; :class:`PluginManager` discovers and
loads it. Decorating a :class:`Detector` with ``@register_detector`` is enough
for in-process extension — plugins are for *shipping* extensions to others.
"""

from __future__ import annotations

from ..detectors.base import Detector
from ..responders.base import Responder


class ShadowShieldPlugin:
    """Base class for distributable extension bundles.

    Not abstract — both hooks have sensible no-op defaults, so a plugin only
    overrides the side(s) it actually contributes (detectors and/or responders).
    """

    #: Unique plugin name (for logging / de-duplication).
    name: str = "plugin"
    #: Semantic version of the plugin (informational).
    version: str = "0.0.0"

    def detectors(self) -> list[Detector]:
        """Extra detectors this plugin contributes (default: none)."""
        return []

    def responders(self) -> list[Responder]:
        """Extra responders this plugin contributes (default: none)."""
        return []

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<ShadowShieldPlugin {self.name!r} v{self.version}>"
