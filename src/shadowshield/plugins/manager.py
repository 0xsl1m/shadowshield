"""Discovery and loading of :class:`ShadowShieldPlugin` extensions.

Plugins are found two ways:

1. **Entry points** in the ``shadowshield.plugins`` group — the standard way to
   ship a plugin as a pip-installable package.
2. **Explicit registration** via :meth:`PluginManager.register` — handy for tests
   and in-process composition.

The manager flattens every plugin's detectors/responders into lists the
:class:`~shadowshield.Shield` can consume through ``extra_detectors`` /
``extra_responders``.
"""

from __future__ import annotations

from importlib import metadata

from ..detectors.base import Detector
from ..responders.base import Responder
from .base import ShadowShieldPlugin

ENTRY_POINT_GROUP = "shadowshield.plugins"


class PluginManager:
    """Loads and aggregates ShadowShield plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, ShadowShieldPlugin] = {}

    def register(self, plugin: ShadowShieldPlugin) -> None:
        self._plugins[plugin.name] = plugin

    def discover(self) -> list[str]:
        """Load all plugins advertised via the entry-point group.

        Returns the names of successfully loaded plugins. A plugin that fails to
        import is skipped (logged by the caller) rather than breaking startup —
        one bad third-party plugin must not disable the shield.
        """
        loaded: list[str] = []
        # The ``group=`` keyword is available on all supported Pythons (3.10+).
        for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
            try:
                factory = ep.load()
                plugin = factory() if callable(factory) else factory
                if isinstance(plugin, ShadowShieldPlugin):
                    self.register(plugin)
                    loaded.append(plugin.name)
            except Exception:  # pragma: no cover - third-party failure isolation
                continue
        return loaded

    @property
    def plugins(self) -> list[ShadowShieldPlugin]:
        return list(self._plugins.values())

    def detectors(self) -> list[Detector]:
        out: list[Detector] = []
        for p in self._plugins.values():
            out.extend(p.detectors())
        return out

    def responders(self) -> list[Responder]:
        out: list[Responder] = []
        for p in self._plugins.values():
            out.extend(p.responders())
        return out
