# Plugins

Two ways to extend ShadowShield:

1. **In-process** — decorate a `Detector` with `@register_detector` (auto-discovered)
   or pass `extra_detectors=` / `extra_responders=` to `Shield(...)`. Best for app
   code.
2. **Distributable plugins** — bundle detectors/responders in their own pip package
   and advertise them via the `shadowshield.plugins` entry-point group. Best for
   sharing reusable protection across projects/teams.

## Writing a plugin package

```python
# my_shadowshield_plugin/__init__.py
from shadowshield.plugins import ShadowShieldPlugin
from shadowshield import Detector, Responder

class MyPlugin(ShadowShieldPlugin):
    name = "my-plugin"
    version = "1.0.0"

    def detectors(self) -> list[Detector]:
        from .detectors import PiiDetector
        return [PiiDetector()]

    def responders(self) -> list[Responder]:
        return []
```

Advertise the entry point in the plugin's `pyproject.toml`:

```toml
[project.entry-points."shadowshield.plugins"]
my_plugin = "my_shadowshield_plugin:MyPlugin"
```

## Loading plugins

```python
from shadowshield import Shield
from shadowshield.plugins import PluginManager

pm = PluginManager()
loaded = pm.discover()          # finds installed plugins via entry points
print("loaded plugins:", loaded)

shield = Shield.for_mode(
    "balanced",
    extra_detectors=pm.detectors(),
    extra_responders=pm.responders(),
)
```

## Isolation guarantees

A plugin that fails to import is **skipped**, not fatal — one broken third-party
plugin can never disable the shield. A plugin detector that *raises during a scan*
is caught by the engine's fail-safe wrapper and drops only its own contribution.

## Security note

Plugins run in-process with full trust. Vet third-party plugins the same way you'd
vet any dependency: read the source, check what it imports and whether it makes
network calls, and pin versions. A malicious "detector" could exfiltrate the very
content it's meant to protect.
