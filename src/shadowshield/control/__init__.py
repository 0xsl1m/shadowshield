"""Full control-plane server + dashboard (prototype).

This package is a richer sibling of :mod:`shadowshield.server`. Where
``server.py`` exposes a minimal scan API + a one-textarea page, this package
powers a full **control dashboard**: a live scan console + threat feed,
metrics/analytics, a config control panel (toggle detectors, switch mode, tune
thresholds/weights - hot-swapped into the running shield), and a one-click
benchmark/eval runner.

Layout (split from the original single ``control.py``):

- ``app.py`` - :func:`create_control_app`, :func:`serve_control`, CLI ``main``.
- ``state.py`` - :class:`ShieldState`: the live shield, event ring, counters,
  floor-bounded mutation.
- ``models.py`` - pydantic request models.
- ``policy_state.py`` - durable authenticated replay-state encoding + file IO.
- ``migrate.py`` - :func:`migrate_policy_state` re-keying tool.

Design constraints kept on purpose:

- **Optional dependency.** Imports FastAPI lazily; needs the ``dashboard`` extra.
- **Bounded local state.** Recent scans/metrics live in a bounded in-memory ring.
- **No CDN.** The page (``static/dashboard.html``) is fully self-contained with
  inline SVG charts so it runs air-gapped - appropriate for a security tool.
- **Fail-safe mutation.** Config changes rebuild a fresh Shield behind a lock;
  a bad patch raises and the previous shield keeps serving.

Run it::

    shadowshield serve --control                       # open (localhost)
    shadowshield serve --control --api-key SCAN --admin-key ADMIN
    # or directly:
    python -m shadowshield.control --mode balanced --api-key SECRET

Security: scan and administrator credentials are separate. Non-loopback startup
also requires signed policy verification and durable anti-replay state. Direct
factory mounting fails closed unless credentials are supplied; insecure mode is
an explicit local-only opt-in. Restrict browser origins with ``--cors-origin`` /
``SHADOWSHIELD_CORS_ORIGINS``.
"""

from __future__ import annotations

from .app import create_control_app, serve_control
from .migrate import migrate_policy_state
from .models import ConfigPatch, PolicyBundleIn, ScanRequest
from .policy_state import _MAX_POLICY_STATE_BYTES, _policy_state_mac_for_key
from .state import ShieldState

__all__ = [
    "ConfigPatch",
    "PolicyBundleIn",
    "ScanRequest",
    "ShieldState",
    "_MAX_POLICY_STATE_BYTES",
    "_policy_state_mac_for_key",
    "create_control_app",
    "migrate_policy_state",
    "serve_control",
]
