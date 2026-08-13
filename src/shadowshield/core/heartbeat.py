"""Usage heartbeat — anonymous, opt-in, one packet.

Answers one product question: how many active installs run ``serve``, and with
how many services. The payload is exactly::

    {"anon_install_id": "<uuid4>", "version": "<x.y.z>",
     "num_services_seen": <int>, "ts": "<iso8601>"}

No hostnames, IPs, keys, detector data, or payloads — ever.

**Opt-in, not opt-out (deliberate deviation from the SaaS plan).** The plan
(DASHBOARD_SAAS_PLAN_2026-08-07 §3) specced an anonymous *opt-out* heartbeat —
but no ShadowShield collector endpoint exists yet, and code that phones a
non-existent endpoint by default is worse than no code. So: the heartbeat only
sends when BOTH ``SHADOWSHIELD_HEARTBEAT=1`` and ``SHADOWSHIELD_HEARTBEAT_URL``
are set. When the Cloud collector ships, the default can be revisited in the
open with the payload already documented here.

Opt out / stay out: do nothing — unset env vars mean zero network calls.

State lives in ``~/.shadowshield/heartbeat.json`` (install id + last-sent
timestamp; at most one send per 24h). Fails open: any error is logged at debug
and swallowed.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

import structlog

_log = structlog.get_logger(__name__)

_ENABLED_ENV = "SHADOWSHIELD_HEARTBEAT"
_URL_ENV = "SHADOWSHIELD_HEARTBEAT_URL"
_INTERVAL_S = 24 * 3600


def _state_path() -> Path:
    return Path.home() / ".shadowshield" / "heartbeat.json"


def _load_state(path: Path) -> dict[str, Any]:
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return data
    except Exception:
        return {}


def _save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state), encoding="utf-8")


def build_payload(num_services_seen: int, *, install_id: str | None = None) -> dict[str, Any]:
    """The complete heartbeat payload. This is the whole contract."""
    from .. import __version__

    return {
        "anon_install_id": install_id or str(uuid.uuid4()),
        "version": __version__,
        "num_services_seen": int(num_services_seen),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def maybe_send_heartbeat(
    num_services_seen: int,
    *,
    state_path: Path | None = None,
    transport: Any = None,
) -> bool:
    """Send the heartbeat if opted in and due. Returns True if a send happened.

    Never raises; never sends unless SHADOWSHIELD_HEARTBEAT=1 and
    SHADOWSHIELD_HEARTBEAT_URL are both set. ``transport`` (callable taking the
    payload dict) is injectable for tests; default posts JSON via httpx.
    """
    if os.environ.get(_ENABLED_ENV) != "1":
        return False
    url = os.environ.get(_URL_ENV)
    if not url:
        return False

    path = state_path or _state_path()
    try:
        state = _load_state(path)
        now = time.time()
        if now - float(state.get("last_sent", 0)) < _INTERVAL_S:
            return False
        install_id = state.get("install_id") or str(uuid.uuid4())
        payload = build_payload(num_services_seen, install_id=install_id)

        if transport is not None:
            transport(payload)
        else:  # pragma: no cover - network path
            import httpx

            httpx.post(url, json=payload, timeout=5.0)

        _save_state(path, {"install_id": install_id, "last_sent": now})
        _log.debug("shadowshield.heartbeat.sent")
        return True
    except Exception:  # fail open, always
        _log.debug("shadowshield.heartbeat.failed", exc_info=True)
        return False
