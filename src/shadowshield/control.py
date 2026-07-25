"""Full control-plane server + dashboard (prototype).

This is a richer sibling of :mod:`shadowshield.server`. Where ``server.py`` exposes
a minimal scan API + a one-textarea page, this module powers a full **control
dashboard**: a live scan console + threat feed, metrics/analytics, a config control
panel (toggle detectors, switch mode, tune thresholds/weights - hot-swapped into the
running shield), and a one-click benchmark/eval runner.

Design constraints kept on purpose:

- **Optional dependency.** Imports FastAPI lazily; needs the ``dashboard`` extra.
- **In-memory only.** Recent scans live in a bounded ring buffer; nothing is
  persisted. Restart = clean slate.
- **No CDN.** The page (``static/dashboard.html``) is fully self-contained with
  inline SVG charts so it runs air-gapped - appropriate for a security tool.
- **Fail-safe mutation.** Config changes rebuild a fresh :class:`Shield` behind a
  lock; a bad patch raises and the previous shield keeps serving.

Run it::

    shadowshield serve --control                       # open (localhost)
    shadowshield serve --control --api-key SECRET       # require a key
    # or directly:
    python -m shadowshield.control --mode balanced --api-key SECRET

Security: pass ``--api-key`` (repeatable) or set ``SHADOWSHIELD_API_KEY`` to require
``X-API-Key``/``Bearer`` auth on the scan, config, and benchmark endpoints. Restrict
browser origins with ``--cors-origin`` / ``SHADOWSHIELD_CORS_ORIGINS``. With no key
set the control plane is unauthenticated - keep it on localhost or behind your own
boundary. (See docs/UPGRADE_OPPORTUNITIES.md #2.)
"""

from __future__ import annotations

import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from ._security import (
    extract_key,
    is_loopback,
    key_is_valid,
    resolve_api_keys,
    resolve_cors_origins,
)
from .core.config import Mode, ShieldConfig
from .core.policy import (
    PolicyBundle,
    PolicyRejected,
    ProtectionFloor,
    apply_bundle,
    make_hmac_verifier,
)
from .core.shield import Shield
from .core.types import Direction
from .detectors.base import registered_detectors

_STATIC = Path(__file__).parent / "static" / "dashboard.html"
_EVENT_RING_MAX = 1000


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #
class ScanRequest(BaseModel):
    text: str
    direction: str = "input"
    identity: str | None = None


class ConfigPatch(BaseModel):
    """Partial config update applied to the live shield."""

    mode: str | None = None
    block_threshold: float | None = None
    # name -> {"enabled": bool, "weight": float}
    detectors: dict[str, dict[str, Any]] | None = None


class PolicyBundleIn(BaseModel):
    """A (optionally signed) policy bundle pushed to the running shield."""

    config: dict[str, Any] = {}
    version: int = 1
    issued_at: float = 0.0
    bundle_id: str = ""
    signature: str | None = None


# --------------------------------------------------------------------------- #
# Mutable shield holder - lets the dashboard hot-swap config at runtime
# --------------------------------------------------------------------------- #
class ShieldState:
    """Owns the live shield + the knobs the dashboard can turn.

    Keeps a small amount of *intent* (mode, threshold, per-detector overrides) so
    a config change rebuilds a coherent shield from a mode preset rather than
    mutating a live object in place.
    """

    def __init__(self, mode: str = "balanced") -> None:
        self._lock = threading.Lock()
        self.mode: str = mode
        self.block_threshold: float | None = None  # None => use the mode's preset
        self.detector_overrides: dict[str, dict[str, Any]] = {}
        self.events: deque[dict[str, Any]] = deque(maxlen=_EVENT_RING_MAX)
        self._seq = 0
        # Monotonic counters for Prometheus (independent of the bounded ring).
        self._scans_total = 0
        self._dec_total: dict[str, int] = {}
        self._sev_total: dict[str, int] = {}
        self._det_total: dict[str, int] = {}
        self._lat_sum_ms = 0.0
        self.floor = ProtectionFloor()
        self.active_policy: dict[str, Any] | None = None
        self.shield: Shield = self._build()

    # -- build / mutate ------------------------------------------------- #
    def _build(self) -> Shield:
        overrides: dict[str, Any] = {}
        if self.block_threshold is not None:
            overrides["block_threshold"] = self.block_threshold
        if self.detector_overrides:
            overrides["detectors"] = self.detector_overrides
        cfg = ShieldConfig.for_mode(Mode(self.mode), **overrides)
        return Shield(cfg)

    def apply_patch(self, patch: ConfigPatch) -> None:
        """Atomically rebuild the shield from a config patch (or raise, unchanged)."""
        with self._lock:
            mode = patch.mode or self.mode
            block_threshold = (
                patch.block_threshold if patch.block_threshold is not None else self.block_threshold
            )
            overrides = dict(self.detector_overrides)
            if patch.detectors:
                for name, d in patch.detectors.items():
                    cur = dict(overrides.get(name, {}))
                    if "enabled" in d:
                        cur["enabled"] = bool(d["enabled"])
                    if "weight" in d:
                        cur["weight"] = float(d["weight"])
                    overrides[name] = cur

            # Build the candidate first; only commit if it validates + constructs.
            trial = ShieldState.__new__(ShieldState)
            trial.mode = mode
            trial.block_threshold = block_threshold
            trial.detector_overrides = overrides
            new_shield = trial._build()  # raises on a bad patch

            self.mode = mode
            self.block_threshold = block_threshold
            self.detector_overrides = overrides
            self.shield = new_shield

    def apply_policy(self, bundle: PolicyBundle, *, verifier: Any = None) -> dict[str, Any]:
        """Apply a floor-bounded (optionally signed) bundle to the live shield.

        Raises PolicyRejected on a bad signature or a floor breach; the previous shield
        keeps serving (fail-safe). On success the clamped config becomes live.
        """
        with self._lock:
            clamped = apply_bundle(self.shield.config, bundle, floor=self.floor, verifier=verifier)
            self.shield = Shield(clamped)
            # Fold the clamped result into the intent so config_view reflects reality and a
            # later /api/config edit builds on top of the policy instead of discarding it.
            self.block_threshold = clamped.block_threshold
            self.mode = clamped.mode.value if hasattr(clamped.mode, "value") else str(clamped.mode)
            self.detector_overrides = {
                name: {
                    "enabled": clamped.detector_config(name).enabled,
                    "weight": clamped.detector_config(name).weight,
                }
                for name in registered_detectors()
            }
            self.active_policy = {
                "bundle_id": bundle.bundle_id,
                "version": bundle.version,
                "applied_at": time.time(),
            }
            return self.active_policy

    # -- scan + record -------------------------------------------------- #
    def scan_and_record(self, req: ScanRequest) -> dict[str, Any]:
        shield = self.shield  # snapshot (swap is atomic via rebind)
        start = time.perf_counter()
        result = shield.scan(req.text, direction=Direction(req.direction), identity=req.identity)
        latency_ms = (time.perf_counter() - start) * 1000.0

        threats = [
            {
                "category": t.category.value,
                "severity": t.severity.label,
                "score": round(t.score, 4),
                "detector": t.detector,
                "message": t.message,
                "matched": t.matched,
                "span": list(t.span) if t.span else None,
            }
            for t in result.threats
        ]
        preview = req.text if len(req.text) <= 140 else req.text[:140] + "…"

        # Bookkeeping (ring + counters + seq) under the lock so concurrent requests on
        # uvicorn's threadpool can't race the counters or duplicate event ids.
        with self._lock:
            self._seq += 1
            seq = self._seq
            event = {
                "id": seq,
                "ts": time.time(),
                "direction": result.direction.value,
                "decision": result.decision.value,
                "severity": result.severity.label,
                "score": round(result.score, 4),
                "blocked": result.blocked,
                "is_safe": result.is_safe,
                "identity": req.identity,
                "latency_ms": round(latency_ms, 3),
                "threats": threats,
                "preview": preview,
            }
            self.events.appendleft(event)
            self._scans_total += 1
            self._dec_total[result.decision.value] = (
                self._dec_total.get(result.decision.value, 0) + 1
            )
            self._sev_total[result.severity.label] = (
                self._sev_total.get(result.severity.label, 0) + 1
            )
            self._lat_sum_ms += latency_ms
            for t in result.threats:
                self._det_total[t.detector] = self._det_total.get(t.detector, 0) + 1

        out = result.to_dict()
        out["latency_ms"] = round(latency_ms, 3)
        out["event_id"] = seq
        out["preview"] = preview
        out["safe_text"] = result.safe_text
        return out

    # -- introspection -------------------------------------------------- #
    def config_view(self) -> dict[str, Any]:
        shield = self.shield
        cfg = shield.config
        active = {d.name for d in shield.detectors}
        registry = registered_detectors()
        detectors = []
        for name in sorted(registry):
            dc = cfg.detector_config(name)
            detectors.append(
                {
                    "name": name,
                    "enabled": bool(dc.enabled),
                    "weight": round(float(dc.weight), 3),
                    "active": name in active,
                }
            )
        return {
            "mode": cfg.mode.value if hasattr(cfg.mode, "value") else str(cfg.mode),
            "block_threshold": round(float(cfg.block_threshold), 4),
            "llm_check_enabled": bool(cfg.llm_check.enabled),
            "rate_limit_enabled": bool(cfg.rate_limit.enabled),
            "detectors": detectors,
        }

    def metrics_view(self) -> dict[str, Any]:
        events = list(self.events)
        n = len(events)
        by_decision: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_detector: dict[str, int] = {}
        by_direction: dict[str, int] = {"input": 0, "output": 0}
        latencies: list[float] = []
        for e in events:
            by_decision[e["decision"]] = by_decision.get(e["decision"], 0) + 1
            by_severity[e["severity"]] = by_severity.get(e["severity"], 0) + 1
            by_direction[e["direction"]] = by_direction.get(e["direction"], 0) + 1
            latencies.append(e["latency_ms"])
            for t in e["threats"]:
                by_detector[t["detector"]] = by_detector.get(t["detector"], 0) + 1

        def pct(p: float) -> float:
            if not latencies:
                return 0.0
            s = sorted(latencies)
            k = max(0, min(len(s) - 1, round(p / 100 * (len(s) - 1))))
            return round(s[k], 3)

        blocked = by_decision.get("block", 0)
        # Volume sparkline: scans per second over the last 60s window.
        now = time.time()
        buckets = [0] * 60
        for e in events:
            age = int(now - e["ts"])
            if 0 <= age < 60:
                buckets[59 - age] += 1

        return {
            "total": n,
            "blocked": blocked,
            "block_rate": round(blocked / n, 4) if n else 0.0,
            "by_decision": by_decision,
            "by_severity": by_severity,
            "by_detector": by_detector,
            "by_direction": by_direction,
            "latency_p50_ms": pct(50),
            "latency_p95_ms": pct(95),
            "volume_60s": buckets,
        }

    def metrics_prometheus(self, version: str) -> str:
        """Render counters + recent-window latency in Prometheus text format (v0.0.4).

        Counters are monotonic since process start; the p50/p95 gauges are computed
        over the recent in-memory window. Label values here are safe identifiers
        (detector/decision/severity names, semver, mode) so no escaping is needed.
        """
        m = self.metrics_view()
        out: list[str] = []
        out.append("# HELP shadowshield_scans_total Total scans processed since start.")
        out.append("# TYPE shadowshield_scans_total counter")
        out.append(f"shadowshield_scans_total {self._scans_total}")
        out.append("# HELP shadowshield_scan_decisions_total Scans by decision.")
        out.append("# TYPE shadowshield_scan_decisions_total counter")
        for k, v in sorted(self._dec_total.items()):
            out.append(f'shadowshield_scan_decisions_total{{decision="{k}"}} {v}')
        out.append("# HELP shadowshield_scan_severity_total Scans by aggregate severity.")
        out.append("# TYPE shadowshield_scan_severity_total counter")
        for k, v in sorted(self._sev_total.items()):
            out.append(f'shadowshield_scan_severity_total{{severity="{k}"}} {v}')
        out.append("# HELP shadowshield_detector_hits_total Threats raised, by detector.")
        out.append("# TYPE shadowshield_detector_hits_total counter")
        for k, v in sorted(self._det_total.items()):
            out.append(f'shadowshield_detector_hits_total{{detector="{k}"}} {v}')
        out.append("# HELP shadowshield_scan_latency_seconds_sum Cumulative scan latency.")
        out.append("# TYPE shadowshield_scan_latency_seconds_sum counter")
        out.append(f"shadowshield_scan_latency_seconds_sum {self._lat_sum_ms / 1000.0:.6f}")
        out.append("# HELP shadowshield_scan_latency_seconds Recent-window latency quantiles.")
        out.append("# TYPE shadowshield_scan_latency_seconds gauge")
        out.append(
            f'shadowshield_scan_latency_seconds{{quantile="0.5"}} {m["latency_p50_ms"] / 1000.0:.6f}'
        )
        out.append(
            f'shadowshield_scan_latency_seconds{{quantile="0.95"}} {m["latency_p95_ms"] / 1000.0:.6f}'
        )
        out.append("# HELP shadowshield_build_info Build and runtime info.")
        out.append("# TYPE shadowshield_build_info gauge")
        out.append(f'shadowshield_build_info{{version="{version}",mode="{self.mode}"}} 1')
        return "\n".join(out) + "\n"


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #
def create_control_app(
    mode: str = "balanced",
    *,
    api_keys: list[str] | None = None,
    cors_origins: list[str] | None = None,
    policy_key: bytes | str | None = None,
) -> Any:
    """Build the FastAPI control-plane app (needs the ``dashboard`` extra).

    ``api_keys``/``cors_origins`` are merged with the ``SHADOWSHIELD_API_KEY`` /
    ``SHADOWSHIELD_CORS_ORIGINS`` env vars. When at least one key is configured the
    scan/config/benchmark endpoints require ``X-API-Key`` or ``Bearer`` auth; the
    dashboard page and ``/health`` stay open so the UI can load and prompt for a key.
    """
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException
        from fastapi.responses import HTMLResponse, PlainTextResponse
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "The control dashboard requires the 'dashboard' extra: "
            "pip install shadowshield[dashboard]"
        ) from exc

    from . import __version__

    keys = resolve_api_keys(api_keys)
    origins = resolve_cors_origins(cors_origins)

    state = ShieldState(mode=mode)
    _pk = policy_key.encode() if isinstance(policy_key, str) else policy_key
    policy_verifier = make_hmac_verifier(_pk) if _pk else None
    app = FastAPI(title="ShadowShield Control", version=__version__)

    if origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "X-API-Key", "Authorization"],
        )

    def require_auth(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        authorization: str | None = Header(default=None),
    ) -> None:
        if not keys:
            return  # auth disabled
        if not key_is_valid(extract_key(x_api_key, authorization), keys):
            raise HTTPException(
                status_code=401,
                detail="missing or invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

    guarded = [Depends(require_auth)]

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "mode": state.mode,
            "auth_required": bool(keys),
            "detectors": [d.name for d in state.shield.detectors],
        }

    @app.post("/scan", dependencies=guarded)
    def scan(req: ScanRequest) -> dict[str, Any]:
        return state.scan_and_record(req)

    @app.post("/guard", dependencies=guarded)
    def guard_endpoint(req: ScanRequest) -> dict[str, Any]:
        out = state.scan_and_record(req)
        return {
            "safe_text": out.get("safe_text"),
            "blocked": out["blocked"],
            "decision": out["decision"],
        }

    @app.get("/api/events", dependencies=guarded)
    def events(limit: int = 50) -> dict[str, Any]:
        limit = max(1, min(limit, _EVENT_RING_MAX))
        return {"events": list(state.events)[:limit], "total": len(state.events)}

    @app.get("/api/metrics", dependencies=guarded)
    def metrics() -> dict[str, Any]:
        return state.metrics_view()

    @app.get("/metrics", dependencies=guarded)
    def metrics_prom() -> Any:
        return PlainTextResponse(
            state.metrics_prometheus(__version__),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/api/config", dependencies=guarded)
    def get_config() -> dict[str, Any]:
        return state.config_view()

    @app.post("/api/config", dependencies=guarded)
    def set_config(patch: ConfigPatch) -> dict[str, Any]:
        try:
            state.apply_patch(patch)
        except Exception as exc:  # bad patch -> 400, previous shield intact
            raise HTTPException(status_code=400, detail=f"invalid config: {exc}") from exc
        return state.config_view()

    @app.get("/api/policy", dependencies=guarded)
    def get_policy() -> dict[str, Any]:
        return {
            "floor": {
                "always_on": sorted(state.floor.always_on),
                "max_block_threshold": state.floor.max_block_threshold,
                "max_degradation_delta": state.floor.max_degradation_delta,
            },
            "active": state.active_policy,
            "signing_required": policy_verifier is not None,
        }

    @app.post("/api/policy", dependencies=guarded)
    def set_policy(body: PolicyBundleIn) -> dict[str, Any]:
        bundle = PolicyBundle(
            config=body.config,
            version=body.version,
            issued_at=body.issued_at,
            bundle_id=body.bundle_id,
            signature=body.signature,
        )
        try:
            applied = state.apply_policy(bundle, verifier=policy_verifier)
        except PolicyRejected as exc:  # floor breach / bad signature -> 400, shield intact
            raise HTTPException(status_code=400, detail=f"policy rejected: {exc}") from exc
        return {"applied": applied, "config": state.config_view()}

    @app.post("/api/benchmark", dependencies=guarded)
    def benchmark() -> dict[str, Any]:
        try:
            from .eval import evaluate_shield, load_builtin
        except ImportError as exc:  # pragma: no cover
            raise HTTPException(status_code=500, detail=f"eval unavailable: {exc}") from exc
        examples = load_builtin()
        start = time.perf_counter()
        report = evaluate_shield(state.shield, examples)
        wall_ms = (time.perf_counter() - start) * 1000.0
        out = report.to_dict()
        out["wall_ms"] = round(wall_ms, 1)
        return out

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        try:
            return _STATIC.read_text(encoding="utf-8")
        except OSError:  # pragma: no cover
            return "<h1>ShadowShield</h1><p>dashboard.html not found.</p>"

    return app


def serve_control(
    host: str = "127.0.0.1",
    port: int = 8000,
    mode: str = "balanced",
    *,
    api_keys: list[str] | None = None,
    cors_origins: list[str] | None = None,
    policy_key: str | None = None,
) -> None:  # pragma: no cover
    """Run the control dashboard with uvicorn."""
    try:
        import uvicorn
    except ImportError as exc:
        raise ImportError(
            "Serving requires the 'dashboard' extra: pip install shadowshield[dashboard]"
        ) from exc
    keys = resolve_api_keys(api_keys)
    if not keys and not is_loopback(host):
        print(
            f"WARNING: control plane bound to {host} with NO API key - "
            "anyone who can reach it can mutate config. Set --api-key.",
            file=sys.stderr,
        )
    uvicorn.run(
        create_control_app(
            mode, api_keys=api_keys, cors_origins=cors_origins, policy_key=policy_key
        ),
        host=host,
        port=port,
    )


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="ShadowShield control dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--mode", default="balanced", choices=["strict", "balanced", "permissive"])
    ap.add_argument("--api-key", action="append", default=None, help="accepted key (repeatable)")
    ap.add_argument("--cors-origin", action="append", default=None, help="allowed origin")
    ap.add_argument("--policy-key", default=None, help="HMAC key required to accept policy bundles")
    args = ap.parse_args()
    serve_control(
        args.host,
        args.port,
        args.mode,
        api_keys=args.api_key,
        cors_origins=args.cors_origin,
        policy_key=args.policy_key,
    )
