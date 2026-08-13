"""Control-plane app factory, server entrypoint, and dashboard wiring.

Extracted from the monolithic ``control`` module; see ``control/__init__.py``
for the package overview and the public re-exports.
"""

from __future__ import annotations

import os
import threading
import time
from pathlib import Path
from typing import Any

from .._security import (
    ConcurrencyLimitMiddleware,
    EarlyAuthMiddleware,
    RequestBodyLimitMiddleware,
    SecurityHeadersMiddleware,
    extract_key,
    is_loopback,
    key_is_valid,
    resolve_admin_keys,
    resolve_api_keys,
    resolve_cors_origins,
    resolve_policy_key,
    resolve_policy_state_key,
    resolve_policy_state_path,
    secret_groups_overlap,
)
from ..core.heartbeat import maybe_send_heartbeat
from ..core.policy import PolicyBundle, PolicyRejected, make_hmac_verifier
from .models import ConfigPatch, PolicyBundleIn, ScanRequest
from .policy_state import _MIN_POLICY_STATE_KEY_BYTES
from .state import ShieldState

_STATIC = Path(__file__).parent.parent / "static" / "dashboard.html"


def _start_heartbeat(state: ShieldState) -> None:
    """Start the opt-in usage-heartbeat loop (no-op unless enabled via env)."""
    if os.environ.get("SHADOWSHIELD_HEARTBEAT") != "1":
        return  # opt-in only: don't even spawn the thread when disabled

    def _loop() -> None:
        time.sleep(60)  # let startup settle; dedupe inside handles 24h cadence
        while True:
            maybe_send_heartbeat(state.services_seen())
            time.sleep(3600)

    thread = threading.Thread(target=_loop, name="shadowshield-heartbeat", daemon=True)
    thread.start()


# --------------------------------------------------------------------------- #
# App factory
# --------------------------------------------------------------------------- #
def create_control_app(
    mode: str = "balanced",
    *,
    api_keys: list[str] | None = None,
    admin_keys: list[str] | None = None,
    cors_origins: list[str] | None = None,
    policy_key: bytes | str | None = None,
    policy_state_path: str | None = None,
    policy_state_key: bytes | str | None = None,
    config_file: str | None = None,
    allow_insecure_local: bool = False,
    warmup_detectors: bool = False,
) -> Any:
    """Build the FastAPI control-plane app (needs the ``dashboard`` extra).

    Scan and administrative credentials are separate. Direct factory mounting
    fails closed unless keys are configured; ``allow_insecure_local=True`` is an
    explicit opt-in for tests or a trusted loopback-only embedding.

    Durable state uses ``policy_state_key`` independently of ``policy_key``. For
    backward compatibility, an explicitly insecure local embedding may still
    authenticate state with ``policy_key`` when no state key is supplied.
    Production callers never receive that fallback, and legacy state files are
    not silently migrated to a newly configured state key.

    ``config_file`` enables ``POST /api/reload`` — hot-reloading that YAML
    through the local protection floor, so operators retune thresholds without
    dropping the process.
    """
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException
        from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "The control dashboard requires the 'dashboard' extra: "
            "pip install shadowshield[dashboard]"
        ) from exc

    from .. import __version__

    keys = resolve_api_keys(api_keys)
    admins = resolve_admin_keys(admin_keys)
    if not allow_insecure_local and not keys:
        raise RuntimeError(
            "refusing to create an unauthenticated control app; configure "
            "api_keys/SHADOWSHIELD_API_KEY or explicitly opt into local-only insecure mode"
        )
    if not allow_insecure_local and not admins:
        raise RuntimeError(
            "refusing to create a control app without an independent administrator key; "
            "configure admin_keys/SHADOWSHIELD_ADMIN_KEY"
        )
    origins = resolve_cors_origins(cors_origins)

    replay_path = resolve_policy_state_path(policy_state_path)
    _pk = resolve_policy_key(policy_key)
    state_auth_key = resolve_policy_state_key(policy_state_key)
    legacy_local_state_key = False
    if state_auth_key is not None and len(state_auth_key) < _MIN_POLICY_STATE_KEY_BYTES:
        raise RuntimeError(
            f"policy state authentication key must be at least {_MIN_POLICY_STATE_KEY_BYTES} bytes"
        )
    if replay_path is not None and state_auth_key is None:
        if allow_insecure_local and _pk is not None:
            state_auth_key = _pk
            legacy_local_state_key = True
        else:
            raise RuntimeError(
                "durable policy state authentication requires an explicit independent "
                "policy_state_key/SHADOWSHIELD_POLICY_STATE_KEY of at least "
                f"{_MIN_POLICY_STATE_KEY_BYTES} bytes; legacy policy-key state is "
                "not auto-migrated in production"
            )

    credential_groups: list[tuple[str, list[bytes | str]]] = [
        ("scan API key", list(keys)),
        ("administrator key", list(admins)),
        ("policy signing key", [_pk] if _pk is not None else []),
    ]
    if state_auth_key is not None and not legacy_local_state_key:
        credential_groups.append(("policy state key", [state_auth_key]))
    for index, (left_name, left_values) in enumerate(credential_groups):
        for right_name, right_values in credential_groups[index + 1 :]:
            if secret_groups_overlap(left_values, right_values):
                raise RuntimeError(f"{left_name} and {right_name} credentials must be distinct")

    if not allow_insecure_local and _pk is not None and replay_path is None:
        raise RuntimeError(
            "signed policy updates require durable anti-replay state; configure "
            "policy_state_path/SHADOWSHIELD_POLICY_STATE_PATH"
        )
    state = ShieldState(
        mode=mode,
        policy_state_path=replay_path,
        policy_state_auth_key=state_auth_key,
        config_path=config_file,
    )
    if warmup_detectors:
        state.shield.warmup()
    _start_heartbeat(state)
    policy_verifier = make_hmac_verifier(_pk) if _pk else None
    scan_keys = list(dict.fromkeys([*keys, *admins]))
    admin_api_required = bool(keys or admins) and not allow_insecure_local
    app = FastAPI(
        title="ShadowShield Control",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.add_middleware(RequestBodyLimitMiddleware)
    app.add_middleware(
        ConcurrencyLimitMiddleware,
        protected_paths=("/scan", "/guard", "/api/benchmark"),
    )
    app.add_middleware(
        EarlyAuthMiddleware,
        api_keys=scan_keys,
        protected_paths=("/scan", "/guard"),
    )
    app.add_middleware(
        EarlyAuthMiddleware,
        api_keys=admins,
        protected_paths=("/metrics",),
        protected_prefixes=("/api/",),
        deny_when_unconfigured=admin_api_required,
    )

    if origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "X-API-Key", "Authorization"],
        )
    app.add_middleware(SecurityHeadersMiddleware)

    def require_scan_auth(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        authorization: str | None = Header(default=None),
    ) -> None:
        if not scan_keys:
            return
        if not key_is_valid(extract_key(x_api_key, authorization), scan_keys):
            raise HTTPException(
                status_code=401,
                detail="missing or invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def require_admin_auth(
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
        authorization: str | None = Header(default=None),
    ) -> None:
        if not admins:
            if allow_insecure_local:
                return
            raise HTTPException(status_code=503, detail="administrative API is disabled")
        if not key_is_valid(extract_key(x_api_key, authorization), admins):
            raise HTTPException(
                status_code=401,
                detail="missing or invalid administrator API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

    scan_guarded = [Depends(require_scan_auth)]
    admin_guarded = [Depends(require_admin_auth)]

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": __version__,
            "mode": state.mode,
            "auth_required": bool(scan_keys),
            "admin_auth_required": bool(admins),
            "detectors": [d.name for d in state.shield.detectors],
        }

    @app.get("/ready")
    def ready() -> JSONResponse:
        report = state.shield.readiness()
        return JSONResponse(
            content=report,
            status_code=200 if report["ready"] else 503,
        )

    @app.post("/scan", dependencies=scan_guarded)
    def scan(req: ScanRequest) -> dict[str, Any]:
        return state.scan_and_record(req)

    @app.post("/guard", dependencies=scan_guarded)
    def guard_endpoint(req: ScanRequest) -> dict[str, Any]:
        out = state.scan_and_record(req)
        return {
            "safe_text": out.get("safe_text"),
            "blocked": out["blocked"],
            "decision": out["decision"],
        }

    @app.get("/api/events", dependencies=admin_guarded)
    def events(limit: int = 50) -> dict[str, Any]:
        limit = max(1, min(limit, 100))
        return state.events_view(limit)

    @app.get("/api/metrics", dependencies=admin_guarded)
    def metrics() -> dict[str, Any]:
        return state.metrics_view()

    @app.get("/metrics", dependencies=admin_guarded)
    def metrics_prom() -> Any:
        return PlainTextResponse(
            state.metrics_prometheus(__version__),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.get("/api/config", dependencies=admin_guarded)
    def get_config() -> dict[str, Any]:
        return state.config_view()

    @app.post("/api/config", dependencies=admin_guarded)
    def set_config(patch: ConfigPatch) -> dict[str, Any]:
        try:
            state.apply_patch(patch)
        except Exception as exc:  # bad patch -> 400, previous shield intact
            raise HTTPException(status_code=400, detail=f"invalid config: {exc}") from exc
        return state.config_view()

    @app.get("/api/policy", dependencies=admin_guarded)
    def get_policy() -> dict[str, Any]:
        return {
            "floor": {
                "always_on": sorted(state.floor.always_on),
                "max_block_threshold": state.floor.max_block_threshold,
                "max_degradation_delta": state.floor.max_degradation_delta,
            },
            "active": state.active_policy,
            "highest_accepted_version": state._highest_policy_version,
            "signing_required": policy_verifier is not None,
            "updates_enabled": policy_verifier is not None or allow_insecure_local,
        }

    @app.post("/api/policy", dependencies=admin_guarded)
    def set_policy(body: PolicyBundleIn) -> dict[str, Any]:
        if policy_verifier is None and not allow_insecure_local:
            raise HTTPException(
                status_code=503,
                detail="policy updates are disabled without a signing key",
            )
        bundle = PolicyBundle(
            config=body.config,
            version=body.version,
            issued_at=body.issued_at,
            bundle_id=body.bundle_id,
            signature=body.signature,
        )
        try:
            applied = state.apply_policy(
                bundle, verifier=policy_verifier, allow_unsigned=allow_insecure_local
            )
        except PolicyRejected as exc:  # floor breach / bad signature -> 400, shield intact
            raise HTTPException(status_code=400, detail=f"policy rejected: {exc}") from exc
        return {"applied": applied, "config": state.config_view()}

    @app.post("/api/reload", dependencies=admin_guarded)
    def reload_config() -> dict[str, Any]:
        if config_file is None:
            raise HTTPException(
                status_code=503,
                detail="config hot-reload is disabled without a config_file",
            )
        try:
            view = state.reload_from_yaml()
        except PolicyRejected as exc:  # unreadable/floor breach -> 400, shield intact
            raise HTTPException(status_code=400, detail=f"config reload rejected: {exc}") from exc
        return {"reloaded": True, "config": view}

    @app.post("/api/benchmark", dependencies=admin_guarded)
    def benchmark() -> dict[str, Any]:
        try:
            from ..eval import evaluate_shield, load_builtin
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
    admin_keys: list[str] | None = None,
    cors_origins: list[str] | None = None,
    policy_key: str | None = None,
    policy_state_path: str | None = None,
    policy_state_key: str | None = None,
    config_file: str | None = None,
) -> None:  # pragma: no cover
    """Run the control dashboard with uvicorn.

    CLI deployments never reuse ``policy_key`` for durable-state authentication.
    Existing state authenticated by the signing key must be deliberately
    reinitialized or migrated before configuring an independent state key.
    """
    keys = resolve_api_keys(api_keys)
    admins = resolve_admin_keys(admin_keys)
    loopback = is_loopback(host)
    replay_path = resolve_policy_state_path(policy_state_path)
    state_auth_key = resolve_policy_state_key(policy_state_key)
    if not keys and not is_loopback(host):
        raise RuntimeError(
            f"refusing to bind unauthenticated control plane to non-loopback host {host}; "
            "set --api-key or SHADOWSHIELD_API_KEY"
        )
    if not admins and not loopback:
        raise RuntimeError(
            "refusing to expose administrative routes without an independent key; "
            "set --admin-key or SHADOWSHIELD_ADMIN_KEY"
        )
    if resolve_policy_key(policy_key) is None and not loopback:
        raise RuntimeError(
            "refusing to expose unsigned policy updates on a non-loopback host; "
            "set --policy-key or SHADOWSHIELD_POLICY_KEY"
        )
    if replay_path is None and not loopback:
        raise RuntimeError(
            "refusing to expose policy updates without durable replay state; "
            "set --policy-state-path or SHADOWSHIELD_POLICY_STATE_PATH"
        )
    if replay_path is not None and state_auth_key is None:
        raise RuntimeError(
            "durable policy state requires an explicit independent state key; "
            "set --policy-state-key or SHADOWSHIELD_POLICY_STATE_KEY "
            f"({_MIN_POLICY_STATE_KEY_BYTES}+ bytes)"
        )
    if state_auth_key is not None and len(state_auth_key) < _MIN_POLICY_STATE_KEY_BYTES:
        raise RuntimeError(
            f"policy state authentication key must be at least {_MIN_POLICY_STATE_KEY_BYTES} bytes"
        )
    try:
        import uvicorn
    except ImportError as exc:
        raise ImportError(
            "Serving requires the 'dashboard' extra: pip install shadowshield[dashboard]"
        ) from exc
    uvicorn.run(
        create_control_app(
            mode,
            api_keys=api_keys,
            admin_keys=admin_keys,
            cors_origins=cors_origins,
            policy_key=policy_key,
            policy_state_path=policy_state_path,
            policy_state_key=policy_state_key,
            config_file=config_file,
            allow_insecure_local=loopback,
        ),
        host=host,
        port=port,
    )


def main() -> None:  # pragma: no cover
    import argparse

    ap = argparse.ArgumentParser(description="ShadowShield control dashboard")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--mode", default="balanced", choices=["strict", "balanced", "permissive"])
    ap.add_argument("--api-key", action="append", default=None, help="accepted key (repeatable)")
    ap.add_argument(
        "--admin-key",
        action="append",
        default=None,
        help="independent administrator key; also SHADOWSHIELD_ADMIN_KEY",
    )
    ap.add_argument("--cors-origin", action="append", default=None, help="allowed origin")
    ap.add_argument(
        "--policy-key",
        default=None,
        help="HMAC key required to accept policy bundles; also SHADOWSHIELD_POLICY_KEY",
    )
    ap.add_argument(
        "--policy-state-path",
        default=None,
        help="durable anti-replay state; also SHADOWSHIELD_POLICY_STATE_PATH",
    )
    ap.add_argument(
        "--policy-state-key",
        default=None,
        help=(
            "independent 32+ byte HMAC key for durable state; also "
            "SHADOWSHIELD_POLICY_STATE_KEY. Legacy policy-key state is not "
            "auto-migrated"
        ),
    )
    args = ap.parse_args()
    serve_control(
        args.host,
        args.port,
        args.mode,
        api_keys=args.api_key,
        admin_keys=args.admin_key,
        cors_origins=args.cors_origin,
        policy_key=args.policy_key,
        policy_state_path=args.policy_state_path,
        policy_state_key=args.policy_state_key,
    )
