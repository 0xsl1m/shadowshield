"""Full control-plane server + dashboard (prototype).

This is a richer sibling of :mod:`shadowshield.server`. Where ``server.py`` exposes
a minimal scan API + a one-textarea page, this module powers a full **control
dashboard**: a live scan console + threat feed, metrics/analytics, a config control
panel (toggle detectors, switch mode, tune thresholds/weights - hot-swapped into the
running shield), and a one-click benchmark/eval runner.

Design constraints kept on purpose:

- **Optional dependency.** Imports FastAPI lazily; needs the ``dashboard`` extra.
- **Bounded local state.** Recent scans/metrics live in a bounded in-memory ring.
  Signed policy provenance and effective config persist when a replay-state path
  is configured.
- **No CDN.** The page (``static/dashboard.html``) is fully self-contained with
  inline SVG charts so it runs air-gapped - appropriate for a security tool.
- **Fail-safe mutation.** Config changes rebuild a fresh :class:`Shield` behind a
  lock; a bad patch raises and the previous shield keeps serving.

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

import hashlib
import hmac
import json
import math
import os
import stat
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from ._security import (
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
from .core.config import Mode, ShieldConfig
from .core.policy import (
    PolicyBundle,
    PolicyRejected,
    ProtectionFloor,
    apply_bundle,
    clamp_to_floor,
    make_hmac_verifier,
    protection_level,
)
from .core.shield import Shield
from .core.types import Direction
from .detectors.base import registered_detectors

_STATIC = Path(__file__).parent / "static" / "dashboard.html"
_EVENT_RING_MAX = 1000
_MAX_POLICY_AGE_SECONDS = 86_400
_MAX_POLICY_FUTURE_SKEW_SECONDS = 300
_MAX_POLICY_STATE_BYTES = 262_144
_MIN_POLICY_STATE_KEY_BYTES = 32
_POLICY_STATE_SCHEMA_VERSION = 1
_POLICY_STATE_MAC_DOMAIN = b"shadowshield-policy-state-v1\0"
_LOWERCASE_HEX_DIGITS = frozenset("0123456789abcdef")
_POLICY_STATE_PAYLOAD_KEYS = frozenset(
    {
        "highest_version",
        "bundle_ids",
        "effective_config",
        "active_policy",
        "updated_at",
    }
)
_ACTIVE_POLICY_KEYS = frozenset({"bundle_id", "version", "issued_at", "applied_at"})


def _policy_state_mac_for_key(payload: dict[str, Any], key: bytes) -> str:
    signed = {
        "schema_version": _POLICY_STATE_SCHEMA_VERSION,
        "payload": payload,
    }
    canonical = json.dumps(
        signed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hmac.new(
        key,
        _POLICY_STATE_MAC_DOMAIN + canonical,
        hashlib.sha256,
    ).hexdigest()


def _encode_policy_state(payload: dict[str, Any], key: bytes) -> bytes:
    envelope = {
        "schema_version": _POLICY_STATE_SCHEMA_VERSION,
        "payload": payload,
        "mac": _policy_state_mac_for_key(payload, key),
    }
    encoded = (
        json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(encoded) > _MAX_POLICY_STATE_BYTES:
        raise ValueError(f"policy state exceeds {_MAX_POLICY_STATE_BYTES} byte limit")
    return encoded


def _read_policy_state(path: Path) -> bytes:
    with path.open("rb") as state_file:
        encoded = state_file.read(_MAX_POLICY_STATE_BYTES + 1)
    if len(encoded) > _MAX_POLICY_STATE_BYTES:
        raise ValueError(f"policy state exceeds {_MAX_POLICY_STATE_BYTES} byte limit")
    return encoded


def _parse_policy_state_envelope(encoded: bytes) -> tuple[Any, str]:
    envelope = json.loads(encoded.decode("utf-8"))
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"schema_version", "payload", "mac"}
        or isinstance(envelope["schema_version"], bool)
        or not isinstance(envelope["schema_version"], int)
        or envelope["schema_version"] != _POLICY_STATE_SCHEMA_VERSION
    ):
        raise ValueError("invalid policy state envelope")
    state_mac = envelope["mac"]
    if (
        not isinstance(state_mac, str)
        or len(state_mac) != 64
        or any(character not in _LOWERCASE_HEX_DIGITS for character in state_mac)
    ):
        raise ValueError("invalid policy state MAC")
    return envelope["payload"], state_mac


def _fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# Mutable shield holder - lets the dashboard hot-swap config at runtime
# --------------------------------------------------------------------------- #
class ShieldState:
    """Owns the live shield + the knobs the dashboard can turn.

    Keeps a small amount of *intent* (mode, threshold, per-detector overrides) so
    a config change rebuilds a coherent shield from a mode preset rather than
    mutating a live object in place.
    """

    def __init__(
        self,
        mode: str = "balanced",
        *,
        policy_state_path: str | None = None,
        policy_state_auth_key: bytes | None = None,
    ) -> None:
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
        self._policy_state_path = Path(policy_state_path) if policy_state_path else None
        self._policy_state_auth_key = policy_state_auth_key
        if self._policy_state_path is not None and self._policy_state_auth_key is None:
            raise RuntimeError("durable policy state requires an authentication key")
        self._highest_policy_version = 0
        self._seen_policy_bundle_ids: set[str] = set()
        self._restored_policy_config: dict[str, Any] | None = None
        self._restored_active_policy: dict[str, Any] | None = None
        self._load_policy_state()
        self.shield: Shield = self._build()
        self._baseline_config = self.shield.config.model_copy(deep=True)
        if self._restored_policy_config is not None:
            try:
                restored = ShieldConfig.model_validate(self._restored_policy_config)
                restored = clamp_to_floor(
                    restored,
                    self.floor,
                    baseline=self._baseline_config,
                )
                if restored.model_dump(mode="json") != self._restored_policy_config:
                    raise ValueError("persisted policy config breaches the local protection floor")
                degradation = protection_level(self._baseline_config) - protection_level(restored)
                if degradation > self.floor.max_degradation_delta + 1e-9:
                    raise ValueError(
                        "persisted policy config exceeds the local maximum degradation"
                    )
                self.shield = Shield(restored)
            except Exception as exc:
                raise RuntimeError(f"cannot restore last accepted policy config: {exc}") from exc
            self.mode = (
                restored.mode.value if hasattr(restored.mode, "value") else str(restored.mode)
            )
            self.block_threshold = restored.block_threshold
            self.detector_overrides = {
                name: {
                    "enabled": restored.detector_config(name).enabled,
                    "weight": restored.detector_config(name).weight,
                }
                for name in registered_detectors()
            }
            self.active_policy = self._restored_active_policy

    def _policy_state_mac(self, payload: dict[str, Any]) -> str:
        key = self._policy_state_auth_key
        if key is None:  # Constructor enforces this whenever state is configured.
            raise RuntimeError("durable policy state requires an authentication key")
        return _policy_state_mac_for_key(payload, key)

    @staticmethod
    def _validate_policy_state_payload(raw: Any) -> dict[str, Any]:
        if not isinstance(raw, dict) or set(raw) != _POLICY_STATE_PAYLOAD_KEYS:
            raise ValueError("invalid policy state payload fields")

        version = raw["highest_version"]
        bundle_ids = raw["bundle_ids"]
        effective_config = raw["effective_config"]
        active_policy = raw["active_policy"]
        updated_at = raw["updated_at"]
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise ValueError("invalid highest policy version")
        if (
            not isinstance(bundle_ids, list)
            or not bundle_ids
            or len(bundle_ids) > 1_024
            or any(
                not isinstance(value, str) or not value or len(value) > 128 for value in bundle_ids
            )
            or len(set(bundle_ids)) != len(bundle_ids)
        ):
            raise ValueError("invalid accepted policy bundle IDs")
        if not isinstance(effective_config, dict):
            raise ValueError("invalid effective policy config")
        if not isinstance(active_policy, dict) or set(active_policy) != _ACTIVE_POLICY_KEYS:
            raise ValueError("invalid active policy provenance")

        active_version = active_policy["version"]
        active_bundle_id = active_policy["bundle_id"]
        if (
            isinstance(active_version, bool)
            or not isinstance(active_version, int)
            or active_version != version
            or not isinstance(active_bundle_id, str)
            or active_bundle_id not in bundle_ids
        ):
            raise ValueError("active policy does not match replay state")
        for field in ("issued_at", "applied_at"):
            value = active_policy[field]
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or float(value) <= 0
            ):
                raise ValueError(f"invalid active policy {field}")
        if (
            isinstance(updated_at, bool)
            or not isinstance(updated_at, (int, float))
            or not math.isfinite(float(updated_at))
            or float(updated_at) <= 0
            or float(updated_at) != float(active_policy["applied_at"])
        ):
            raise ValueError("invalid policy state update time")
        return raw

    def _load_policy_state(self) -> None:
        path = self._policy_state_path
        if path is None or not path.exists():
            return
        try:
            encoded_state = _read_policy_state(path)
            raw_payload, state_mac = _parse_policy_state_envelope(encoded_state)
            payload = self._validate_policy_state_payload(raw_payload)
            expected_mac = self._policy_state_mac(payload)
            if not hmac.compare_digest(expected_mac, state_mac):
                raise ValueError("policy state authentication failed")

            version = payload["highest_version"]
            bundle_ids = payload["bundle_ids"]
            self._highest_policy_version = version
            self._seen_policy_bundle_ids = set(bundle_ids)
            self._restored_policy_config = payload["effective_config"]
            self._restored_active_policy = payload["active_policy"]
        except Exception as exc:
            raise RuntimeError(f"cannot load policy replay state from {path}: {exc}") from exc

    def _persist_policy_acceptance(
        self,
        bundle: PolicyBundle,
        effective_config: ShieldConfig,
        *,
        applied_at: float,
    ) -> None:
        path = self._policy_state_path
        next_ids = [*sorted(self._seen_policy_bundle_ids), bundle.bundle_id][-1_024:]
        active_policy = {
            "bundle_id": bundle.bundle_id,
            "version": bundle.version,
            "issued_at": bundle.issued_at,
            "applied_at": applied_at,
        }
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(f".{path.name}.tmp")
            payload = {
                "highest_version": bundle.version,
                "bundle_ids": next_ids,
                "effective_config": effective_config.model_dump(mode="json"),
                "active_policy": active_policy,
                "updated_at": applied_at,
            }
            try:
                key = self._policy_state_auth_key
                if key is None:  # Constructor enforces this whenever state is configured.
                    raise RuntimeError("durable policy state requires an authentication key")
                encoded_state = _encode_policy_state(payload, key)
                with temporary.open("wb") as state_file:
                    state_file.write(encoded_state)
                    state_file.flush()
                    os.fsync(state_file.fileno())
                os.replace(temporary, path)
                _fsync_parent(path)
            except Exception as exc:
                temporary.unlink(missing_ok=True)
                raise PolicyRejected(f"cannot persist policy replay state: {exc}") from exc
        self._highest_policy_version = bundle.version
        self._seen_policy_bundle_ids = set(next_ids)
        self.active_policy = active_policy

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
            candidate = trial._build().config  # raises on a bad patch
            candidate = clamp_to_floor(
                candidate,
                self.floor,
                baseline=self._baseline_config,
            )
            current = self.shield.config
            mode_rank = {"permissive": 0, "balanced": 1, "strict": 2}
            current_mode = (
                current.mode.value if hasattr(current.mode, "value") else str(current.mode)
            )
            candidate_mode = (
                candidate.mode.value if hasattr(candidate.mode, "value") else str(candidate.mode)
            )
            if mode_rank[candidate_mode] < mode_rank[current_mode]:
                raise PolicyRejected("unsigned config changes may not weaken the active mode")
            if candidate.block_threshold > current.block_threshold + 1e-9:
                raise PolicyRejected(
                    "unsigned config changes may not raise the active block threshold"
                )
            for name in registered_detectors():
                active = current.detector_config(name)
                proposed = candidate.detector_config(name)
                if active.enabled and not proposed.enabled:
                    raise PolicyRejected(
                        f"unsigned config changes may not disable active detector {name}"
                    )
                if active.enabled and proposed.weight + 1e-9 < active.weight:
                    raise PolicyRejected(
                        f"unsigned config changes may not reduce active detector weight {name}"
                    )
            new_shield = Shield(candidate)

            self.mode = (
                candidate.mode.value if hasattr(candidate.mode, "value") else str(candidate.mode)
            )
            self.block_threshold = candidate.block_threshold
            self.detector_overrides = {
                name: {
                    "enabled": candidate.detector_config(name).enabled,
                    "weight": candidate.detector_config(name).weight,
                }
                for name in registered_detectors()
            }
            self.shield = new_shield

    def apply_policy(self, bundle: PolicyBundle, *, verifier: Any = None) -> dict[str, Any]:
        """Apply a floor-bounded (optionally signed) bundle to the live shield.

        Raises PolicyRejected on a bad signature or a floor breach; the previous shield
        keeps serving (fail-safe). On success the clamped config becomes live.
        """
        with self._lock:
            now = time.time()
            if bundle.version <= self._highest_policy_version:
                raise PolicyRejected("policy version must increase monotonically")
            if bundle.bundle_id in self._seen_policy_bundle_ids:
                raise PolicyRejected("policy bundle_id has already been accepted")
            if bundle.issued_at > now + _MAX_POLICY_FUTURE_SKEW_SECONDS:
                raise PolicyRejected("policy issued_at is too far in the future")
            if bundle.issued_at < now - _MAX_POLICY_AGE_SECONDS:
                raise PolicyRejected("policy bundle is stale")
            clamped = apply_bundle(
                self.shield.config,
                bundle,
                floor=self.floor,
                verifier=verifier,
                baseline=self._baseline_config,
            )
            next_shield = Shield(clamped)
            # Persist replay state before swapping live config. A persistence
            # failure keeps the previous shield serving and rejects the bundle.
            self._persist_policy_acceptance(bundle, clamped, applied_at=now)
            self.shield = next_shield
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
            assert self.active_policy is not None
            return self.active_policy

    # -- scan + record -------------------------------------------------- #
    def scan_and_record(self, req: ScanRequest) -> dict[str, Any]:
        shield = self.shield  # snapshot (swap is atomic via rebind)
        start = time.perf_counter()
        result = shield.scan(req.text, direction=req.direction, identity=req.identity)
        latency_ms = (time.perf_counter() - start) * 1000.0

        threats = [
            {
                "category": t.category.value,
                "severity": t.severity.label,
                "score": round(t.score, 4),
                "detector": t.detector,
                "span": list(t.span) if t.span else None,
            }
            for t in result.threats[:10]
        ]

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
                "identity_present": req.identity is not None,
                "payload_length": len(req.text),
                "latency_ms": round(latency_ms, 3),
                "threats": threats,
                "findings_total": result.metadata.get("findings_total", len(result.threats)),
                "findings_retained": len(result.threats),
                "findings_truncated": result.metadata.get("findings_truncated", 0),
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

    def events_view(self, limit: int) -> dict[str, Any]:
        with self._lock:
            return {
                "events": list(self.events)[:limit],
                "total": len(self.events),
            }

    def metrics_view(self) -> dict[str, Any]:
        with self._lock:
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
        with self._lock:
            scans_total = self._scans_total
            decision_totals = dict(self._dec_total)
            severity_totals = dict(self._sev_total)
            detector_totals = dict(self._det_total)
            latency_sum_ms = self._lat_sum_ms
        out: list[str] = []
        out.append("# HELP shadowshield_scans_total Total scans processed since start.")
        out.append("# TYPE shadowshield_scans_total counter")
        out.append(f"shadowshield_scans_total {scans_total}")
        out.append("# HELP shadowshield_scan_decisions_total Scans by decision.")
        out.append("# TYPE shadowshield_scan_decisions_total counter")
        for k, v in sorted(decision_totals.items()):
            out.append(f'shadowshield_scan_decisions_total{{decision="{k}"}} {v}')
        out.append("# HELP shadowshield_scan_severity_total Scans by aggregate severity.")
        out.append("# TYPE shadowshield_scan_severity_total counter")
        for k, v in sorted(severity_totals.items()):
            out.append(f'shadowshield_scan_severity_total{{severity="{k}"}} {v}')
        out.append("# HELP shadowshield_detector_hits_total Threats raised, by detector.")
        out.append("# TYPE shadowshield_detector_hits_total counter")
        for k, v in sorted(detector_totals.items()):
            out.append(f'shadowshield_detector_hits_total{{detector="{k}"}} {v}')
        out.append("# HELP shadowshield_scan_latency_seconds_sum Cumulative scan latency.")
        out.append("# TYPE shadowshield_scan_latency_seconds_sum counter")
        out.append(f"shadowshield_scan_latency_seconds_sum {latency_sum_ms / 1000.0:.6f}")
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


def migrate_policy_state(
    path: str | Path,
    *,
    old_key: bytes | str,
    new_key: bytes | str,
    backup_path: str | Path | None = None,
) -> Path:
    """Verify and atomically re-key a stopped 0.6.0 policy-state file.

    The source must authenticate with ``old_key`` and restore as a valid policy
    state before it is changed. The original bytes are preserved in an exclusive
    backup, and the replacement is constrained by the same size limit as startup.
    Run this only while every process using the state file is stopped.
    """

    state_path = Path(path)
    backup = (
        Path(backup_path)
        if backup_path is not None
        else state_path.with_name(f"{state_path.name}.pre-0.6.1.bak")
    )
    old_key_bytes = old_key.encode("utf-8") if isinstance(old_key, str) else old_key
    new_key_bytes = new_key.encode("utf-8") if isinstance(new_key, str) else new_key
    if not old_key_bytes:
        raise ValueError("old policy-state key must not be empty")
    if len(new_key_bytes) < _MIN_POLICY_STATE_KEY_BYTES:
        raise ValueError(
            f"new policy-state key must be at least {_MIN_POLICY_STATE_KEY_BYTES} bytes"
        )
    if hmac.compare_digest(old_key_bytes, new_key_bytes):
        raise ValueError("new policy-state key must be independent from the old key")
    if state_path.resolve() == backup.resolve():
        raise ValueError("backup path must differ from the policy-state path")
    if backup.exists():
        raise FileExistsError(f"refusing to overwrite existing backup {backup}")

    try:
        encoded_source = _read_policy_state(state_path)
        raw_payload, state_mac = _parse_policy_state_envelope(encoded_source)
        payload = ShieldState._validate_policy_state_payload(raw_payload)
        expected_mac = _policy_state_mac_for_key(payload, old_key_bytes)
        if not hmac.compare_digest(expected_mac, state_mac):
            raise ValueError("policy state authentication failed under the old key")

        restored_mode = str(payload["effective_config"].get("mode", Mode.BALANCED.value))
        ShieldState(
            restored_mode,
            policy_state_path=str(state_path),
            policy_state_auth_key=old_key_bytes,
        )
        encoded_replacement = _encode_policy_state(payload, new_key_bytes)
        source_mode = stat.S_IMODE(state_path.stat().st_mode)
    except Exception as exc:
        raise RuntimeError(f"cannot verify policy state {state_path}: {exc}") from exc

    temporary_name: str | None = None
    try:
        temporary_fd, temporary_name = tempfile.mkstemp(
            prefix=f".{state_path.name}.migrate-",
            dir=state_path.parent,
        )
        with os.fdopen(temporary_fd, "wb") as temporary_file:
            temporary_file.write(encoded_replacement)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.chmod(temporary_name, source_mode)

        # Detect an online writer or other change after verification.
        if _read_policy_state(state_path) != encoded_source:
            raise RuntimeError("policy state changed during migration; stop all writers and retry")

        backup_fd = os.open(
            backup,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            source_mode,
        )
        with os.fdopen(backup_fd, "wb") as backup_file:
            backup_file.write(encoded_source)
            backup_file.flush()
            os.fsync(backup_file.fileno())
        _fsync_parent(backup)

        os.replace(temporary_name, state_path)
        temporary_name = None
        _fsync_parent(state_path)
    except Exception as exc:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
        raise RuntimeError(
            f"cannot migrate policy state {state_path}: {exc}; "
            f"the original or backup at {backup} remains recoverable"
        ) from exc

    return backup


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
    """
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException
        from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "The control dashboard requires the 'dashboard' extra: "
            "pip install shadowshield[dashboard]"
        ) from exc

    from . import __version__

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
    )
    if warmup_detectors:
        state.shield.warmup()
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
            applied = state.apply_policy(bundle, verifier=policy_verifier)
        except PolicyRejected as exc:  # floor breach / bad signature -> 400, shield intact
            raise HTTPException(status_code=400, detail=f"policy rejected: {exc}") from exc
        return {"applied": applied, "config": state.config_view()}

    @app.post("/api/benchmark", dependencies=admin_guarded)
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
    admin_keys: list[str] | None = None,
    cors_origins: list[str] | None = None,
    policy_key: str | None = None,
    policy_state_path: str | None = None,
    policy_state_key: str | None = None,
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
            allow_insecure_local=loopback,
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
