"""The mutable live-shield holder behind the control plane.

Owns the hot-swappable :class:`~shadowshield.core.shield.Shield`, the bounded
event ring + monotonic Prometheus counters, and the floor-bounded config/policy
mutation paths. Extracted from the monolithic ``control`` module.
"""

from __future__ import annotations

import hmac
import math
import os
import stat
import threading
import time
from collections import deque
from itertools import islice
from pathlib import Path
from typing import Any

from ..core.config import Mode, ShieldConfig
from ..core.policy import (
    PolicyBundle,
    PolicyRejected,
    ProtectionFloor,
    apply_bundle,
    clamp_to_floor,
    protection_level,
)
from ..core.shield import Shield
from ..detectors.base import registered_detectors
from .models import ConfigPatch, ScanRequest
from .policy_state import (
    _ACTIVE_POLICY_KEYS,
    _MAX_POLICY_AGE_SECONDS,
    _MAX_POLICY_FUTURE_SKEW_SECONDS,
    _POLICY_STATE_PAYLOAD_KEYS,
    _assert_file_revision,
    _encode_policy_state,
    _fsync_parent,
    _lstat_policy_state,
    _normalize_operator_file_path,
    _parse_policy_state_envelope,
    _policy_state_mac_for_key,
    _read_policy_state,
    _write_policy_state_temporary,
)

_EVENT_RING_MAX = 1000


def _prometheus_label(value: str) -> str:
    """Escape a dynamic Prometheus label value."""

    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


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
        config_path: str | None = None,
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
        self._det_error_total: dict[str, int] = {}
        self._lat_sum_ms = 0.0
        self.floor = ProtectionFloor()
        self.active_policy: dict[str, Any] | None = None
        self._config_path = _normalize_operator_file_path(config_path) if config_path else None
        self._policy_state_path = (
            _normalize_operator_file_path(policy_state_path) if policy_state_path else None
        )
        self._policy_state_auth_key = policy_state_auth_key
        if self._policy_state_path is not None and self._policy_state_auth_key is None:
            raise RuntimeError("durable policy state requires an authentication key")
        self._highest_policy_version = 0
        self._seen_policy_bundle_ids: set[str] = set()
        # Distinct scan identities seen this process (heartbeat's
        # num_services_seen; bounded, in-memory only, never leaves the node).
        self._identities: set[str] = set()
        self._restored_policy_config: dict[str, Any] | None = None
        self._restored_active_policy: dict[str, Any] | None = None
        self._load_policy_state()
        self.shield: Shield = self._build()
        self._baseline_config = self.shield.config.model_copy(deep=True)
        if self._restored_policy_config is not None:
            try:
                restored_data = dict(self._restored_policy_config)
                if "fail_closed_on_detector_error" not in restored_data:
                    # 0.6.2 durable state predates this field. Preserve the
                    # current mode preset's security posture instead of using
                    # the model-wide balanced default, which would silently
                    # make a restored strict deployment fail open.
                    restored_mode = Mode(restored_data.get("mode", self.mode))
                    restored_data["fail_closed_on_detector_error"] = restored_mode is Mode.STRICT
                restored = ShieldConfig.model_validate(restored_data)
                # Canonicalize through the current schema before checking the
                # protection floor. This permits additive fields with safe
                # defaults to restore older authenticated state while still
                # detecting any clamp that would change its effective policy.
                canonical_restored = restored.model_dump(mode="json")
                restored = clamp_to_floor(
                    restored,
                    self.floor,
                    baseline=self._baseline_config,
                )
                if restored.model_dump(mode="json") != canonical_restored:
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
        if path is None:
            return
        try:
            state_snapshot = _read_policy_state(path, missing_ok=True)
            if state_snapshot is None:
                return
            encoded_state, _ = state_snapshot
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
            temporary: Path | None = None
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
                previous = _lstat_policy_state(path, missing_ok=True)
                target_mode = stat.S_IMODE(previous.st_mode) if previous is not None else 0o600
                temporary, temporary_metadata = _write_policy_state_temporary(
                    path,
                    encoded_state,
                    mode=target_mode,
                )
                _assert_file_revision(path, previous)
                _assert_file_revision(temporary, temporary_metadata)
                # The destination is an explicit operator-selected state file.
                # `temporary` is an exclusive same-directory regular file.
                # codeql[py/path-injection]
                os.replace(temporary, path)
                temporary = None
                _fsync_parent(path)
            except Exception as exc:
                if temporary is not None:
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
            mode_rank = {"shadow": -1, "permissive": 0, "balanced": 1, "strict": 2}
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

    def apply_policy(
        self, bundle: PolicyBundle, *, verifier: Any = None, allow_unsigned: bool = False
    ) -> dict[str, Any]:
        """Apply a floor-bounded (optionally signed) bundle to the live shield.

        Raises PolicyRejected on a bad signature or a floor breach; the previous shield
        keeps serving (fail-safe). On success the clamped config becomes live. Unsigned
        bundles are rejected unless ``allow_unsigned=True`` (loopback-only embeddings).
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
                allow_unsigned=allow_unsigned,
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

    def reload_from_yaml(self) -> dict[str, Any]:
        """Hot-reload the shield from the operator's YAML config file.

        The reloaded config goes through the same fail-safe gates as a policy
        bundle: clamped up to the local protection floor and rejected when it
        would degrade protection beyond ``max_degradation_delta`` vs. the local
        baseline. On any failure the previous shield keeps serving.
        """
        with self._lock:
            if self._config_path is None:
                raise PolicyRejected("no config file configured for hot-reload")
            try:
                candidate = ShieldConfig.from_yaml(self._config_path)
            except Exception as exc:
                raise PolicyRejected(f"cannot reload config: {exc}") from exc
            clamped = clamp_to_floor(candidate, self.floor, baseline=self._baseline_config)
            degradation = protection_level(self._baseline_config) - protection_level(clamped)
            if degradation > self.floor.max_degradation_delta + 1e-9:
                raise PolicyRejected(
                    f"reloaded config degrades protection by {degradation:.3f} "
                    f"(> max_degradation_delta {self.floor.max_degradation_delta})"
                )
            self.shield = Shield(clamped)
            self.block_threshold = clamped.block_threshold
            self.mode = clamped.mode.value if hasattr(clamped.mode, "value") else str(clamped.mode)
            self.detector_overrides = {
                name: {
                    "enabled": clamped.detector_config(name).enabled,
                    "weight": clamped.detector_config(name).weight,
                }
                for name in registered_detectors()
            }
            return self.config_view()

    # -- scan + record -------------------------------------------------- #
    def scan_and_record(self, req: ScanRequest) -> dict[str, Any]:
        shield = self.shield  # snapshot (swap is atomic via rebind)
        start = time.perf_counter()
        result = shield.scan(req.text, direction=req.direction, identity=req.identity)
        latency_ms = (time.perf_counter() - start) * 1000.0
        detector_errors = result.metadata.get("detector_errors", {})
        if not isinstance(detector_errors, dict):
            detector_errors = {}

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
                "detector_errors": dict(detector_errors),
            }
            self.events.appendleft(event)
            if req.identity is not None and len(self._identities) < 10_000:
                self._identities.add(req.identity)
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
            for detector, count in detector_errors.items():
                self._det_error_total[detector] = self._det_error_total.get(detector, 0) + int(
                    count
                )

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
            "fail_closed_on_detector_error": bool(cfg.fail_closed_on_detector_error),
            "llm_check_enabled": bool(cfg.llm_check.enabled),
            "rate_limit_enabled": bool(cfg.rate_limit.enabled),
            "detectors": detectors,
        }

    def events_view(self, limit: int) -> dict[str, Any]:
        with self._lock:
            return {
                "events": list(islice(self.events, limit)),
                "total": len(self.events),
            }

    def services_seen(self) -> int:
        """Count of distinct service identities observed (capped at 10k)."""
        with self._lock:
            return len(self._identities)

    def metrics_view(self) -> dict[str, Any]:
        with self._lock:
            events = list(self.events)
        n = len(events)
        by_decision: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_detector: dict[str, int] = {}
        by_detector_error: dict[str, int] = {}
        by_direction: dict[str, int] = {"input": 0, "output": 0}
        latencies: list[float] = []
        for e in events:
            by_decision[e["decision"]] = by_decision.get(e["decision"], 0) + 1
            by_severity[e["severity"]] = by_severity.get(e["severity"], 0) + 1
            by_direction[e["direction"]] = by_direction.get(e["direction"], 0) + 1
            latencies.append(e["latency_ms"])
            for t in e["threats"]:
                by_detector[t["detector"]] = by_detector.get(t["detector"], 0) + 1
            for detector, count in e.get("detector_errors", {}).items():
                by_detector_error[detector] = by_detector_error.get(detector, 0) + int(count)

        sorted_latencies = sorted(latencies)

        def pct(p: float) -> float:
            if not sorted_latencies:
                return 0.0
            k = max(
                0,
                min(
                    len(sorted_latencies) - 1,
                    round(p / 100 * (len(sorted_latencies) - 1)),
                ),
            )
            return round(sorted_latencies[k], 3)

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
            "detector_errors": sum(by_detector_error.values()),
            "by_detector_error": by_detector_error,
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
            detector_error_totals = dict(self._det_error_total)
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
            out.append(f'shadowshield_detector_hits_total{{detector="{_prometheus_label(k)}"}} {v}')
        out.append("# HELP shadowshield_detector_errors_total Detector execution failures.")
        out.append("# TYPE shadowshield_detector_errors_total counter")
        for k, v in sorted(detector_error_totals.items()):
            out.append(
                f'shadowshield_detector_errors_total{{detector="{_prometheus_label(k)}"}} {v}'
            )
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
