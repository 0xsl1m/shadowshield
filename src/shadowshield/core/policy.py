"""Pull-based policy bundles with an engine-enforced protection floor.

This is the *consumer* side of fleet policy push (see docs/REPORTER_SDK_SPEC.md). It is
deliberately built before any server exists to push bundles, because the dangerous
failure mode is local: a security control must never be remotely turn-off-able.

Threat model addressed: a compromised control plane or signing key pushes a bundle
that disables detection or makes the shield maximally lenient across a fleet on the
next poll. We make that *structurally impossible* on the shield:

1. **Signature verification** - an unsigned/badly-signed bundle is rejected. Skipping
   verification requires an explicit ``allow_unsigned=True`` opt-in at the call site.
2. **Field allow-list** - a bundle may only touch ``block_threshold``, ``detectors``,
   and ``disabled_detectors``. It may NOT rewrite the policy decision mapping, the mode,
   ``raise_on_block``, ``max_input_chars``, or logging - those are not pushable.
3. **Clamp to a local floor** - always-on detectors stay enabled AND keep at least their
   local-baseline weight (so a bundle can't silence them by zeroing the weight); the
   block threshold is capped at a ceiling.
4. **Degradation cap** - even within the floor, a bundle may not lower aggregate
   protection (weighted-enabled detectors + threshold + decision mapping) more than
   ``max_degradation_delta`` vs. the local baseline.
5. **Fail-safe, never fail-open** - on any rejection the caller keeps its last-known-good
   config; this module raises :class:`PolicyRejected` rather than returning a weakened one.

The floor is set by the *customer*, locally - never supplied by the bundle. Signing here
is HMAC-SHA256 (stdlib, zero new deps); the verifier is pluggable so an asymmetric scheme
can drop in later without touching callers.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .config import ShieldConfig
from .types import Decision

# Default always-on detectors: the two that catch the highest-value attacks and
# successful exfiltration. A bundle can never disable or de-weight these below baseline.
_DEFAULT_ALWAYS_ON = frozenset({"prompt_injection", "canary_leak"})

# A bundle may only set these top-level fields. Anything else is rejected, so a bundle
# cannot rewrite the decision mapping, switch mode to permissive, raise the input cap, etc.
_ALLOWED_BUNDLE_KEYS = frozenset({"block_threshold", "detectors", "disabled_detectors"})


class PolicyRejected(Exception):
    """Raised when a bundle fails verification or breaches the protection floor.

    The caller MUST treat this as "keep the last-known-good config" - never as a
    reason to drop protection.
    """


@dataclass(frozen=True)
class ProtectionFloor:
    """Customer-set lower bound on protection that no pushed bundle may cross.

    Attributes:
        always_on: detector names that must stay enabled regardless of any bundle.
        max_block_threshold: the highest (most lenient) ``block_threshold`` a bundle
            may set; anything higher is clamped down to this.
        min_always_on_weight: fallback minimum weight for always-on detectors when no
            local baseline is supplied (the baseline weight is preferred when available).
        max_degradation_delta: the largest allowed drop in aggregate protection level
            (0..1) vs. the local baseline, after clamping. Exceeding it rejects the bundle.
    """

    always_on: frozenset[str] = _DEFAULT_ALWAYS_ON
    max_block_threshold: float = 0.80
    min_always_on_weight: float = 1.0
    max_degradation_delta: float = 0.20


@dataclass
class PolicyBundle:
    """A signed configuration patch fetched from a (future) policy service.

    ``config`` is a partial :class:`ShieldConfig` mapping limited to the allow-listed keys
    (``block_threshold``, ``detectors``, ``disabled_detectors``). The signature covers the
    canonical payload of everything *except* the signature field itself.
    """

    config: dict[str, Any] = field(default_factory=dict)
    version: int = 1
    issued_at: float = 0.0
    bundle_id: str = ""
    signature: str | None = None

    def canonical_payload(self) -> bytes:
        """Deterministic byte payload the signature is computed over."""
        body = {
            "version": self.version,
            "issued_at": self.issued_at,
            "bundle_id": self.bundle_id,
            "config": self.config,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------------- #
# Signing / verification (HMAC-SHA256; pluggable)
# --------------------------------------------------------------------------- #
Verifier = Callable[[PolicyBundle], bool]


def sign_bundle(bundle: PolicyBundle, key: bytes) -> str:
    """Compute the HMAC-SHA256 signature (hex) for ``bundle`` under ``key``."""
    return hmac.new(key, bundle.canonical_payload(), hashlib.sha256).hexdigest()


def make_hmac_verifier(key: bytes) -> Verifier:
    """Build a constant-time HMAC verifier closure."""

    def verify(bundle: PolicyBundle) -> bool:
        if not bundle.signature:
            return False
        expected = sign_bundle(bundle, key)
        return hmac.compare_digest(expected, bundle.signature)

    return verify


# --------------------------------------------------------------------------- #
# Protection level + floor enforcement
# --------------------------------------------------------------------------- #
def _detector_universe(explicit: set[str] | None) -> set[str]:
    if explicit is not None:
        return explicit
    # Lazy import to avoid an import cycle (detectors import core.types).
    from ..detectors.base import registered_detectors

    return set(registered_detectors())


def _decision_protection(d: Decision) -> float:
    """How protective a decision mapping is (1 = block, 0 = allow)."""
    return {
        Decision.BLOCK: 1.0,
        Decision.ESCALATE: 1.0,
        Decision.SANITIZE: 0.6,
        Decision.FLAG: 0.2,
        Decision.ALLOW: 0.0,
    }.get(d, 0.0)


def protection_level(config: ShieldConfig, *, universe: set[str] | None = None) -> float:
    """A scalar in ``[0, 1]`` summarising how protective ``config`` is.

    Combines (a) the **weighted** fraction of enabled detectors (a detector enabled but
    weighted 0 counts as off), (b) the block threshold (lower = more protective), and
    (c) the high/critical decision mapping. Used for the relative degradation check, so
    monotonicity matters more than the exact weights.
    """
    names = _detector_universe(universe)
    if names:
        weighted = sum(
            min(config.detector_config(n).weight, 1.0)
            for n in names
            if config.detector_config(n).enabled
        )
        weighted_frac = weighted / len(names)
    else:
        weighted_frac = 1.0
    threshold_term = 1.0 - max(0.0, min(1.0, config.block_threshold))
    policy_term = (
        _decision_protection(config.policy.high) + _decision_protection(config.policy.critical)
    ) / 2.0
    level = 0.5 * weighted_frac + 0.3 * threshold_term + 0.2 * policy_term
    return max(0.0, min(1.0, level))


def clamp_to_floor(
    config: ShieldConfig,
    floor: ProtectionFloor,
    *,
    universe: set[str] | None = None,
    baseline: ShieldConfig | None = None,
) -> ShieldConfig:
    """Return a copy of ``config`` raised to meet ``floor`` (never weakened below it).

    Always-on detectors are forced enabled and kept at >= their baseline weight (or
    ``floor.min_always_on_weight`` when no baseline is given), so a bundle cannot silence
    them by zeroing the weight. The block threshold is capped at the ceiling.
    """
    data = config.model_dump()
    detectors = dict(data.get("detectors") or {})
    for name in floor.always_on:
        cur = dict(detectors.get(name, {}))
        cur["enabled"] = True
        floor_w = baseline.detector_config(name).weight if baseline else floor.min_always_on_weight
        effective_w = config.detector_config(name).weight
        cur["weight"] = max(effective_w, floor_w)
        detectors[name] = cur
    data["detectors"] = detectors
    # The global kill-switch must not silence an always-on detector either.
    data["disabled_detectors"] = [
        d for d in data.get("disabled_detectors", []) if d not in floor.always_on
    ]
    if data["block_threshold"] > floor.max_block_threshold:
        data["block_threshold"] = floor.max_block_threshold
    return ShieldConfig.model_validate(data)


def _merge_patch(local: ShieldConfig, patch: dict[str, Any]) -> ShieldConfig:
    """Merge an allow-listed partial patch onto ``local`` (per-detector, not wholesale).

    Rejects any field outside :data:`_ALLOWED_BUNDLE_KEYS` so a bundle cannot rewrite the
    decision mapping, mode, input cap, or logging.
    """
    forbidden = set(patch) - _ALLOWED_BUNDLE_KEYS
    if forbidden:
        raise PolicyRejected(f"bundle may not set: {', '.join(sorted(forbidden))}")
    data = local.model_dump()
    patch = dict(patch)
    if patch.get("detectors"):
        merged = dict(data.get("detectors") or {})
        for name, dc in patch["detectors"].items():
            cur = dict(merged.get(name, {}))
            cur.update(dc)
            merged[name] = cur
        data["detectors"] = merged
    patch.pop("detectors", None)
    data.update(patch)
    return ShieldConfig.model_validate(data)


def apply_bundle(
    local: ShieldConfig,
    bundle: PolicyBundle,
    *,
    floor: ProtectionFloor | None = None,
    verifier: Verifier | None = None,
    allow_unsigned: bool = False,
    universe: set[str] | None = None,
    baseline: ShieldConfig | None = None,
) -> ShieldConfig:
    """Validate ``bundle`` against the floor and return the config to apply.

    Order: verify signature -> reject forbidden fields + merge onto local -> clamp up to
    the floor -> reject if the clamped result still degrades protection beyond
    ``max_degradation_delta``. Raises :class:`PolicyRejected` on any failure; the caller
    keeps its current config.

    Verification is fail-closed: when no ``verifier`` is supplied the bundle is rejected
    unless the caller explicitly opts in with ``allow_unsigned=True`` (intended for
    loopback-only embeddings that authenticate out-of-band). Skipping signature checks
    is therefore always a deliberate, greppable decision.
    """
    floor = floor or ProtectionFloor()
    baseline = baseline or local

    if verifier is None:
        if not allow_unsigned:
            raise PolicyRejected(
                "no signature verifier supplied; pass a verifier or explicitly "
                "opt into unsigned bundles with allow_unsigned=True"
            )
    elif not verifier(bundle):
        raise PolicyRejected("signature verification failed")

    try:
        candidate = _merge_patch(local, bundle.config)
    except PolicyRejected:
        raise
    except Exception as exc:  # malformed patch -> reject, do not weaken
        raise PolicyRejected(f"malformed bundle config: {exc}") from exc

    clamped = clamp_to_floor(candidate, floor, universe=universe, baseline=baseline)

    degradation = protection_level(baseline, universe=universe) - protection_level(
        clamped, universe=universe
    )
    if degradation > floor.max_degradation_delta + 1e-9:
        raise PolicyRejected(
            f"bundle degrades protection by {degradation:.3f} "
            f"(> max_degradation_delta {floor.max_degradation_delta})"
        )
    return clamped
