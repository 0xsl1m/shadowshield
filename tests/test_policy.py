"""Tests for pull-based policy bundles + the engine-enforced protection floor."""

from __future__ import annotations

import pytest

from shadowshield.core.config import ShieldConfig
from shadowshield.core.policy import (
    PolicyBundle,
    PolicyRejected,
    ProtectionFloor,
    apply_bundle,
    clamp_to_floor,
    make_hmac_verifier,
    protection_level,
    sign_bundle,
)

# A fixed detector universe so tests don't depend on the live registry.
UNIVERSE = {
    "prompt_injection",
    "jailbreak",
    "encoding_obfuscation",
    "data_exfiltration",
    "pii",
    "anomaly",
    "canary_leak",
}
KEY = b"test-signing-key"


def _local() -> ShieldConfig:
    return ShieldConfig.for_mode("balanced")


# --------------------------------------------------------------------------- #
# Signing / verification
# --------------------------------------------------------------------------- #
def test_sign_verify_roundtrip() -> None:
    b = PolicyBundle(config={"block_threshold": 0.5}, bundle_id="b1", issued_at=1.0)
    b.signature = sign_bundle(b, KEY)
    assert make_hmac_verifier(KEY)(b) is True


def test_bad_signature_rejected() -> None:
    b = PolicyBundle(config={"block_threshold": 0.5}, bundle_id="b1")
    b.signature = "deadbeef"
    with pytest.raises(PolicyRejected):
        apply_bundle(_local(), b, verifier=make_hmac_verifier(KEY), universe=UNIVERSE)


def test_unsigned_rejected_when_verifier_required() -> None:
    b = PolicyBundle(config={"block_threshold": 0.5})  # no signature
    with pytest.raises(PolicyRejected):
        apply_bundle(_local(), b, verifier=make_hmac_verifier(KEY), universe=UNIVERSE)


# --------------------------------------------------------------------------- #
# Protection floor
# --------------------------------------------------------------------------- #
def test_always_on_detector_cannot_be_disabled() -> None:
    # A malicious bundle tries to disable prompt_injection via both levers.
    b = PolicyBundle(
        config={
            "detectors": {"prompt_injection": {"enabled": False}},
            "disabled_detectors": ["canary_leak"],
        }
    )
    out = apply_bundle(_local(), b, universe=UNIVERSE)  # no verifier => skip sig check
    assert out.detector_config("prompt_injection").enabled is True
    assert out.detector_config("canary_leak").enabled is True


def test_block_threshold_clamped_to_ceiling() -> None:
    b = PolicyBundle(config={"block_threshold": 1.0})
    floor = ProtectionFloor(max_block_threshold=0.8)
    out = apply_bundle(_local(), b, floor=floor, universe=UNIVERSE)
    assert out.block_threshold == pytest.approx(0.8)


def test_degradation_cap_rejects_wholesale_weakening() -> None:
    # Disable every non-always-on detector AND raise threshold to the ceiling.
    weak = {n: {"enabled": False} for n in UNIVERSE if n not in {"prompt_injection", "canary_leak"}}
    b = PolicyBundle(config={"block_threshold": 0.8, "detectors": weak})
    floor = ProtectionFloor(max_degradation_delta=0.2)
    with pytest.raises(PolicyRejected):
        apply_bundle(_local(), b, floor=floor, universe=UNIVERSE)


def test_benign_bundle_applied() -> None:
    # Lowering the threshold + bumping a weight is MORE protective: must be accepted.
    b = PolicyBundle(
        config={"block_threshold": 0.5, "detectors": {"prompt_injection": {"weight": 2.0}}}
    )
    out = apply_bundle(_local(), b, universe=UNIVERSE)
    assert out.block_threshold == pytest.approx(0.5)
    assert out.detector_config("prompt_injection").weight == pytest.approx(2.0)


def test_malformed_bundle_rejected() -> None:
    b = PolicyBundle(config={"block_threshold": "not-a-number"})
    with pytest.raises(PolicyRejected):
        apply_bundle(_local(), b, universe=UNIVERSE)


def test_protection_level_monotonic() -> None:
    base = _local()
    stricter = base.model_copy(update={"block_threshold": 0.3})
    looser = base.model_copy(update={"block_threshold": 0.95})
    assert protection_level(stricter, universe=UNIVERSE) > protection_level(base, universe=UNIVERSE)
    assert protection_level(looser, universe=UNIVERSE) < protection_level(base, universe=UNIVERSE)


def test_clamp_is_idempotent() -> None:
    floor = ProtectionFloor()
    once = clamp_to_floor(_local(), floor, universe=UNIVERSE)
    twice = clamp_to_floor(once, floor, universe=UNIVERSE)
    assert once.model_dump() == twice.model_dump()


# --------------------------------------------------------------------------- #
# Floor-completeness regressions (code review M1)
# --------------------------------------------------------------------------- #
def test_always_on_weight_cannot_be_zeroed() -> None:
    # Zeroing an always-on detector's weight would silence it while it reports "enabled".
    b = PolicyBundle(config={"detectors": {"prompt_injection": {"weight": 0.0}}})
    out = apply_bundle(_local(), b, universe=UNIVERSE)
    assert out.detector_config("prompt_injection").enabled is True
    assert out.detector_config("prompt_injection").weight >= 1.0  # clamped to baseline


def test_bundle_cannot_rewrite_policy_mapping() -> None:
    allow_all = {
        "none": "allow",
        "low": "allow",
        "medium": "allow",
        "high": "allow",
        "critical": "allow",
    }
    with pytest.raises(PolicyRejected, match="policy"):
        apply_bundle(_local(), PolicyBundle(config={"policy": allow_all}), universe=UNIVERSE)


def test_bundle_forbidden_fields_rejected() -> None:
    for cfg in ({"mode": "permissive"}, {"max_input_chars": 10**9}, {"raise_on_block": False}):
        with pytest.raises(PolicyRejected):
            apply_bundle(_local(), PolicyBundle(config=cfg), universe=UNIVERSE)


def test_wholesale_weight_zeroing_rejected_by_degradation_cap() -> None:
    weak = {n: {"weight": 0.0} for n in UNIVERSE if n not in {"prompt_injection", "canary_leak"}}
    with pytest.raises(PolicyRejected):
        apply_bundle(_local(), PolicyBundle(config={"detectors": weak}), universe=UNIVERSE)


def test_protection_level_drops_when_weight_zeroed() -> None:
    base = _local()
    weakened = ShieldConfig.for_mode(
        "balanced", detectors={"jailbreak": {"enabled": True, "weight": 0.0}}
    )
    assert protection_level(weakened, universe=UNIVERSE) < protection_level(base, universe=UNIVERSE)
