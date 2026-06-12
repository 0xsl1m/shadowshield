"""Tests for configuration loading, mode presets, and policy mapping."""

from __future__ import annotations

import textwrap

from shadowshield import Decision, Severity
from shadowshield.core.config import Mode, PolicyConfig, ShieldConfig


def test_mode_presets_differ() -> None:
    strict = ShieldConfig.for_mode("strict")
    permissive = ShieldConfig.for_mode("permissive")
    assert strict.block_threshold < permissive.block_threshold
    assert strict.policy.medium == Decision.BLOCK
    assert permissive.policy.medium == Decision.FLAG


def test_for_mode_overrides() -> None:
    cfg = ShieldConfig.for_mode("balanced", block_threshold=0.3)
    assert cfg.block_threshold == 0.3
    assert cfg.mode == Mode.BALANCED


def test_policy_decide_maps_every_severity() -> None:
    policy = PolicyConfig()
    for sev in Severity:
        assert isinstance(policy.decide(sev), Decision)


def test_from_yaml_layers_on_mode(tmp_path) -> None:
    yaml_text = textwrap.dedent(
        """
        mode: strict
        block_threshold: 0.2
        rate_limit:
          enabled: true
          max_events: 5
        """
    )
    path = tmp_path / "cfg.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    cfg = ShieldConfig.from_yaml(path)
    assert cfg.mode == Mode.STRICT
    assert cfg.block_threshold == 0.2
    assert cfg.rate_limit.enabled
    assert cfg.rate_limit.max_events == 5


def test_disabled_detectors_kill_switch() -> None:
    cfg = ShieldConfig.for_mode("balanced", disabled_detectors=["jailbreak"])
    assert cfg.detector_config("jailbreak").enabled is False
    assert cfg.detector_config("prompt_injection").enabled is True


def test_detector_weight_default() -> None:
    cfg = ShieldConfig.for_mode("balanced")
    assert cfg.detector_config("anything").weight == 1.0
