"""Coverage for the plugin manager: registration, aggregation, discovery."""

from __future__ import annotations

import shadowshield as ss
from shadowshield.core.types import Direction
from shadowshield.detectors.base import Detector, ScanContext
from shadowshield.middleware.base import message_direction, message_text, scan_messages
from shadowshield.plugins.base import ShadowShieldPlugin
from shadowshield.plugins.manager import ENTRY_POINT_GROUP, PluginManager
from shadowshield.responders.blocker import BlockResponder


class _KeywordDetector(Detector):
    name = "keyword_test"

    def scan(self, text: str, *, context: ScanContext):
        return []


class _DemoPlugin(ShadowShieldPlugin):
    name = "demo"

    def detectors(self):
        return [_KeywordDetector()]

    def responders(self):
        return [BlockResponder()]


def test_register_and_aggregate() -> None:
    mgr = PluginManager()
    mgr.register(_DemoPlugin())
    assert [p.name for p in mgr.plugins] == ["demo"]
    assert [d.name for d in mgr.detectors()] == ["keyword_test"]
    assert len(mgr.responders()) == 1


def test_empty_manager_aggregates_nothing() -> None:
    mgr = PluginManager()
    assert mgr.plugins == []
    assert mgr.detectors() == []
    assert mgr.responders() == []


def test_default_plugin_hooks_are_noops() -> None:
    base = ShadowShieldPlugin()
    assert base.detectors() == []
    assert base.responders() == []


def test_discover_loads_entry_points(monkeypatch) -> None:
    class _EP:
        name = "demo"

        def load(self):
            return _DemoPlugin

    monkeypatch.setattr(
        "shadowshield.plugins.manager.metadata.entry_points",
        lambda group: [_EP()] if group == ENTRY_POINT_GROUP else [],
    )
    mgr = PluginManager()
    assert mgr.discover() == ["demo"]
    assert [p.name for p in mgr.plugins] == ["demo"]


def test_discover_skips_broken_entry_points(monkeypatch) -> None:
    class _BadEP:
        def load(self):
            raise RuntimeError("broken plugin")

    class _NonPluginEP:
        def load(self):
            return object()  # not a ShadowShieldPlugin instance

    monkeypatch.setattr(
        "shadowshield.plugins.manager.metadata.entry_points",
        lambda group: [_BadEP(), _NonPluginEP()],
    )
    mgr = PluginManager()
    assert mgr.discover() == []
    assert mgr.plugins == []


# -- middleware/base.py edge paths ------------------------------------------ #
def test_message_text_multimodal_parts() -> None:
    msg = {
        "role": "user",
        "content": [
            "plain part",
            {"type": "text", "text": "dict part"},
            {"type": "image_url", "image_url": "ignored"},
            {"text": "typeless part"},
        ],
    }
    assert message_text(msg) == "plain part\ndict part\ntypeless part"


def test_message_text_object_and_fallback() -> None:
    class _Obj:
        content = 123

    assert message_text(_Obj()) == "123"
    assert message_text({"role": "user"}) == ""
    assert message_text(object()) == ""


def test_message_direction_roles() -> None:
    assert message_direction({"role": "assistant"}) is Direction.OUTPUT
    assert message_direction({"role": "tool"}) is Direction.INPUT

    class _LCMsg:
        type = "ai"

    assert message_direction(_LCMsg()) is Direction.OUTPUT
    assert message_direction({"role": "system"}) is Direction.INPUT  # default
    assert message_direction({"role": "system"}, default=Direction.OUTPUT) is Direction.OUTPUT


def test_scan_messages_skips_empty_and_scans_rest() -> None:
    shield = ss.Shield.for_mode("balanced")
    results = scan_messages(
        shield,
        [
            {"role": "user", "content": ""},
            {"role": "user", "content": "hello there"},
            {"role": "assistant", "content": "hi! how can I help?"},
        ],
    )
    assert len(results) == 2
    assert results[0].direction is Direction.INPUT
    assert results[1].direction is Direction.OUTPUT
