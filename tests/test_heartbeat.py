"""Usage-heartbeat tests — opt-in semantics, payload contract, fail-open."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shadowshield.core.heartbeat import build_payload, maybe_send_heartbeat


@pytest.fixture()
def state_path(tmp_path: Path) -> Path:
    return tmp_path / "heartbeat.json"


class TestOptIn:
    def test_default_off_no_env(self, monkeypatch: pytest.MonkeyPatch, state_path: Path) -> None:
        monkeypatch.delenv("SHADOWSHIELD_HEARTBEAT", raising=False)
        monkeypatch.delenv("SHADOWSHIELD_HEARTBEAT_URL", raising=False)
        assert maybe_send_heartbeat(3, state_path=state_path) is False
        assert not state_path.exists()

    def test_enabled_but_no_url(self, monkeypatch: pytest.MonkeyPatch, state_path: Path) -> None:
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT", "1")
        monkeypatch.delenv("SHADOWSHIELD_HEARTBEAT_URL", raising=False)
        assert maybe_send_heartbeat(3, state_path=state_path) is False
        assert not state_path.exists()

    def test_enabled_wrong_value(self, monkeypatch: pytest.MonkeyPatch, state_path: Path) -> None:
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT", "true")
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT_URL", "http://localhost:1/hb")
        assert maybe_send_heartbeat(3, state_path=state_path) is False


class TestPayload:
    def test_payload_contract(self) -> None:
        payload = build_payload(7, install_id="fixed-id")
        assert set(payload) == {"anon_install_id", "version", "num_services_seen", "ts"}
        assert payload["anon_install_id"] == "fixed-id"
        assert payload["num_services_seen"] == 7
        assert isinstance(payload["version"], str) and payload["version"]

    def test_send_with_injected_transport(
        self, monkeypatch: pytest.MonkeyPatch, state_path: Path
    ) -> None:
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT", "1")
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT_URL", "http://collector.local/hb")
        sent: list[dict] = []
        assert maybe_send_heartbeat(5, state_path=state_path, transport=sent.append) is True
        assert len(sent) == 1
        assert set(sent[0]) == {"anon_install_id", "version", "num_services_seen", "ts"}
        assert sent[0]["num_services_seen"] == 5

    def test_install_id_stable_across_sends(
        self, monkeypatch: pytest.MonkeyPatch, state_path: Path
    ) -> None:
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT", "1")
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT_URL", "http://collector.local/hb")
        sent: list[dict] = []
        assert maybe_send_heartbeat(1, state_path=state_path, transport=sent.append) is True
        # wind clock past the dedupe window
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["last_sent"] = 0
        state_path.write_text(json.dumps(state), encoding="utf-8")
        assert maybe_send_heartbeat(1, state_path=state_path, transport=sent.append) is True
        assert sent[0]["anon_install_id"] == sent[1]["anon_install_id"]


class TestDedupeAndFailOpen:
    def test_24h_dedupe(self, monkeypatch: pytest.MonkeyPatch, state_path: Path) -> None:
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT", "1")
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT_URL", "http://collector.local/hb")
        sent: list[dict] = []
        assert maybe_send_heartbeat(1, state_path=state_path, transport=sent.append) is True
        assert maybe_send_heartbeat(1, state_path=state_path, transport=sent.append) is False
        assert len(sent) == 1

    def test_transport_exception_fails_open(
        self, monkeypatch: pytest.MonkeyPatch, state_path: Path
    ) -> None:
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT", "1")
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT_URL", "http://collector.local/hb")

        def boom(_payload: dict) -> None:
            raise ConnectionError("collector down")

        assert maybe_send_heartbeat(1, state_path=state_path, transport=boom) is False

    def test_corrupt_state_file_recovers(
        self, monkeypatch: pytest.MonkeyPatch, state_path: Path
    ) -> None:
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT", "1")
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT_URL", "http://collector.local/hb")
        state_path.write_text("not json{{{", encoding="utf-8")
        sent: list[dict] = []
        assert maybe_send_heartbeat(2, state_path=state_path, transport=sent.append) is True

    def test_rejects_dangerous_collector_urls(
        self, monkeypatch: pytest.MonkeyPatch, state_path: Path
    ) -> None:
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT", "1")
        sent: list[dict] = []
        for bad in (
            "file:///etc/passwd",
            "ftp://collector.local/hb",
            "https://user:pw@collector.local/hb",
            "https://collector.local/hb#frag",
            "not-a-url",
            "",
        ):
            monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT_URL", bad)
            assert maybe_send_heartbeat(1, state_path=state_path, transport=sent.append) is False
        assert sent == []
        assert not state_path.exists()  # refused before any state write


class TestControlAppWiring:
    def test_heartbeat_thread_not_started_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SHADOWSHIELD_HEARTBEAT", raising=False)
        started: list[str] = []
        from shadowshield.control import app as control_app

        monkeypatch.setattr(
            control_app.threading,
            "Thread",
            lambda *a, **k: type("T", (), {"start": lambda self: started.append("x")})(),
        )
        control_app._start_heartbeat(object())  # type: ignore[arg-type]
        assert started == []

    def test_heartbeat_thread_started_when_enabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SHADOWSHIELD_HEARTBEAT", "1")
        started: list[str] = []
        from shadowshield.control import app as control_app

        monkeypatch.setattr(
            control_app.threading,
            "Thread",
            lambda *a, **k: type("T", (), {"start": lambda self: started.append("x")})(),
        )
        control_app._start_heartbeat(object())  # type: ignore[arg-type]
        assert started == ["x"]
