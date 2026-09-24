"""Receipt evidence must reject missing, altered and content-bearing records."""

from __future__ import annotations

import importlib.util
import json
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

_PATH = Path(__file__).resolve().parents[1] / "scripts/qualify_protocol_source.py"
_SPEC = importlib.util.spec_from_file_location("source_qualifier", _PATH)
assert _SPEC and _SPEC.loader
qualifier = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(qualifier)


def _rows() -> list[dict[str, object]]:
    return [
        {
            "test_nodeid": "tests/test_protocol_coverage.py::test_claude_request_variants_reach_scanner",
            "event": "shadowshield.proxy.coverage",
            "schema": "shadowshield.proxy.coverage.v1",
            "protocol": protocol,
            "phase": phase,
            "transport": transport,
            "status": "full",
            "reason": "complete",
            "text_units_discovered": 1,
            "text_units_scanned": 1,
            "opaque_units": 0,
            "media_units": 0,
            "reference_units": 0,
            "malformed_units": 0,
            "scanner_errors": 0,
            "budget_exceeded": False,
            "terminal_seen": transport == "sse",
        }
        for protocol in ("anthropic", "responses")
        for phase, transport in (("request", "json"), ("response", "json"), ("response", "sse"))
    ]


@pytest.mark.parametrize(
    "mutation", ["missing", "boundary", "payload", "type", "enum", "parameter"]
)
def test_coverage_evidence_rejects_gaps_and_untrusted_fields(tmp_path: Path, mutation: str) -> None:
    path = tmp_path / "receipts.jsonl"
    rows = _rows()
    if mutation == "missing":
        assert not qualifier.validate_coverage(path)["valid"]
        return
    if mutation == "boundary":
        rows.pop()
    elif mutation == "payload":
        rows[0]["payload"] = "not permitted"
    elif mutation == "type":
        rows[0]["text_units_scanned"] = True
    elif mutation == "enum":
        rows[0]["reason"] = "unknown-user-controlled-string"
    elif mutation == "parameter":
        rows[0]["test_nodeid"] = str(rows[0]["test_nodeid"]) + "[payload]"
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    assert not qualifier.validate_coverage(path)["valid"]


def test_valid_coverage_is_bound_to_exact_bytes(tmp_path: Path) -> None:
    path = tmp_path / "receipts.jsonl"
    rows = _rows()
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    first = qualifier.validate_coverage(path)
    assert first["valid"] and first["count"] == 6
    rows[0]["text_units_discovered"] = 2
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    second = qualifier.validate_coverage(path)
    assert second["valid"] and first["sha256"] != second["sha256"]


def test_runner_collects_receipts_once_without_other_properties_or_parameter_values() -> None:
    results = qualifier.Results()
    record = _rows()[0]
    for phase in ("setup", "call", "teardown"):
        results.pytest_runtest_logreport(
            SimpleNamespace(
                when=phase,
                failed=False,
                skipped=False,
                nodeid="tests/test_protocol_coverage.py::test_boundary[private-input]",
                outcome="passed",
                duration=0.001,
                user_properties=[
                    ("unrelated_property", "private-input"),
                    ("shadowshield_coverage", record),
                ],
            )
        )
    assert results.coverage_records == [record]
    assert len(results.cases) == 1
    assert "private-input" not in json.dumps(results.cases + results.coverage_records)


@pytest.mark.parametrize("method", ["connect", "connect_ex", "create_connection", "getaddrinfo"])
@pytest.mark.parametrize("address", ["127.0.0.1", "192.0.2.1"])
def test_guard_denies_ordinary_local_and_remote_clients(
    monkeypatch: pytest.MonkeyPatch, method: str, address: str
) -> None:
    # Restore the enclosing qualification guard after this nested test guard.
    for owner, name in (
        (socket.socket, "connect"),
        (socket.socket, "connect_ex"),
        (socket, "create_connection"),
        (socket, "getaddrinfo"),
        (socket, "socketpair"),
    ):
        monkeypatch.setattr(owner, name, getattr(owner, name))
    counts = qualifier.install_network_guard()
    with pytest.raises(RuntimeError, match="forbids network clients"):
        if method in ("connect", "connect_ex"):
            with socket.socket() as client:
                getattr(client, method)((address, 443))
        elif method == "create_connection":
            socket.create_connection((address, 443))
        else:
            socket.getaddrinfo(address, 443)
    assert counts == {"network_attempts": 1, "local_scheduler_socketpairs": 0}
