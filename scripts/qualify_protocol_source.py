"""Run source-only protocol qualification with provider access disabled.

Only fixed test names, outcomes, source hashes and content-free coverage records
are saved. Pytest assertion output and captured application logs are not persisted.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import io
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TESTS = (
    "tests/test_protocol_coverage.py",
    "tests/test_proxy.py",
    "tests/test_shield.py",
    "tests/test_mcp_guard.py",
    "tests/test_stream.py",
    "tests/test_http_security.py",
    "tests/test_config.py",
    "tests/test_source_qualification.py",
)


def source_inventory() -> list[dict[str, Any]]:
    """Bind all Python source/tests plus package metadata to exact disk bytes."""
    paths = [ROOT / "pyproject.toml", Path(__file__).resolve()]
    for folder in ("src", "tests"):
        paths.extend((ROOT / folder).rglob("*.py"))
    return [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "size": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(set(paths))
    ]


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def validate_coverage(path: Path) -> dict[str, Any]:
    """Independently reject missing, non-schema or content-bearing receipts."""
    if not path.is_file():
        return {"valid": False, "count": 0, "reason": "missing"}
    raw = path.read_bytes()
    if not raw or len(raw) > 8_388_608:
        return {"valid": False, "count": 0, "reason": "size"}
    enums = {
        "event": {"shadowshield.proxy.coverage"},
        "schema": {"shadowshield.proxy.coverage.v1"},
        "protocol": {"chat", "anthropic", "responses"},
        "phase": {"request", "response"},
        "transport": {"json", "sse"},
        "status": {"full", "partial", "unscanned", "failed"},
        "reason": {
            "complete",
            "disabled",
            "invalid_json",
            "invalid_utf8",
            "unknown_shape",
            "budget_exceeded",
            "malformed_event",
            "event_too_large",
            "scanner_error",
            "detector_error",
            "upstream_error",
            "stream_incomplete",
        },
    }
    counters = {
        "text_units_discovered",
        "text_units_scanned",
        "opaque_units",
        "media_units",
        "reference_units",
        "malformed_units",
        "scanner_errors",
    }
    flags = {"budget_exceeded", "terminal_seen"}
    expected = set(enums) | counters | flags | {"test_nodeid"}
    tree = ast.parse((ROOT / TESTS[0]).read_text(encoding="utf-8"))
    test_names = {
        f"{TESTS[0]}::{node.name}"
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name.startswith("test_")
    }
    rows: list[dict[str, Any]] = []
    try:
        for line in raw.splitlines():
            row = json.loads(line)
            if not isinstance(row, dict) or set(row) != expected:
                raise ValueError
            if row["test_nodeid"] not in test_names:
                raise ValueError
            if any(
                type(row[key]) is not str or row[key] not in values for key, values in enums.items()
            ):
                raise ValueError
            if any(type(row[key]) is not int or not 0 <= row[key] < 2**63 for key in counters):
                raise ValueError
            if any(type(row[key]) is not bool for key in flags):
                raise ValueError
            rows.append(row)
    except (ValueError, TypeError, UnicodeError, KeyError):
        return {"valid": False, "count": len(rows), "reason": "schema"}
    observed = {(row["protocol"], row["phase"], row["transport"]) for row in rows}
    required = {
        (protocol, phase, transport)
        for protocol in ("anthropic", "responses")
        for phase, transport in (("request", "json"), ("response", "json"), ("response", "sse"))
    }
    return {
        "valid": required <= observed,
        "count": len(rows),
        "reason": "complete" if required <= observed else "missing_boundary",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "boundaries": [list(boundary) for boundary in sorted(observed)],
        "status_counts": {
            status: sum(row["status"] == status for row in rows)
            for status in ("full", "partial", "unscanned", "failed")
        },
    }


class Results:
    def __init__(self) -> None:
        self.cases: list[dict[str, Any]] = []
        self.coverage_records: list[dict[str, Any]] = []
        self.failures = 0

    def pytest_runtest_logreport(self, report: Any) -> None:
        if report.when == "call":
            self.coverage_records.extend(
                record for name, record in report.user_properties if name == "shadowshield_coverage"
            )
        if report.when != "call" and not report.failed and not report.skipped:
            return
        # Parametrized IDs can contain test input: retain only the static name.
        self.cases.append(
            {
                "case": report.nodeid.split("[", 1)[0],
                "phase": report.when,
                "outcome": report.outcome,
                "duration_ms": round(report.duration * 1000, 3),
            }
        )
        self.failures += int(report.failed)


def install_network_guard() -> dict[str, int]:
    """Deny network clients, allowing only Windows' internal scheduler pairs."""
    counts = {"network_attempts": 0, "local_scheduler_socketpairs": 0}
    original_connect = socket.socket.connect

    def deny_network(*_args: Any, **_kwargs: Any) -> Any:
        counts["network_attempts"] += 1
        raise RuntimeError("synthetic qualification forbids network clients")

    def scheduler_socketpair(
        family: int = socket.AF_INET, type: int = socket.SOCK_STREAM, proto: int = 0
    ) -> tuple[socket.socket, socket.socket]:
        # Windows implements socketpair using TCP. The destination is always
        # this function's own ephemeral loopback listener, never caller input.
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError("unsupported scheduler socket family")
        if type != socket.SOCK_STREAM or proto != 0:
            raise ValueError("unsupported scheduler socket type or protocol")
        host = "127.0.0.1" if family == socket.AF_INET else "::1"
        listener = socket.socket(family, type, proto)
        client = None
        server = None
        try:
            listener.bind((host, 0))
            listener.listen(1)
            listener.settimeout(5)
            client = socket.socket(family, type, proto)
            client.setblocking(False)
            with contextlib.suppress(BlockingIOError, InterruptedError):
                original_connect(client, listener.getsockname())
            client.setblocking(True)
            server, _ = listener.accept()
            if (
                server.getsockname() != client.getpeername()
                or client.getsockname() != server.getpeername()
            ):
                raise ConnectionError("unexpected scheduler socket peer")
            counts["local_scheduler_socketpairs"] += 1
            return server, client
        except BaseException:
            if client is not None:
                client.close()
            if server is not None:
                server.close()
            raise
        finally:
            listener.close()

    socket.socket.connect = deny_network  # type: ignore[method-assign]
    socket.socket.connect_ex = deny_network  # type: ignore[method-assign]
    socket.create_connection = deny_network
    socket.getaddrinfo = deny_network
    if os.name == "nt":
        socket.socketpair = scheduler_socketpair
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.receipts.exists():
        parser.error("output paths must be new; previous evidence is never overwritten")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.receipts.parent.mkdir(parents=True, exist_ok=True)

    # Child-process environment only. Never load, inspect or print a credential.
    for name in tuple(os.environ):
        upper = name.upper()
        if upper.startswith("SHADOWSHIELD_") or upper.endswith(
            ("_API_KEY", "_API_KEYS", "_TOKEN", "_SECRET")
        ):
            del os.environ[name]
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    sys.path.insert(0, str(ROOT / "src"))
    os.chdir(ROOT)

    network = install_network_guard()

    import pytest

    import shadowshield

    if Path(shadowshield.__file__).resolve() != ROOT / "src/shadowshield/__init__.py":
        raise RuntimeError("qualification imported a different source tree")
    before = source_inventory()
    results = Results()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        exit_code = int(
            pytest.main(["-q", "-p", "pytest_asyncio.plugin", *TESTS], plugins=[results])
        )
    after = source_inventory()
    with args.receipts.open("x", encoding="utf-8", newline="\n") as out:
        for record in results.coverage_records:
            out.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    coverage = validate_coverage(args.receipts)
    passed = (
        exit_code == 0
        and before == after
        and network["network_attempts"] == 0
        and bool(results.cases)
        and coverage["valid"]
    )
    receipt = {
        "schema": "shadowshield.synthetic-qualification.v1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": "PASS" if passed else "FAIL",
        "version": shadowshield.__version__,
        "source_files": before,
        "source_inventory_sha256": hashlib.sha256(canonical(before)).hexdigest(),
        "source_unchanged_during_tests": before == after,
        "network_guard_installed": True,
        "network_attempts": network["network_attempts"],
        "local_scheduler_socketpairs": network["local_scheduler_socketpairs"],
        "targeted_sensitive_env_removed": True,
        "removed_env_name_patterns": [
            "SHADOWSHIELD_*",
            "*_API_KEY",
            "*_API_KEYS",
            "*_TOKEN",
            "*_SECRET",
        ],
        "live_mutation_authorized": False,
        "coverage_receipts": coverage,
        "test_exit_code": exit_code,
        "case_count": len(results.cases),
        "passed_count": sum(case["outcome"] == "passed" for case in results.cases),
        "skipped_count": sum(case["outcome"] == "skipped" for case in results.cases),
        "failed_count": results.failures,
        "cases": results.cases,
    }
    with args.output.open("x", encoding="utf-8") as out:
        json.dump(receipt, out, indent=2)
        out.write("\n")
    print(
        json.dumps(
            {k: receipt[k] for k in ("status", "case_count", "failed_count", "network_attempts")}
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
