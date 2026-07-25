"""Guard MCP (Model Context Protocol) tool calls and tool results.

Agentic injections most often surface as a *tool call* the model was tricked into
making, or hide inside an untrusted *tool result* (a fetched web page, a file). This
module gives a transport-agnostic :class:`ToolGuard` that wraps a :class:`Shield` and
returns structured verdicts for both — usable from any MCP client/proxy without taking
on the ``mcp`` dependency. :func:`build_mcp_server` is an optional convenience that
exposes the guard as an MCP server when the ``mcp`` package is installed.

    guard = ToolGuard(Shield.for_mode("strict"))
    verdict = guard.guard_tool_call("send_email", {"to": addr, "body": body})
    if not verdict["allowed"]:
        refuse(verdict["reason"])
"""

from __future__ import annotations

from typing import Any

from ..core.shield import Shield
from ..core.types import ScanResult


def _verdict(kind: str, name: str, result: ScanResult) -> dict[str, Any]:
    top = result.top_threat()
    return {
        "kind": kind,
        "tool": name,
        "allowed": result.is_safe,
        "blocked": result.blocked,
        "decision": result.decision.value,
        "severity": result.severity.label,
        "score": round(result.score, 4),
        "reason": (top.message if top else None),
        "categories": [c.value for c in result.categories],
        # content-free: detector names + messages only, never the offending payload
        "threats": [
            {
                "detector": t.detector,
                "category": t.category.value,
                "severity": t.severity.label,
                "message": t.message,
            }
            for t in result.threats
        ],
    }


class ToolGuard:
    """Transport-agnostic guard for MCP tool calls and results."""

    def __init__(self, shield: Shield | None = None) -> None:
        self.shield = shield or Shield.for_mode("strict")

    def guard_tool_call(
        self, name: str, arguments: Any, *, identity: str | None = None
    ) -> dict[str, Any]:
        """Scan an outbound tool call (name + arguments) before it executes."""
        result = self.shield.scan_tool_call(name, arguments, identity=identity)
        return _verdict("tool_call", name, result)

    def guard_tool_result(
        self, name: str, result_payload: Any, *, identity: str | None = None
    ) -> dict[str, Any]:
        """Scan an (untrusted) tool result before it re-enters the model context."""
        result = self.shield.scan_tool_result(name, result_payload, identity=identity)
        return _verdict("tool_result", name, result)


def build_mcp_server(shield: Shield | None = None, *, name: str = "shadowshield") -> Any:
    """Build an MCP server exposing ``guard_tool_call`` / ``guard_tool_result`` as tools.

    Requires the optional ``mcp`` package (``pip install mcp``). Kept import-soft so the
    integration module is usable (via :class:`ToolGuard`) without it.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError("build_mcp_server requires the 'mcp' package: pip install mcp") from exc

    guard = ToolGuard(shield)
    server = FastMCP(name)  # pragma: no cover - exercised only with mcp installed

    @server.tool()  # type: ignore[untyped-decorator,unused-ignore]  # pragma: no cover
    def guard_tool_call(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Scan a tool call's name + arguments; returns an allow/block verdict."""
        return guard.guard_tool_call(tool, arguments)

    @server.tool()  # type: ignore[untyped-decorator,unused-ignore]  # pragma: no cover
    def guard_tool_result(tool: str, result: str) -> dict[str, Any]:
        """Scan an untrusted tool result before it re-enters the model context."""
        return guard.guard_tool_result(tool, result)

    return server
