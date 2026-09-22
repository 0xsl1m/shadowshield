"""Bounded protocol extraction and content-free scan coverage receipts.

This module understands the text-bearing portions of the wire formats accepted
by the gateway.  It deliberately keeps inspected values out of receipts: only
fixed enums, counts, and booleans leave the extraction boundary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, ClassVar

MAX_ITEMS = 128
MAX_DEPTH = 6
MAX_TOOL_CHANNELS = 128
MAX_TOOL_BUFFER_BYTES = 1_048_576
STREAM_CHANNEL_TAIL_CHARS = 4_096
MAX_STREAM_SCAN_WORK_CHARS = 16_777_216

_JSON_CHANNELS = frozenset(
    {"anthropic_tool", "chat_function", "chat_tool", "function_arguments", "mcp_arguments"}
)

PROTOCOLS = frozenset({"chat", "anthropic", "responses"})
PHASES = frozenset({"request", "response"})
TRANSPORTS = frozenset({"json", "sse"})
REASONS = frozenset(
    {
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
    }
)


@dataclass
class Extraction:
    """Text units plus bounded, content-free facts about what was not text."""

    texts: list[str] = field(default_factory=list)
    opaque_units: int = 0
    media_units: int = 0
    reference_units: int = 0
    malformed_units: int = 0
    unknown_shape: bool = False
    budget_exceeded: bool = False

    @property
    def complete(self) -> bool:
        return not (
            self.unknown_shape
            or self.budget_exceeded
            or self.malformed_units
            or self.opaque_units
            or self.media_units
            or self.reference_units
        )

    @property
    def enforcement_gap(self) -> bool:
        """Whether text may have escaped extraction in an enforceable shape."""
        return self.unknown_shape or self.budget_exceeded or bool(self.malformed_units)

    def add_text(self, value: str) -> None:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            self.mark_malformed()
            return
        if len(self.texts) >= MAX_ITEMS:
            self.budget_exceeded = True
            return
        self.texts.append(value)

    def merge(self, other: Extraction) -> None:
        for text in other.texts:
            self.add_text(text)
        self.opaque_units += other.opaque_units
        self.media_units += other.media_units
        self.reference_units += other.reference_units
        self.malformed_units += other.malformed_units
        self.unknown_shape = self.unknown_shape or other.unknown_shape
        self.budget_exceeded = self.budget_exceeded or other.budget_exceeded

    def mark_unknown(self) -> None:
        self.unknown_shape = True
        self.opaque_units += 1

    def mark_malformed(self) -> None:
        self.malformed_units += 1


_REASON_PRIORITY = {
    "complete": 0,
    "upstream_error": 1,
    "stream_incomplete": 2,
    "unknown_shape": 3,
    "invalid_utf8": 4,
    "malformed_event": 5,
    "invalid_json": 6,
    "event_too_large": 7,
    "budget_exceeded": 8,
    "disabled": 9,
    "detector_error": 10,
    "scanner_error": 11,
}


@dataclass
class CoverageReceipt:
    """Aggregate scan accounting for one request or response boundary."""

    protocol: str
    phase: str
    transport: str
    text_units_discovered: int = 0
    text_units_scanned: int = 0
    opaque_units: int = 0
    media_units: int = 0
    reference_units: int = 0
    malformed_units: int = 0
    scanner_errors: int = 0
    budget_exceeded: bool = False
    terminal_seen: bool = False
    _reason: str = "complete"
    _emitted: bool = False

    SCHEMA: ClassVar[str] = "shadowshield.proxy.coverage.v1"

    def __post_init__(self) -> None:
        if self.protocol not in PROTOCOLS:
            raise ValueError("invalid coverage protocol")
        if self.phase not in PHASES:
            raise ValueError("invalid coverage phase")
        if self.transport not in TRANSPORTS:
            raise ValueError("invalid coverage transport")

    def record_extraction(self, extraction: Extraction) -> None:
        self.text_units_discovered += len(extraction.texts)
        self.opaque_units += extraction.opaque_units
        self.media_units += extraction.media_units
        self.reference_units += extraction.reference_units
        self.malformed_units += extraction.malformed_units
        self.budget_exceeded = self.budget_exceeded or extraction.budget_exceeded
        if extraction.budget_exceeded:
            self.mark("budget_exceeded")
        elif extraction.malformed_units:
            self.mark("malformed_event" if self.transport == "sse" else "unknown_shape")
        elif (
            extraction.unknown_shape
            or extraction.opaque_units
            or extraction.media_units
            or extraction.reference_units
        ):
            self.mark("unknown_shape")

    def record_scanned(self, count: int = 1) -> None:
        self.text_units_scanned += count

    def mark(self, reason: str, *, scanner_error: bool = False) -> None:
        if reason not in REASONS:
            raise ValueError("invalid coverage reason")
        if _REASON_PRIORITY[reason] > _REASON_PRIORITY[self._reason]:
            self._reason = reason
        if scanner_error:
            self.scanner_errors += 1

    @property
    def has_gap(self) -> bool:
        return self._reason not in {"complete", "upstream_error"} or (
            self.text_units_scanned < self.text_units_discovered
        )

    def as_event(self) -> dict[str, str | int | bool]:
        if self.scanner_errors:
            status = "failed"
        elif self._reason in {"disabled", "upstream_error"}:
            status = "unscanned"
        elif self.has_gap:
            status = "partial" if self.text_units_scanned else "unscanned"
        else:
            status = "full"
        return {
            "schema": self.SCHEMA,
            "protocol": self.protocol,
            "phase": self.phase,
            "transport": self.transport,
            "status": status,
            "reason": self._reason,
            "text_units_discovered": self.text_units_discovered,
            "text_units_scanned": self.text_units_scanned,
            "opaque_units": self.opaque_units,
            "media_units": self.media_units,
            "reference_units": self.reference_units,
            "malformed_units": self.malformed_units,
            "scanner_errors": self.scanner_errors,
            "budget_exceeded": self.budget_exceeded,
            "terminal_seen": self.terminal_seen,
        }

    def emit(self, log: Any) -> None:
        if self._emitted:
            return
        self._emitted = True
        log.info("shadowshield.proxy.coverage", **self.as_event())


@dataclass
class _JsonFragmentState:
    depth: int = 0
    started: bool = False
    in_string: bool = False
    escaped: bool = False
    complete: bool = False
    invalid: bool = False

    def feed(self, fragment: str) -> bool:
        """Return true exactly when an object or array first completes."""
        became_complete = False
        for char in fragment:
            if self.complete:
                if not char.isspace():
                    self.invalid = True
                continue
            if not self.started:
                if char.isspace():
                    continue
                if char not in "[{":
                    self.invalid = True
                    continue
                self.started = True
                self.depth = 1
                continue
            if self.in_string:
                if self.escaped:
                    self.escaped = False
                elif char == "\\":
                    self.escaped = True
                elif char == '"':
                    self.in_string = False
                continue
            if char == '"':
                self.in_string = True
            elif char in "[{":
                self.depth += 1
            elif char in "]}":
                self.depth -= 1
                if self.depth < 0:
                    self.invalid = True
                elif self.depth == 0:
                    self.complete = True
                    became_complete = True
        return became_complete


def _json_texts(value: Any) -> list[str]:
    """Return raw and decoded/canonical forms for structured string payloads."""
    if isinstance(value, (dict, list)):
        try:
            return [json.dumps(value, ensure_ascii=False, separators=(",", ":"))]
        except (TypeError, ValueError, OverflowError, RecursionError):
            return []
    if not isinstance(value, str):
        return []
    texts = [value]
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        return texts
    if isinstance(decoded, (dict, list, str)):
        try:
            canonical = (
                decoded
                if isinstance(decoded, str)
                else json.dumps(decoded, ensure_ascii=False, separators=(",", ":"))
            )
        except (TypeError, ValueError, OverflowError, RecursionError):
            return texts
        if canonical != value:
            texts.append(canonical)
    return texts


def _add_json(result: Extraction, value: Any, *, required: bool = False) -> None:
    texts = _json_texts(value)
    if not texts:
        if required:
            result.mark_malformed()
        return
    for text in texts:
        result.add_text(text)


def _walk_anthropic(value: Any, result: Extraction, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        result.budget_exceeded = True
        return
    if isinstance(value, str):
        result.add_text(value)
        return
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            result.budget_exceeded = True
        for item in value[:MAX_ITEMS]:
            _walk_anthropic(item, result, depth=depth + 1)
        return
    if value is None:
        return
    if not isinstance(value, dict):
        result.mark_malformed()
        return

    block_type = value.get("type")
    if block_type is not None and not isinstance(block_type, str):
        result.mark_malformed()
        return
    if block_type == "text":
        text = value.get("text")
        result.add_text(text) if isinstance(text, str) else result.mark_malformed()
    elif block_type == "thinking":
        thinking = value.get("thinking")
        result.add_text(thinking) if isinstance(thinking, str) else result.mark_malformed()
        if "signature" in value:
            result.opaque_units += 1
    elif block_type == "redacted_thinking":
        result.opaque_units += 1
    elif block_type in {"tool_use", "server_tool_use", "mcp_tool_use"}:
        _add_json(result, value.get("input"), required=True)
    elif block_type in {"tool_result", "mcp_tool_result"} or block_type in {
        "web_search_tool_result",
        "web_fetch_tool_result",
        "code_execution_tool_result",
        "bash_code_execution_tool_result",
        "text_editor_code_execution_tool_result",
        "tool_search_tool_result",
    }:
        _walk_anthropic(value.get("content"), result, depth=depth + 1)
    elif block_type in {"web_search_result", "search_result"}:
        title = value.get("title")
        if isinstance(title, str):
            result.add_text(title)
        content = value.get("content")
        if content is not None:
            _walk_anthropic(content, result, depth=depth + 1)
        if "url" in value or "source" in value:
            result.reference_units += 1
        if "encrypted_content" in value:
            result.opaque_units += 1
    elif block_type in {"web_fetch_result", "document"}:
        source = value.get("source")
        source_type = source.get("type") if isinstance(source, dict) else None
        if source_type is not None and not isinstance(source_type, str):
            result.mark_malformed()
        elif isinstance(source, dict) and source_type == "text":
            data = source.get("data")
            result.add_text(data) if isinstance(data, str) else result.mark_malformed()
        elif isinstance(source, dict) and source_type in {"base64", "content"}:
            result.media_units += 1
        elif source is not None:
            result.reference_units += 1
        content = value.get("content")
        if content is not None:
            _walk_anthropic(content, result, depth=depth + 1)
    elif block_type in {
        "code_execution_result",
        "bash_code_execution_result",
        "text_editor_code_execution_result",
    }:
        found = False
        for field_name in ("stdout", "stderr", "output", "content"):
            field_value = value.get(field_name)
            if isinstance(field_value, str):
                result.add_text(field_value)
                found = True
            elif isinstance(field_value, (list, dict)):
                _walk_anthropic(field_value, result, depth=depth + 1)
                found = True
        if not found and value.get("is_error"):
            result.opaque_units += 1
    elif block_type == "tool_search_tool_search_result":
        references = value.get("tool_references")
        if isinstance(references, list):
            result.reference_units += len(references[:MAX_ITEMS])
            if len(references) > MAX_ITEMS:
                result.budget_exceeded = True
        else:
            result.mark_malformed()
    elif block_type in {"tool_reference", "citation", "citations_delta"}:
        result.reference_units += 1
    elif block_type in {"image", "audio", "browser_state"}:
        result.media_units += 1
    elif block_type in {
        "web_search_tool_result_error",
        "web_fetch_tool_result_error",
        "code_execution_tool_result_error",
        "bash_code_execution_tool_result_error",
        "text_editor_code_execution_tool_result_error",
    }:
        result.opaque_units += 1
    else:
        result.mark_unknown()


def _walk_openai(value: Any, result: Extraction, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        result.budget_exceeded = True
        return
    if isinstance(value, str):
        for text in _json_texts(value):
            result.add_text(text)
        return
    if isinstance(value, list):
        if len(value) > MAX_ITEMS:
            result.budget_exceeded = True
        for item in value[:MAX_ITEMS]:
            _walk_openai(item, result, depth=depth + 1)
        return
    if value is None:
        return
    if not isinstance(value, dict):
        result.mark_malformed()
        return

    item_type = value.get("type")
    if item_type is not None and not isinstance(item_type, str):
        result.mark_malformed()
        return
    if item_type in {"input_text", "output_text", "text", "summary_text"}:
        text_value = value.get("text")
        if isinstance(text_value, str):
            for variant in _json_texts(text_value):
                result.add_text(variant)
        else:
            result.mark_malformed()
    elif item_type == "refusal":
        refusal = value.get("refusal")
        result.add_text(refusal) if isinstance(refusal, str) else result.mark_malformed()
    elif item_type in {"message", "input_message", "output_message", "easy_input_message"} or (
        item_type is None and isinstance(value.get("role"), str) and "content" in value
    ):
        _walk_openai(value.get("content"), result, depth=depth + 1)
    elif item_type in {"function_call", "mcp_call"}:
        _add_json(result, value.get("arguments"), required=True)
        for field_name in ("output", "error"):
            field_value = value.get(field_name)
            if isinstance(field_value, str):
                result.add_text(field_value)
    elif item_type == "function_call_output":
        _walk_openai(value.get("output"), result, depth=depth + 1)
    elif item_type in {"custom_tool_call", "custom_tool_call_output"}:
        field_name = "input" if "input" in value else "output"
        _add_json(result, value.get(field_name), required=True)
    elif item_type in {
        "computer_call",
        "shell_call",
        "local_shell_call",
        "apply_patch_call",
        "web_search_call",
    }:
        structured = value.get("action")
        if structured is None:
            structured = value.get("actions")
        if structured is None:
            structured = value.get("command")
        if structured is None:
            structured = value.get("operation")
        _add_json(result, structured, required=item_type not in {"web_search_call"})
        output = value.get("output")
        if isinstance(output, (str, dict, list)):
            _walk_openai(output, result, depth=depth + 1)
    elif item_type in {
        "computer_call_output",
        "shell_call_output",
        "local_shell_call_output",
        "apply_patch_call_output",
    }:
        output = value.get("output")
        if isinstance(output, str):
            result.add_text(output)
        elif isinstance(output, (dict, list)):
            _walk_openai(output, result, depth=depth + 1)
        else:
            result.mark_malformed()
    elif item_type == "reasoning":
        _walk_openai(value.get("summary"), result, depth=depth + 1)
        _walk_openai(value.get("content"), result, depth=depth + 1)
        if value.get("encrypted_content") is not None:
            result.opaque_units += 1
    elif item_type in {"compaction", "computer_screenshot"}:
        result.opaque_units += 1
    elif item_type in {"input_image", "output_image", "image_generation_call"}:
        result.media_units += 1
    elif item_type in {"input_file", "file_reference", "item_reference"}:
        if value.get("file_data") is not None:
            result.media_units += 1
        else:
            result.reference_units += 1
    elif item_type == "code_interpreter_call":
        code = value.get("code")
        if isinstance(code, str):
            result.add_text(code)
        outputs = value.get("outputs")
        if isinstance(outputs, list):
            for output in outputs[:MAX_ITEMS]:
                if isinstance(output, dict) and output.get("type") == "logs":
                    logs = output.get("logs")
                    result.add_text(logs) if isinstance(logs, str) else result.mark_malformed()
                else:
                    result.media_units += 1
            if len(outputs) > MAX_ITEMS:
                result.budget_exceeded = True
    elif item_type == "file_search_call":
        queries = value.get("queries")
        if isinstance(queries, list):
            for query in queries[:MAX_ITEMS]:
                result.add_text(query) if isinstance(query, str) else result.mark_malformed()
            if len(queries) > MAX_ITEMS:
                result.budget_exceeded = True
        results = value.get("results")
        if isinstance(results, list):
            for item in results[:MAX_ITEMS]:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    result.add_text(item["text"])
                else:
                    result.reference_units += 1
            if len(results) > MAX_ITEMS:
                result.budget_exceeded = True
    elif item_type in {"mcp_list_tools", "mcp_approval_request", "mcp_approval_response"}:
        payload = value.get("tools") if "tools" in value else value.get("approve")
        if payload is None:
            result.reference_units += 1
        else:
            _add_json(result, payload)
    elif item_type is None and any(
        field_name in value for field_name in ("stdout", "stderr", "output", "content", "result")
    ):
        found = False
        for field_name in ("stdout", "stderr", "output", "content", "result"):
            field_value = value.get(field_name)
            if isinstance(field_value, (str, dict, list)):
                _walk_openai(field_value, result, depth=depth + 1)
                found = True
        if not found:
            result.mark_malformed()
    else:
        result.mark_unknown()


def extract_request(payload: dict[str, Any], protocol: str) -> Extraction:
    result = Extraction()
    if protocol == "chat":
        messages = payload.get("messages")
        if isinstance(messages, list):
            if len(messages) > MAX_ITEMS:
                result.budget_exceeded = True
            for message in messages[:MAX_ITEMS]:
                if not isinstance(message, dict):
                    result.mark_malformed()
                    continue
                _walk_openai(message, result)
                function_call = message.get("function_call")
                if isinstance(function_call, dict):
                    _add_json(result, function_call.get("arguments"), required=True)
                tool_calls = message.get("tool_calls")
                if isinstance(tool_calls, list):
                    for tool_call in tool_calls[:MAX_ITEMS]:
                        function = (
                            tool_call.get("function") if isinstance(tool_call, dict) else None
                        )
                        if isinstance(function, dict):
                            _add_json(result, function.get("arguments"), required=True)
                        else:
                            result.mark_malformed()
                    if len(tool_calls) > MAX_ITEMS:
                        result.budget_exceeded = True
        elif messages is not None:
            result.mark_malformed()
        prompt = payload.get("prompt")
        if prompt is not None:
            _walk_openai(prompt, result)
        tools = payload.get("tools")
        if isinstance(tools, list):
            if len(tools) > MAX_ITEMS:
                result.budget_exceeded = True
            for tool in tools[:MAX_ITEMS]:
                _add_json(result, tool, required=True)
        elif tools is not None:
            result.mark_malformed()
        return result

    if protocol == "anthropic":
        system = payload.get("system")
        if system is not None:
            _walk_anthropic(system, result)
        messages = payload.get("messages")
        if isinstance(messages, list):
            if len(messages) > MAX_ITEMS:
                result.budget_exceeded = True
            for message in messages[:MAX_ITEMS]:
                if isinstance(message, dict):
                    _walk_anthropic(message.get("content"), result)
                else:
                    result.mark_malformed()
        else:
            result.mark_malformed()
        tools = payload.get("tools")
        if isinstance(tools, list):
            if len(tools) > MAX_ITEMS:
                result.budget_exceeded = True
            for tool in tools[:MAX_ITEMS]:
                _add_json(result, tool, required=True)
        elif tools is not None:
            result.mark_malformed()
        return result

    instructions = payload.get("instructions")
    if instructions is not None:
        _walk_openai(instructions, result)
    input_value = payload.get("input")
    if input_value is not None:
        _walk_openai(input_value, result)
    prompt = payload.get("prompt")
    variables = prompt.get("variables") if isinstance(prompt, dict) else None
    if isinstance(variables, dict):
        if len(variables) > MAX_ITEMS:
            result.budget_exceeded = True
        for value in list(variables.values())[:MAX_ITEMS]:
            _walk_openai(value, result)
    elif prompt is not None and not isinstance(prompt, dict):
        result.mark_malformed()
    tools = payload.get("tools")
    if isinstance(tools, list):
        if len(tools) > MAX_ITEMS:
            result.budget_exceeded = True
        for tool in tools[:MAX_ITEMS]:
            _add_json(result, tool, required=True)
    elif tools is not None:
        result.mark_malformed()
    if isinstance(prompt, dict) and prompt.get("id") is not None:
        result.reference_units += 1
    if payload.get("previous_response_id") is not None or payload.get("conversation") is not None:
        result.reference_units += 1
    return result


def extract_response(payload: dict[str, Any], protocol: str) -> Extraction:
    result = Extraction()
    if protocol == "anthropic":
        content = payload.get("content")
        if isinstance(content, list):
            _walk_anthropic(content, result)
        else:
            result.mark_malformed()
        return result
    if protocol == "responses":
        output = payload.get("output")
        if isinstance(output, list):
            _walk_openai(output, result)
        else:
            result.mark_malformed()
        output_text = payload.get("output_text")
        if isinstance(output_text, str):
            for text in _json_texts(output_text):
                result.add_text(text)
        elif output_text is not None:
            result.mark_malformed()
        return result

    choices = payload.get("choices")
    if not isinstance(choices, list):
        result.mark_malformed()
        return result
    if len(choices) > MAX_ITEMS:
        result.budget_exceeded = True
    for choice in choices[:MAX_ITEMS]:
        if not isinstance(choice, dict):
            result.mark_malformed()
            continue
        message = choice.get("message")
        if isinstance(message, dict):
            _walk_openai(message, result)
            function_call = message.get("function_call")
            if isinstance(function_call, dict):
                _add_json(result, function_call.get("arguments"), required=True)
            tool_calls = message.get("tool_calls")
            if isinstance(tool_calls, list):
                for tool_call in tool_calls[:MAX_ITEMS]:
                    function = tool_call.get("function") if isinstance(tool_call, dict) else None
                    if isinstance(function, dict):
                        _add_json(result, function.get("arguments"), required=True)
        choice_text = choice.get("text")
        if isinstance(choice_text, str):
            result.add_text(choice_text)
    return result


class StreamProtocolExtractor:
    """Stateful extractor for SSE deltas, tool fragments, and snapshots."""

    def __init__(self, protocol: str, *, scan_interval_chars: int = 256) -> None:
        self.protocol = protocol
        self._scan_interval_chars = max(1, scan_interval_chars)
        self._tool_buffers: dict[tuple[str, str, int, int], list[str]] = {}
        self._buffer_sizes: dict[tuple[str, str, int, int], int] = {}
        self._channel_tails: dict[tuple[str, str, int, int], str] = {}
        self._json_states: dict[tuple[str, str, int, int], _JsonFragmentState] = {}
        self._pending_chars: dict[tuple[str, str, int, int], int] = {}
        self._buffer_bytes = 0
        self._scan_work_chars = 0

    @property
    def has_pending(self) -> bool:
        return bool(self._tool_buffers)

    def _key(self, event: dict[str, Any], family: str) -> tuple[str, str, int, int]:
        item_id = event.get("item_id")
        if not isinstance(item_id, str) or len(item_id) > 256:
            item_id = ""
        output_index = event.get("output_index")
        content_index = event.get("content_index")
        summary_index = event.get("summary_index")
        if isinstance(summary_index, int) and not isinstance(summary_index, bool):
            content_index = summary_index
        return (
            family,
            item_id,
            output_index if type(output_index) is int else -1,
            content_index if type(content_index) is int else -1,
        )

    def _append(self, key: tuple[str, str, int, int], delta: str, result: Extraction) -> list[str]:
        if not delta:
            return []
        try:
            delta_bytes = len(delta.encode("utf-8"))
        except UnicodeEncodeError:
            result.mark_malformed()
            return []
        if (
            key not in self._tool_buffers and len(self._tool_buffers) >= MAX_TOOL_CHANNELS
        ) or self._buffer_bytes + delta_bytes > MAX_TOOL_BUFFER_BYTES:
            result.budget_exceeded = True
            return []
        self._tool_buffers.setdefault(key, []).append(delta)
        self._buffer_sizes[key] = self._buffer_sizes.get(key, 0) + delta_bytes
        self._buffer_bytes += delta_bytes
        scan_view = self._channel_tails.get(key, "") + delta
        self._channel_tails[key] = scan_view[-STREAM_CHANNEL_TAIL_CHARS:]
        self._pending_chars[key] = self._pending_chars.get(key, 0) + len(delta)
        json_completed = False
        if key[0] in _JSON_CHANNELS:
            state = self._json_states.setdefault(key, _JsonFragmentState())
            json_completed = state.feed(delta)
            if state.invalid:
                result.mark_malformed()
        if self._pending_chars[key] < self._scan_interval_chars and not json_completed:
            return []
        self._pending_chars[key] = 0
        self._scan_work_chars += len(scan_view)
        if self._scan_work_chars > MAX_STREAM_SCAN_WORK_CHARS:
            result.budget_exceeded = True
            return []
        texts = [scan_view]
        if key[0] in _JSON_CHANNELS:
            if json_completed:
                joined = "".join(self._tool_buffers[key])
                try:
                    json.loads(joined)
                except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
                    result.mark_malformed()
                else:
                    texts.extend(_json_texts(joined))
            if state.invalid:
                result.mark_malformed()
        return texts

    def _flush_key(self, key: tuple[str, str, int, int], result: Extraction) -> None:
        fragments = self._tool_buffers.pop(key, None)
        if fragments is None:
            return
        value = "".join(fragments)
        self._buffer_bytes -= self._buffer_sizes.pop(key, 0)
        self._channel_tails.pop(key, None)
        state = self._json_states.pop(key, None)
        self._pending_chars.pop(key, None)
        if key[0] in _JSON_CHANNELS:
            try:
                decoded = json.loads(value)
            except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
                result.mark_malformed()
            else:
                if (
                    state is None
                    or not state.complete
                    or state.invalid
                    or not isinstance(decoded, (dict, list))
                ):
                    result.mark_malformed()
            texts = _json_texts(value)
        else:
            texts = [value]
        for text in texts:
            result.add_text(text)

    def _discard_key(self, key: tuple[str, str, int, int]) -> None:
        fragments = self._tool_buffers.pop(key, None)
        if fragments is not None:
            self._buffer_bytes -= self._buffer_sizes.pop(key, 0)
        self._channel_tails.pop(key, None)
        self._json_states.pop(key, None)
        self._pending_chars.pop(key, None)

    def flush(self) -> Extraction:
        result = Extraction()
        for key in list(self._tool_buffers):
            self._flush_key(key, result)
        return result

    def consume(self, event: dict[str, Any]) -> Extraction:
        if self.protocol == "anthropic":
            return self._consume_anthropic(event)
        if self.protocol == "responses":
            return self._consume_responses(event)
        return self._consume_chat(event)

    def _consume_chat(self, event: dict[str, Any]) -> Extraction:
        result = Extraction()
        choices = event.get("choices")
        if not isinstance(choices, list):
            result.mark_malformed()
            return result
        if len(choices) > MAX_ITEMS:
            result.budget_exceeded = True
        for choice in choices[:MAX_ITEMS]:
            if not isinstance(choice, dict):
                result.mark_malformed()
                continue
            delta = choice.get("delta")
            if isinstance(delta, dict):
                content = delta.get("content")
                if isinstance(content, str):
                    choice_index = choice.get("index")
                    key = (
                        "text_chat",
                        "",
                        choice_index if type(choice_index) is int else -1,
                        -1,
                    )
                    for view in self._append(key, content, result):
                        result.add_text(view)
                function_call = delta.get("function_call")
                if isinstance(function_call, dict) and isinstance(
                    function_call.get("arguments"), str
                ):
                    choice_index = choice.get("index")
                    key = (
                        "chat_function",
                        "",
                        choice_index if type(choice_index) is int else -1,
                        -1,
                    )
                    for view in self._append(key, function_call["arguments"], result):
                        result.add_text(view)
                tool_calls = delta.get("tool_calls")
                if isinstance(tool_calls, list):
                    for tool in tool_calls[:MAX_ITEMS]:
                        function = tool.get("function") if isinstance(tool, dict) else None
                        arguments = (
                            function.get("arguments") if isinstance(function, dict) else None
                        )
                        if isinstance(arguments, str):
                            tool_index = tool.get("index") if isinstance(tool, dict) else -1
                            choice_index = choice.get("index")
                            key = (
                                "chat_tool",
                                "",
                                choice_index if type(choice_index) is int else -1,
                                tool_index if type(tool_index) is int else -1,
                            )
                            for view in self._append(key, arguments, result):
                                result.add_text(view)
                if choice.get("finish_reason") is not None:
                    result.merge(self.flush())
            choice_text = choice.get("text")
            if isinstance(choice_text, str):
                result.add_text(choice_text)
        return result

    def _consume_anthropic(self, event: dict[str, Any]) -> Extraction:
        result = Extraction()
        event_type = event.get("type")
        if not isinstance(event_type, str):
            result.mark_malformed()
            return result
        if event_type == "content_block_start":
            block = event.get("content_block")
            if isinstance(block, dict):
                _walk_anthropic(block, result)
            else:
                result.mark_malformed()
        elif event_type == "content_block_delta":
            delta = event.get("delta")
            if not isinstance(delta, dict):
                result.mark_malformed()
                return result
            delta_type = delta.get("type")
            if not isinstance(delta_type, str):
                result.mark_malformed()
                return result
            if delta_type == "text_delta" and isinstance(delta.get("text"), str):
                index = event.get("index")
                key = ("text_anthropic", "", index if type(index) is int else -1, -1)
                for view in self._append(key, delta["text"], result):
                    result.add_text(view)
            elif delta_type == "thinking_delta" and isinstance(delta.get("thinking"), str):
                index = event.get("index")
                key = ("text_thinking", "", index if type(index) is int else -1, -1)
                for view in self._append(key, delta["thinking"], result):
                    result.add_text(view)
            elif delta_type == "input_json_delta" and isinstance(delta.get("partial_json"), str):
                index = event.get("index")
                key = ("anthropic_tool", "", index if type(index) is int else -1, -1)
                for view in self._append(key, delta["partial_json"], result):
                    result.add_text(view)
            elif delta_type in {"signature_delta", "citations_delta"}:
                if delta_type == "signature_delta":
                    result.opaque_units += 1
                else:
                    result.reference_units += 1
            else:
                result.mark_unknown()
        elif event_type == "content_block_stop":
            index = event.get("index")
            key = ("anthropic_tool", "", index if type(index) is int else -1, -1)
            self._flush_key(key, result)
            for text_family in ("text_anthropic", "text_thinking"):
                self._discard_key((text_family, "", index if type(index) is int else -1, -1))
        elif event_type == "message_start":
            message = event.get("message")
            if not isinstance(message, dict):
                result.mark_malformed()
            content = message.get("content") if isinstance(message, dict) else None
            if content is not None:
                _walk_anthropic(content, result)
        elif event_type in {"message_delta", "message_stop", "ping", "error"}:
            if event_type in {"message_stop", "error"}:
                result.merge(self.flush())
        else:
            result.mark_unknown()
        return result

    def _consume_responses(self, event: dict[str, Any]) -> Extraction:
        result = Extraction()
        event_type = event.get("type")
        if not isinstance(event_type, str):
            result.mark_malformed()
            return result
        text_deltas = {
            "response.output_text.delta",
            "response.refusal.delta",
            "response.reasoning_summary_text.delta",
            "response.reasoning_text.delta",
        }
        tool_deltas = {
            "response.function_call_arguments.delta": "function_arguments",
            "response.mcp_call_arguments.delta": "mcp_arguments",
            "response.custom_tool_call_input.delta": "custom_input",
            "response.code_interpreter_call_code.delta": "code",
        }
        if event_type in text_deltas:
            delta = event.get("delta")
            if isinstance(delta, str):
                for view in self._append(self._key(event, "text_openai"), delta, result):
                    result.add_text(view)
            else:
                result.mark_malformed()
        elif event_type in tool_deltas:
            delta = event.get("delta")
            if isinstance(delta, str):
                for view in self._append(self._key(event, tool_deltas[event_type]), delta, result):
                    result.add_text(view)
            else:
                result.mark_malformed()
        elif event_type in {
            "response.output_text.done",
            "response.refusal.done",
            "response.function_call_arguments.done",
            "response.mcp_call_arguments.done",
            "response.custom_tool_call_input.done",
            "response.code_interpreter_call_code.done",
            "response.reasoning_summary_text.done",
            "response.reasoning_text.done",
            "response.content_part.done",
            "response.output_item.done",
        }:
            family = None
            if event_type == "response.function_call_arguments.done":
                family = "function_arguments"
            elif event_type == "response.mcp_call_arguments.done":
                family = "mcp_arguments"
            elif event_type == "response.custom_tool_call_input.done":
                family = "custom_input"
            elif event_type == "response.code_interpreter_call_code.done":
                family = "code"
            if family is not None:
                self._flush_key(self._key(event, family), result)
            if event_type in {
                "response.output_text.done",
                "response.refusal.done",
                "response.reasoning_summary_text.done",
                "response.reasoning_text.done",
            }:
                self._discard_key(self._key(event, "text_openai"))
            for field_name in ("text", "refusal", "arguments", "input", "code"):
                field_value = event.get(field_name)
                if isinstance(field_value, str):
                    for text in _json_texts(field_value):
                        result.add_text(text)
            part = event.get("part")
            if isinstance(part, dict):
                _walk_openai(part, result)
            item = event.get("item")
            if isinstance(item, dict):
                _walk_openai(item, result)
        elif event_type in {"response.completed", "response.incomplete", "response.failed"}:
            result.merge(self.flush())
            response = event.get("response")
            if isinstance(response, dict):
                result.merge(extract_response(response, "responses"))
            else:
                result.mark_malformed()
        elif event_type in {
            "response.created",
            "response.queued",
            "response.in_progress",
            "response.output_item.added",
            "response.content_part.added",
            "response.reasoning_summary_part.added",
            "response.reasoning_summary_part.done",
            "response.audio.delta",
            "response.audio.done",
            "response.audio_transcript.delta",
            "response.audio_transcript.done",
            "error",
        }:
            if event_type == "response.output_item.added" and isinstance(event.get("item"), dict):
                _walk_openai(event["item"], result)
            elif (
                event_type == "response.content_part.added" and isinstance(event.get("part"), dict)
            ) or (
                event_type
                in {
                    "response.reasoning_summary_part.added",
                    "response.reasoning_summary_part.done",
                }
                and isinstance(event.get("part"), dict)
            ):
                _walk_openai(event["part"], result)
            elif event_type and event_type.startswith("response.audio"):
                result.media_units += 1
        else:
            result.mark_unknown()
        return result
