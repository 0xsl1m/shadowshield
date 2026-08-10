"""AgentDojo defense adapter.

`AgentDojo <https://github.com/ethz-spylab/agentdojo>`_ (NeurIPS 2024) is the
gold-standard benchmark for agent injection because it measures **security AND
utility jointly** — a defense that blocks everything scores zero utility, so the
number is honest.

This adapter exposes ShadowShield as an AgentDojo *defense* that inspects tool
outputs (the primary indirect-injection vector) before the model acts on them and
aborts the trajectory when an injection is detected. AgentDojo is a heavy,
API-key-requiring dependency, so it is imported lazily — installing ShadowShield
never pulls it.

Running the benchmark (needs ``pip install agentdojo`` and an LLM API key)::

    import agentdojo
    from agentdojo.agent_pipeline import AgentPipeline
    from shadowshield import Shield
    from shadowshield.integrations import make_agentdojo_defense

    pipeline = AgentPipeline.from_config(...)              # your model pipeline
    pipeline.append(make_agentdojo_defense(Shield.for_mode("strict")))
    # then run agentdojo's benchmark over the suites and report ASR + utility.

See ``docs/BENCHMARKS.md`` for how we report the result.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ..core.shield import Shield
from ..core.types import Direction

# Bound on the content-hash cache used to skip already-scanned tool outputs.
_SEEN_MAX = 10_000


@dataclass(slots=True)
class ShadowShieldVerdict:
    """Result of scanning a message stream for injection."""

    is_attack: bool
    detail: str = ""
    index: int | None = None  # which message tripped it


# Roles whose content is untrusted tool/data output in chat-message form.
_TOOL_ROLES = {"tool", "function", "tool_result"}


def _message_role(message: Any) -> str:
    if isinstance(message, dict):
        return str(message.get("role", ""))
    return str(getattr(message, "role", ""))


def _message_text(message: Any) -> str:
    content = (
        message.get("content") if isinstance(message, dict) else getattr(message, "content", None)
    )
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        # Content blocks vary by framework: OpenAI-style uses {"text": ...},
        # AgentDojo serializes blocks as {"type": "text", "content": ...}.
        parts = [
            p if isinstance(p, str) else str(p.get("text", p.get("content", "")))
            for p in content
            if isinstance(p, (str, dict))
        ]
        return "\n".join(parts)
    return str(content)


def scan_messages_for_injection(
    shield: Shield,
    messages: Sequence[Any],
    *,
    tool_outputs_only: bool = True,
    _seen: set[str] | None = None,
) -> ShadowShieldVerdict:
    """Scan a chat-message stream; return a verdict on the worst finding.

    By default only *tool* messages are scanned (the indirect-injection channel);
    set ``tool_outputs_only=False`` to scan every message. Usable standalone — no
    AgentDojo required — which is what the unit tests exercise.

    ``_seen`` is an optional content-hash cache: texts already scanned clean in
    this process are skipped. Agent loops re-present the full history every
    iteration, so without the cache scanning is quadratic in trajectory length.

    A message is treated as an attack only when the scan decision is **block**
    (fail-closed). Sanitize-level findings (e.g. low-severity PII in a benign
    document) must not interrupt a clean trajectory.
    """
    for i, msg in enumerate(messages):
        if tool_outputs_only and _message_role(msg) not in _TOOL_ROLES:
            continue
        text = _message_text(msg)
        if not text:
            continue
        if _seen is not None:
            digest = hashlib.sha256(text.encode()).hexdigest()
            if digest in _seen:
                continue
        result = shield.scan(text, direction=Direction.INPUT)
        if result.blocked:
            top = result.top_threat()
            return ShadowShieldVerdict(
                is_attack=True,
                detail=top.message if top else "injection detected in tool output",
                index=i,
            )
        if _seen is not None:
            if len(_seen) >= _SEEN_MAX:
                _seen.clear()
            _seen.add(digest)
    return ShadowShieldVerdict(is_attack=False)


def make_agentdojo_defense(shield: Shield) -> Any:
    """Build an AgentDojo ``PipelineElement`` backed by ``shield`` (lazy import).

    The element scans tool outputs in the message history and raises AgentDojo's
    ``AbortAgentError`` when an injection is found, which AgentDojo scores as the
    attack being *prevented* (no utility loss on clean trajectories).
    """
    try:
        # AgentDojo >= 0.1.33 renamed PipelineElement to BasePipelineElement.
        try:
            from agentdojo.agent_pipeline import BasePipelineElement as _Element
        except ImportError:
            from agentdojo.agent_pipeline import PipelineElement as _Element
        from agentdojo.agent_pipeline.errors import AbortAgentError
    except ImportError as exc:  # pragma: no cover - optional heavy dependency
        raise ImportError(
            "make_agentdojo_defense requires AgentDojo: pip install agentdojo"
        ) from exc

    class ShadowShieldDefense(_Element):  # type: ignore[misc]
        """Aborts the agent trajectory on injection found in tool output."""

        def __init__(self, guard: Shield) -> None:
            self._guard = guard
            self._seen: set[str] = set()

        def query(
            self,
            query: str,
            runtime: Any,
            env: Any = None,
            messages: Sequence[Any] = (),
            extra_args: dict[str, Any] | None = None,
        ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
            verdict = scan_messages_for_injection(self._guard, messages, _seen=self._seen)
            if verdict.is_attack:
                raise AbortAgentError(
                    f"ShadowShield blocked a prompt injection in tool output: {verdict.detail}",
                    list(messages),
                    env,
                )
            return query, runtime, env, messages, (extra_args or {})

    return ShadowShieldDefense(shield)
