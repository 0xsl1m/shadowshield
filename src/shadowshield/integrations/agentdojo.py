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

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from ..core.shield import Shield
from ..core.types import Direction


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
        parts = [
            p if isinstance(p, str) else str(p.get("text", ""))
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
) -> ShadowShieldVerdict:
    """Scan a chat-message stream; return a verdict on the worst finding.

    By default only *tool* messages are scanned (the indirect-injection channel);
    set ``tool_outputs_only=False`` to scan every message. Usable standalone — no
    AgentDojo required — which is what the unit tests exercise.
    """
    for i, msg in enumerate(messages):
        if tool_outputs_only and _message_role(msg) not in _TOOL_ROLES:
            continue
        text = _message_text(msg)
        if not text:
            continue
        result = shield.scan(text, direction=Direction.INPUT)
        if not result.is_safe:
            top = result.top_threat()
            return ShadowShieldVerdict(
                is_attack=True,
                detail=top.message if top else "injection detected in tool output",
                index=i,
            )
    return ShadowShieldVerdict(is_attack=False)


def make_agentdojo_defense(shield: Shield) -> Any:
    """Build an AgentDojo ``PipelineElement`` backed by ``shield`` (lazy import).

    The element scans tool outputs in the message history and raises AgentDojo's
    ``AbortAgentError`` when an injection is found, which AgentDojo scores as the
    attack being *prevented* (no utility loss on clean trajectories).
    """
    try:
        from agentdojo.agent_pipeline import PipelineElement
        from agentdojo.agent_pipeline.errors import AbortAgentError
    except ImportError as exc:  # pragma: no cover - optional heavy dependency
        raise ImportError(
            "make_agentdojo_defense requires AgentDojo: pip install agentdojo"
        ) from exc

    class ShadowShieldDefense(PipelineElement):  # type: ignore[misc]
        """Aborts the agent trajectory on injection found in tool output."""

        def __init__(self, guard: Shield) -> None:
            self._guard = guard

        def query(
            self,
            query: str,
            runtime: Any,
            env: Any = None,
            messages: Sequence[Any] = (),
            extra_args: dict[str, Any] | None = None,
        ) -> tuple[str, Any, Any, Sequence[Any], dict[str, Any]]:
            verdict = scan_messages_for_injection(self._guard, messages)
            if verdict.is_attack:
                raise AbortAgentError(
                    f"ShadowShield blocked a prompt injection in tool output: {verdict.detail}",
                    list(messages),
                    env,
                )
            return query, runtime, env, messages, (extra_args or {})

    return ShadowShieldDefense(shield)
