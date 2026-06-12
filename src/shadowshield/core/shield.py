"""The public :class:`Shield` — one object, the whole framework.

``Shield`` assembles the configured detectors, responders, rate limiter, audit
sink, and the engine, then exposes a small, ergonomic surface:

- :meth:`scan` — full :class:`ScanResult` (the power-user path).
- :meth:`guard` — return safe text, **raise** on block (fail-closed ergonomics).
- :meth:`filter` — return safe text, **never raise** (fail-soft: fallback on block).
- :meth:`isolate` — spotlight untrusted text for safe passthrough.
- :meth:`session` — a stateful :class:`ShieldedSession` for one conversation.
- :meth:`protect` — a decorator that shields a function's string I/O.

Everything funnels through the single engine, so input and output get identical,
consistent treatment.
"""

from __future__ import annotations

import asyncio
import functools
import json
from collections.abc import Callable
from typing import Any, TypeVar

from ..detectors.alignment import AlignmentJudge
from ..detectors.base import Detector, build_detectors
from ..detectors.llm_check import LLMJudge
from ..responders.base import Responder
from ..responders.blocker import BlockResponder
from ..responders.isolator import IsolationResponder, spotlight
from ..responders.rate_limiter import RateLimitResponder
from ..responders.sanitizer import SanitizeResponder
from ..utils.logging import AuditLog
from .canary import CanaryRegistry, CanaryToken
from .config import Mode, ShieldConfig
from .engine import Engine
from .session import ConversationHistory, ShieldedSession
from .types import Direction, ScanResult, ThreatBlockedError

F = TypeVar("F", bound=Callable[..., Any])


class Shield:
    """The unified ShadowShield entry point."""

    def __init__(
        self,
        config: ShieldConfig | None = None,
        *,
        llm_judge: LLMJudge | None = None,
        alignment_judge: AlignmentJudge | None = None,
        extra_detectors: list[Detector] | None = None,
        extra_responders: list[Responder] | None = None,
        isolate_flagged: bool = False,
        use_transformer: bool | str = False,
    ) -> None:
        self.config = config or ShieldConfig.for_mode(Mode.BALANCED)
        self._audit = AuditLog(self.config.logging)
        self.canaries = CanaryRegistry()

        detectors = build_detectors(
            is_enabled=lambda name: self.config.detector_config(name).enabled
        )
        # Opt-in ML classifier layer. ``use_transformer`` may be True (default
        # model) or a model id string. Kept out of the auto-registered set so it
        # never triggers a surprise model download.
        if use_transformer:
            from ..detectors.transformer import TransformerDetector

            model = use_transformer if isinstance(use_transformer, str) else None
            detectors.append(TransformerDetector(model) if model else TransformerDetector())
        if extra_detectors:
            detectors.extend(extra_detectors)
        self._detectors = detectors

        self._rate_limiter = RateLimitResponder(self.config.rate_limit)

        # Responder order matters: sanitize/isolate transform text; block has the
        # final say and overwrites with a fallback.
        responders: list[Responder] = [SanitizeResponder()]
        if isolate_flagged:
            responders.append(IsolationResponder())
        responders.append(BlockResponder())
        if extra_responders:
            responders.extend(extra_responders)
        self._responders = responders

        self._engine = Engine(
            self.config,
            detectors=self._detectors,
            responders=self._responders,
            rate_limiter=self._rate_limiter,
            audit=self._audit,
            llm_judge=llm_judge,
            alignment_judge=alignment_judge,
        )

    # ------------------------------------------------------------------ #
    # Builders
    # ------------------------------------------------------------------ #
    @classmethod
    def for_mode(cls, mode: Mode | str = Mode.BALANCED, **kwargs: Any) -> Shield:
        return cls(ShieldConfig.for_mode(mode), **kwargs)

    @classmethod
    def from_yaml(cls, path: str, **kwargs: Any) -> Shield:
        return cls(ShieldConfig.from_yaml(path), **kwargs)

    @property
    def detectors(self) -> list[Detector]:
        return list(self._detectors)

    # ------------------------------------------------------------------ #
    # Core scanning
    # ------------------------------------------------------------------ #
    def scan(
        self,
        text: str,
        *,
        direction: Direction | str = Direction.INPUT,
        identity: str | None = None,
        history: ConversationHistory | None = None,
        objective: str | None = None,
    ) -> ScanResult:
        """Scan ``text`` and return the full :class:`ScanResult`.

        Raises :class:`ThreatBlockedError` only when ``config.raise_on_block`` is
        set *and* the result is blocked; otherwise always returns a result.

        Pass ``objective`` (the user's stated goal) on output scans to enable the
        agent-trace alignment audit (requires ``Shield(alignment_judge=...)``).
        """
        result = self._engine.evaluate(
            text,
            direction=Direction(direction),
            identity=identity,
            history=history,
            canaries=self.canaries.active(),
            objective=objective,
        )
        if self.config.raise_on_block and result.blocked:
            raise ThreatBlockedError(result)
        return result

    def scan_input(self, text: str, **kwargs: Any) -> ScanResult:
        return self.scan(text, direction=Direction.INPUT, **kwargs)

    def scan_output(self, text: str, **kwargs: Any) -> ScanResult:
        return self.scan(text, direction=Direction.OUTPUT, **kwargs)

    # ------------------------------------------------------------------ #
    # Ergonomic wrappers
    # ------------------------------------------------------------------ #
    def guard(
        self,
        text: str,
        *,
        direction: Direction | str = Direction.INPUT,
        identity: str | None = None,
        history: ConversationHistory | None = None,
        objective: str | None = None,
    ) -> str:
        """Return safe text, **raising** :class:`ThreatBlockedError` on a block.

        Fail-closed ergonomics: the dangerous path is the exceptional path. Use
        this when you'd rather abort than risk passing tainted content.
        """
        result = self._engine.evaluate(
            text,
            direction=Direction(direction),
            identity=identity,
            history=history,
            canaries=self.canaries.active(),
            objective=objective,
        )
        if result.blocked:
            raise ThreatBlockedError(result)
        return result.safe_text

    def filter(
        self,
        text: str,
        *,
        direction: Direction | str = Direction.INPUT,
        identity: str | None = None,
        history: ConversationHistory | None = None,
        objective: str | None = None,
    ) -> str:
        """Return safe text, **never raising**.

        Fail-soft ergonomics: a blocked payload yields the safe fallback string
        instead of an exception. Use this on paths that must always return text.
        """
        result = self._engine.evaluate(
            text,
            direction=Direction(direction),
            identity=identity,
            history=history,
            canaries=self.canaries.active(),
            objective=objective,
        )
        return result.safe_text

    def isolate(self, text: str, *, datamark: bool = False) -> str:
        """Spotlight untrusted ``text`` so it's safer to feed to a model."""
        return spotlight(text, datamark=datamark)

    # ------------------------------------------------------------------ #
    # Canary tokens (detect *successful* injections)
    # ------------------------------------------------------------------ #
    def issue_canary(self, *, prefix: str = "ss-canary", note: str = "") -> CanaryToken:
        """Mint a canary token to embed in a system prompt / hidden context.

        Embed ``token.instruction()`` in your prompt; if the token later appears
        in model output (or a guarded tool call), :class:`CanaryLeakDetector`
        flags a confirmed exfiltration. See :mod:`shadowshield.core.canary`.
        """
        return self.canaries.issue(prefix=prefix, note=note)

    # ------------------------------------------------------------------ #
    # Agentic guarding: tool calls & tool results are untrusted too
    # ------------------------------------------------------------------ #
    def scan_tool_call(
        self, name: str, arguments: Any, *, identity: str | None = None
    ) -> ScanResult:
        """Scan an outbound tool/function call (name + arguments) as input.

        Agentic injections often surface as a *tool call* the model was tricked
        into making. Serialise the call and scan it so a poisoned argument or a
        leaked canary in a tool payload is caught before the tool runs.
        """
        payload = self._stringify_tool(name, arguments)
        return self.scan(payload, direction=Direction.INPUT, identity=identity)

    def scan_tool_result(
        self, name: str, result: Any, *, identity: str | None = None
    ) -> ScanResult:
        """Scan a tool/function *result* (untrusted external content) as input.

        Tool results — web pages, file contents, API responses — are a primary
        indirect-injection vector. Treat them as untrusted input.
        """
        payload = self._stringify_tool(name, result)
        return self.scan(payload, direction=Direction.INPUT, identity=identity)

    @staticmethod
    def _stringify_tool(name: str, data: Any) -> str:
        if isinstance(data, str):
            body = data
        else:
            try:
                body = json.dumps(data, ensure_ascii=False, default=str)
            except (TypeError, ValueError):
                body = str(data)
        return f"{name}: {body}"

    # ------------------------------------------------------------------ #
    # Async API (non-blocking for event-loop apps: FastAPI, async agents)
    # ------------------------------------------------------------------ #
    async def ascan(self, text: str, **kwargs: Any) -> ScanResult:
        """Async :meth:`scan` — runs the CPU-bound scan off the event loop."""
        return await asyncio.to_thread(self.scan, text, **kwargs)

    async def aguard(self, text: str, **kwargs: Any) -> str:
        """Async :meth:`guard`."""
        return await asyncio.to_thread(self.guard, text, **kwargs)

    async def afilter(self, text: str, **kwargs: Any) -> str:
        """Async :meth:`filter`."""
        return await asyncio.to_thread(self.filter, text, **kwargs)

    # ------------------------------------------------------------------ #
    # Sessions & decorators
    # ------------------------------------------------------------------ #
    def session(
        self,
        *,
        identity: str | None = None,
        history_size: int = 50,
        objective: str | None = None,
    ) -> ShieldedSession:
        return ShieldedSession(
            self, identity=identity, history_size=history_size, objective=objective
        )

    def protect(
        self,
        func: F | None = None,
        *,
        input_arg: str | int | None = 0,
        check_output: bool = True,
        identity: str | None = None,
    ) -> Any:
        """Decorator that shields a function's string input and output.

        By default the first positional argument is treated as untrusted input
        and scanned (raising on block); if the return value is a string it is
        scanned as output. Point ``input_arg`` at a keyword name or another
        positional index to shield a different argument.

        Usage::

            @shield.protect
            def ask(prompt: str) -> str: ...

            @shield.protect(input_arg="question", check_output=False)
            def ask2(*, question: str) -> str: ...
        """

        def decorate(fn: F) -> F:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                value = self._extract_arg(args, kwargs, input_arg)
                if isinstance(value, str):
                    self.guard(value, direction=Direction.INPUT, identity=identity)
                out = fn(*args, **kwargs)
                if check_output and isinstance(out, str):
                    return self.guard(out, direction=Direction.OUTPUT, identity=identity)
                return out

            return wrapper  # type: ignore[return-value]

        return decorate if func is None else decorate(func)

    @staticmethod
    def _extract_arg(
        args: tuple[Any, ...], kwargs: dict[str, Any], selector: str | int | None
    ) -> Any:
        if selector is None:
            return None
        if isinstance(selector, int):
            return args[selector] if len(args) > selector else None
        return kwargs.get(selector)
