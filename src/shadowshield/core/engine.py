"""The unified detection→decision→response engine.

This is the heart of ShadowShield and the thing that makes it *one* system rather
than a detector bag bolted to a responder bag. One pass:

1. Build a shared :class:`ScanContext` (normalise + decode once).
2. Run the cheap, deterministic detectors.
3. Conditionally consult the optional LLM self-check (only when the cheap tiers
   already crossed ``min_score_to_invoke`` — never on clean traffic).
4. Aggregate weighted findings into one score + severity (noisy-or).
5. Let the policy + block-threshold + rate limiter decide.
6. Apply the matching responders (sanitize / block / isolate).
7. Audit.

The flow is identical for input and output, which is what gives ShadowShield its
symmetric, two-way protection.
"""

from __future__ import annotations

import concurrent.futures
from collections.abc import Callable
from typing import Any

from ..core.config import ShieldConfig
from ..core.types import (
    Decision,
    Direction,
    ScanResult,
    Severity,
    Threat,
    ThreatCategory,
)
from ..detectors.alignment import AlignmentCheckDetector, AlignmentJudge
from ..detectors.base import Detector, ScanContext
from ..detectors.llm_check import LLMJudge, LLMSelfCheckDetector
from ..responders.base import Responder
from ..responders.rate_limiter import RateLimitResponder
from ..utils.logging import AuditLog
from ..utils.scoring import aggregate_score, aggregate_severity
from ..utils.text import truncate
from .session import ConversationHistory

# Total order over decisions for "take the stronger of two" comparisons.
_DECISION_RANK: dict[Decision, int] = {
    Decision.ALLOW: 0,
    Decision.FLAG: 1,
    Decision.SANITIZE: 2,
    Decision.BLOCK: 3,
    Decision.ESCALATE: 4,
}

_LLM_DETECTOR_NAME = LLMSelfCheckDetector.name
_ALIGNMENT_DETECTOR_NAME = AlignmentCheckDetector.name
# Detectors that the engine drives separately (gated / context-injected), not in
# the cheap deterministic loop.
_GATED_DETECTORS = frozenset({_LLM_DETECTOR_NAME, _ALIGNMENT_DETECTOR_NAME})


def _stronger(a: Decision, b: Decision) -> Decision:
    return a if _DECISION_RANK[a] >= _DECISION_RANK[b] else b


class Engine:
    """Stateless-per-call orchestrator wired with detectors and responders."""

    def __init__(
        self,
        config: ShieldConfig,
        *,
        detectors: list[Detector],
        responders: list[Responder],
        rate_limiter: RateLimitResponder,
        audit: AuditLog,
        llm_judge: LLMJudge | None = None,
        alignment_judge: AlignmentJudge | None = None,
    ) -> None:
        self._config = config
        self._detectors = detectors
        self._responders = responders
        self._rate_limiter = rate_limiter
        self._audit = audit
        self._llm_judge = llm_judge
        self._alignment_judge = alignment_judge
        # Judges are user-supplied callables that may hang or make network calls.
        # Run them in a small pool so we can enforce a hard timeout — a hung judge
        # must never block the request path. Only created when a judge exists.
        self._judge_pool: concurrent.futures.ThreadPoolExecutor | None = (
            concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="ss-judge")
            if (llm_judge is not None or alignment_judge is not None)
            else None
        )
        # Detector weights are read from config once.
        self._weights = {
            name: config.detector_config(name).weight for name in self._detector_names()
        }

    def _detector_names(self) -> list[str]:
        return [d.name for d in self._detectors]

    # ------------------------------------------------------------------ #
    def evaluate(
        self,
        text: str,
        *,
        direction: Direction,
        identity: str | None = None,
        history: ConversationHistory | None = None,
        canaries: tuple[str, ...] = (),
        objective: str | None = None,
    ) -> ScanResult:
        # Bound the work: oversized payloads are scanned as a truncated prefix so
        # a multi-megabyte input can't exhaust CPU. The original text is preserved
        # on the result; only the scanned region is capped.
        max_chars = self._config.max_input_chars
        oversized = bool(max_chars) and len(text) > max_chars
        scan_text = text[:max_chars] if oversized else text

        context = ScanContext.build(
            scan_text,
            direction=direction,
            history=history,
            identity=identity,
            canaries=canaries,
            objective=objective,
        )

        threats = self._run_cheap_detectors(scan_text, context)
        interim_score = aggregate_score(threats, self._weights)
        threats += self._maybe_run_llm_check(scan_text, context, interim_score)
        threats += self._maybe_run_alignment(scan_text, context)
        if oversized:
            threats.append(
                Threat(
                    category=ThreatCategory.ANOMALY,
                    severity=Severity.MEDIUM,
                    score=0.5,
                    detector="input_size_guard",
                    message=(
                        f"Input exceeds max_input_chars ({max_chars}); scanned a "
                        f"truncated prefix of a {len(text)}-char payload."
                    ),
                    metadata={"original_length": len(text), "scanned_length": max_chars},
                )
            )

        score = aggregate_score(threats, self._weights)
        severity = aggregate_severity(threats, score)
        decision = self._decide(score, severity)

        result = ScanResult(
            text=text,
            direction=direction,
            threats=threats,
            score=score,
            severity=severity,
            decision=decision,
        )

        # Rate-limit pre-pass can escalate to BLOCK based on identity history.
        result = self._rate_limiter.check(result, context=context)

        result = self._apply_responders(result, context)
        self._record(result, context)
        return result

    # ------------------------------------------------------------------ #
    def _run_cheap_detectors(self, text: str, context: ScanContext) -> list[Threat]:
        threats: list[Threat] = []
        for det in self._detectors:
            if det.name in _GATED_DETECTORS:
                continue  # handled separately (gated / context-injected)
            if not det.applies_to(context.direction):
                continue
            context.options = self._config.detector_config(det.name).options
            threats.extend(self._safe_scan(det, text, context))
        return threats

    def _maybe_run_llm_check(
        self, text: str, context: ScanContext, interim_score: float
    ) -> list[Threat]:
        cfg = self._config.llm_check
        if not cfg.enabled or self._llm_judge is None:
            return []
        if interim_score < cfg.min_score_to_invoke:
            return []
        det = next((d for d in self._detectors if d.name == _LLM_DETECTOR_NAME), None)
        if det is None or not det.applies_to(context.direction):
            return []
        context.options = {"judge": self._with_timeout(self._llm_judge, cfg.timeout_seconds)}
        return self._safe_scan(det, text, context)

    def _maybe_run_alignment(self, text: str, context: ScanContext) -> list[Threat]:
        # Only runs on the output side, when an objective is set and a judge is
        # wired in. This is the agent-trace alignment audit (goal-hijack detection).
        if self._alignment_judge is None or not context.objective:
            return []
        det = next((d for d in self._detectors if d.name == _ALIGNMENT_DETECTOR_NAME), None)
        if det is None or not det.applies_to(context.direction):
            return []
        timeout = self._config.llm_check.timeout_seconds
        context.options = {"alignment_judge": self._with_timeout(self._alignment_judge, timeout)}
        return self._safe_scan(det, text, context)

    def _with_timeout(self, fn: Callable[..., Any], timeout: float) -> Callable[..., Any]:
        """Wrap a user judge so a hang can't block the request beyond ``timeout``.

        The judge runs in the pool; if it overruns, ``future.result`` raises
        ``TimeoutError``, which the calling detector's fail-safe ``except`` turns
        into a low-severity "unavailable" note rather than a crash or a hang.
        (An over-running judge thread is left to finish/leak — the standard,
        accepted trade-off for thread-based timeouts in Python.)
        """

        def wrapped(*args: Any) -> Any:
            assert self._judge_pool is not None  # only built when a judge exists
            future = self._judge_pool.submit(fn, *args)
            return future.result(timeout=timeout)

        return wrapped

    @staticmethod
    def _safe_scan(det: Detector, text: str, context: ScanContext) -> list[Threat]:
        """A detector that raises must never take down the request path."""
        try:
            return det.scan(text, context=context)
        except Exception:  # pragma: no cover - defensive
            # Fail-safe: drop this detector's contribution, keep the others.
            return []

    def _decide(self, score: float, severity: Severity) -> Decision:
        decision = self._config.policy.decide(severity)
        # Independent floor: a high aggregate score forces at least a block even
        # if the per-band policy was lenient.
        if score >= self._config.block_threshold:
            decision = _stronger(decision, Decision.BLOCK)
        return decision

    def _apply_responders(self, result: ScanResult, context: ScanContext) -> ScanResult:
        for responder in self._responders:
            if responder.applies(result):
                result = responder.apply(result, context=context)
        return result

    def _record(self, result: ScanResult, context: ScanContext) -> None:
        event = result.to_dict()
        event["identity"] = context.identity
        if not self._audit.redact:
            event["text"] = truncate(result.text, 400)
        else:
            event["text_preview"] = truncate(result.text, 80)
        # Clean, threat-free scans are logged at DEBUG (quiet by default);
        # anything noteworthy is logged at INFO.
        notable = bool(result.threats) or not result.is_safe
        self._audit.record(event, notable=notable)
