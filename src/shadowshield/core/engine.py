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

import json
import math
import threading
import time
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
from ..detectors.base import MAX_FINDINGS_PER_DETECTOR, Detector, ScanContext
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
_MAX_FINDINGS_PER_SCAN = 50
_MAX_THREAT_MESSAGE_CHARS = 1_024
_MAX_THREAT_MATCH_CHARS = 256
_MAX_THREAT_METADATA_BYTES = 4_096
_JUDGE_WORKERS = 4


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
        # User-supplied judges may hang or make network calls. Each admitted call
        # runs in a bounded daemon thread: request time is limited, queue growth is
        # impossible, and a permanently hung client cannot prevent process exit.
        # A timed-out call retains its slot until the callable really finishes.
        self._judge_slots: threading.BoundedSemaphore | None = (
            threading.BoundedSemaphore(_JUDGE_WORKERS)
            if (llm_judge is not None or alignment_judge is not None)
            else None
        )
        # Detector weights are read from config once.
        self._weights = {
            name: config.detector_config(name).weight for name in self._detector_names()
        }
        # Result observers (e.g. the telemetry reporter). Invoked after every evaluate,
        # so guard()/filter()/scan()/async all report through a single chokepoint.
        self._observers: list[Callable[[ScanResult, float, str | None], None]] = []

    def add_observer(self, callback: Callable[[ScanResult, float, str | None], None]) -> None:
        """Register a ``(result, latency_ms, identity)`` callback run after each scan."""
        self._observers.append(callback)

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
        start = time.perf_counter()
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

        threats = self._cap_findings(threats, context)

        score = aggregate_score(threats, self._weights)
        severity = aggregate_severity(threats, score)
        decision = self._decide(score, severity)
        # No unscanned suffix may ever flow downstream. The result preserves the
        # original for caller inspection, but oversized payloads always receive
        # the blocker's safe fallback in every mode and policy configuration.
        if oversized:
            decision = _stronger(decision, Decision.BLOCK)

        result = ScanResult(
            text=text,
            direction=direction,
            threats=threats,
            score=score,
            severity=severity,
            decision=decision,
        )
        truncated_findings = int(context.metadata.get("findings_truncated", 0))
        if truncated_findings:
            result.metadata["findings_truncated"] = truncated_findings
            result.metadata["findings_total"] = len(threats) + truncated_findings

        # Rate-limit pre-pass can escalate to BLOCK based on identity history.
        result = self._rate_limiter.check(result, context=context)
        result.threats = self._cap_findings(
            result.threats,
            context,
            preserve_detector=self._rate_limiter.name,
        )
        result.score = aggregate_score(result.threats, self._weights)
        result.severity = aggregate_severity(result.threats, result.score)
        if result.metadata.get("rate_limited"):
            result.severity = max(result.severity, Severity.HIGH)
        truncated_findings = int(context.metadata.get("findings_truncated", 0))
        if truncated_findings:
            result.metadata["findings_truncated"] = truncated_findings
            result.metadata["findings_total"] = len(result.threats) + truncated_findings

        result = self._apply_responders(result, context)
        self._record(result, context)
        self._notify_observers(result, (time.perf_counter() - start) * 1000.0, identity)
        return result

    def _notify_observers(
        self, result: ScanResult, latency_ms: float, identity: str | None
    ) -> None:
        for cb in self._observers:
            try:
                cb(result, latency_ms, identity)
            except Exception:  # an observer must never break the request path
                continue

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

        The judge runs in a daemon thread; if it overruns, ``TimeoutError`` is
        raised, which the calling detector's fail-safe ``except`` turns
        into a low-severity "unavailable" note rather than a crash or a hang.
        At most four judge calls may be outstanding. A timed-out running call
        retains its admission slot until it really finishes, so later scans fail
        fast instead of accumulating behind hung workers.
        """

        def wrapped(*args: Any) -> Any:
            slots = self._judge_slots
            assert slots is not None
            if not slots.acquire(blocking=False):
                raise RuntimeError("judge capacity exhausted")
            done = threading.Event()
            outcome: dict[str, Any] = {}

            def invoke() -> None:
                try:
                    outcome["value"] = fn(*args)
                except BaseException as exc:
                    outcome["error"] = exc
                finally:
                    slots.release()
                    done.set()

            worker = threading.Thread(target=invoke, name="ss-judge", daemon=True)
            try:
                worker.start()
            except Exception:
                slots.release()
                raise
            if not done.wait(timeout):
                raise TimeoutError
            if "error" in outcome:
                error = outcome["error"]
                if isinstance(error, Exception):
                    raise error
                raise RuntimeError(f"judge terminated with {type(error).__name__}")
            if "value" not in outcome:
                raise RuntimeError("judge exited without a result")
            return outcome["value"]

        return wrapped

    @staticmethod
    def _safe_scan(det: Detector, text: str, context: ScanContext) -> list[Threat]:
        """A detector that raises must never take down the request path."""
        try:
            findings = [
                Engine._bound_threat(threat, text_length=len(text))
                for threat in det.scan(text, context=context)
            ]
            if len(findings) <= MAX_FINDINGS_PER_DETECTOR:
                return findings
            context.metadata["findings_truncated"] = (
                int(context.metadata.get("findings_truncated", 0))
                + len(findings)
                - MAX_FINDINGS_PER_DETECTOR
            )
            return sorted(
                findings,
                key=lambda threat: (threat.severity, threat.score),
                reverse=True,
            )[:MAX_FINDINGS_PER_DETECTOR]
        except Exception:  # pragma: no cover - defensive
            # Fail-safe: drop this detector's contribution, keep the others.
            return []

    @staticmethod
    def _bound_threat(threat: Threat, *, text_length: int) -> Threat:
        """Bound plugin/judge-controlled fields before they reach results or logs."""
        if not isinstance(threat, Threat):
            raise TypeError("detectors must return Threat instances")
        if not isinstance(threat.category, ThreatCategory):
            raise TypeError("threat category must be a ThreatCategory")
        if not isinstance(threat.severity, Severity):
            raise TypeError("threat severity must be a Severity")
        try:
            score = float(threat.score)
        except (TypeError, ValueError, OverflowError) as exc:
            raise TypeError("threat score must be a finite number") from exc
        if not math.isfinite(score):
            raise TypeError("threat score must be a finite number")
        threat.score = max(0.0, min(1.0, score))
        threat.detector = truncate(str(threat.detector), 128)
        threat.message = truncate(str(threat.message), _MAX_THREAT_MESSAGE_CHARS)
        if threat.matched is not None:
            threat.matched = truncate(str(threat.matched), _MAX_THREAT_MATCH_CHARS)
        if (
            not isinstance(threat.span, tuple)
            or len(threat.span) != 2
            or not all(
                isinstance(value, int) and not isinstance(value, bool) for value in threat.span
            )
            or not (0 <= threat.span[0] <= threat.span[1] <= text_length)
        ):
            threat.span = None
        try:
            metadata_json = json.dumps(
                threat.metadata,
                default=lambda value: f"<{type(value).__name__}>",
                ensure_ascii=False,
            )
            canonical_metadata = json.loads(metadata_json)
            if not isinstance(canonical_metadata, dict):
                raise TypeError("threat metadata must serialize to an object")
            metadata_size = len(metadata_json.encode("utf-8"))
        except Exception:
            threat.metadata = {"metadata_dropped": True}
        else:
            if metadata_size > _MAX_THREAT_METADATA_BYTES:
                threat.metadata = {
                    "metadata_truncated": True,
                    "original_bytes": metadata_size,
                }
            else:
                threat.metadata = canonical_metadata
        return threat

    @staticmethod
    def _cap_findings(
        threats: list[Threat],
        context: ScanContext,
        *,
        preserve_detector: str | None = None,
    ) -> list[Threat]:
        if len(threats) <= _MAX_FINDINGS_PER_SCAN:
            return threats
        context.metadata["findings_truncated"] = (
            int(context.metadata.get("findings_truncated", 0))
            + len(threats)
            - _MAX_FINDINGS_PER_SCAN
        )
        ordered = sorted(
            threats,
            key=lambda threat: (threat.severity, threat.score),
            reverse=True,
        )
        if preserve_detector is None:
            return ordered[:_MAX_FINDINGS_PER_SCAN]
        preserved = next(
            (threat for threat in ordered if threat.detector == preserve_detector),
            None,
        )
        if preserved is None:
            return ordered[:_MAX_FINDINGS_PER_SCAN]
        remainder = [threat for threat in ordered if threat is not preserved]
        return [preserved, *remainder[: _MAX_FINDINGS_PER_SCAN - 1]]

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
        if self._audit.redact:
            # Redaction is an allowlist, not a best-effort scrub. Detector messages,
            # matches, metadata, identities, and previews may all contain attacker-
            # controlled text, secrets, PII, judge output, or decoded payloads.
            event: dict[str, Any] = {
                "direction": result.direction.value,
                "decision": result.decision.value,
                "score": round(result.score, 4),
                "severity": result.severity.label,
                "is_safe": result.is_safe,
                "blocked": result.blocked,
                "sanitized": result.sanitized_text is not None,
                "payload_length": len(result.text),
                "identity_present": context.identity is not None,
                "findings_total": result.metadata.get("findings_total", len(result.threats)),
                "findings_truncated": result.metadata.get("findings_truncated", 0),
                "threats": [
                    {
                        "category": threat.category.value,
                        "severity": threat.severity.label,
                        "score": round(threat.score, 4),
                        "detector": threat.detector,
                        "span": list(threat.span) if threat.span else None,
                    }
                    for threat in result.threats
                ],
            }
        else:
            event = result.to_dict()
            event["identity"] = context.identity
            event["text"] = truncate(result.text, 400)
        # Clean, threat-free scans are logged at DEBUG (quiet by default);
        # anything noteworthy is logged at INFO.
        notable = bool(result.threats) or not result.is_safe
        self._audit.record(event, notable=notable)
