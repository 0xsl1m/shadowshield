"""Optional transformer-classifier detector (the ML layer the best guards have).

The deterministic detectors are fast and explainable but blind to novel phrasings
that don't match a signature. A fine-tuned prompt-injection classifier closes that
gap — it's the layer LLM Guard, Rebuff, and Meta Prompt-Guard are built around.

This detector is **opt-in** (it pulls a model, which is heavy) and **not
auto-registered** — add it explicitly::

    from shadowshield.detectors import TransformerDetector
    shield = Shield.for_mode("strict", extra_detectors=[TransformerDetector()])

or the shorthand ``Shield.for_mode("strict", use_transformer=True)``.

Requires the ``transformers`` extra: ``pip install shadowshield[transformers]``.
The model id is configurable so you can swap in Meta's Prompt-Guard, a distilled
model, or your own fine-tune without touching code.
"""

from __future__ import annotations

import copy
import re
import threading
from collections.abc import Iterable
from typing import Any

from ..core.types import Direction, Severity, Threat, ThreatCategory
from .base import Detector, ScanContext

# Well-known, permissively-licensed prompt-injection classifier. Override via the
# ``model`` argument (e.g. "meta-llama/Llama-Prompt-Guard-2-86M").
DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"

# Label strings different models use for the "this is an attack" class.
_ATTACK_LABELS = {"INJECTION", "JAILBREAK", "LABEL_1", "1", "UNSAFE", "MALICIOUS"}

# Character budget per segment for ``segment_spans`` mode. 1,200 chars stays
# comfortably inside 512 tokens even for dense English/code, so no segment is
# silently truncated by the tokenizer.
_SEGMENT_MAX_CHARS = 1200

# Target segment size. Small enough that an attacking sentence cluster
# localizes away from surrounding legitimate data (which is what lets the
# sanitizer preserve the data); large enough to give the classifier context.
# Fragments shorter than this are merged into the previous segment so the
# classifier never sees context-free scraps like "Signed,".
_SEGMENT_MIN_CHARS = 25

_PIECE_SPLIT_RE = re.compile(r"\n\s*\n|\n|(?<=[.!?])\s+")


def _segments(
    text: str,
    max_chars: int = _SEGMENT_MAX_CHARS,
    min_chars: int = _SEGMENT_MIN_CHARS,
) -> Iterable[tuple[int, int, str]]:
    """Yield ``(start, end, segment)`` covering the non-whitespace content.

    Splits into sentence/line pieces — fine enough that an attack localizes
    to its own sentences instead of dragging the whole document with it —
    merging sub-``min_chars`` fragments into the previous piece, and
    hard-windowing pieces longer than ``max_chars`` so every segment fits
    the classifier's token budget. Offsets index into ``text``.
    """
    raw: list[tuple[int, int]] = []
    pos = 0
    for m in _PIECE_SPLIT_RE.finditer(text):
        raw.append((pos, m.start()))
        pos = m.end()
    raw.append((pos, len(text)))

    # Merge tiny fragments into the previous piece.
    pieces: list[tuple[int, int]] = []
    for ps, pe in raw:
        stripped = text[ps:pe].strip()
        if not stripped:
            continue
        if pieces and len(stripped) < min_chars:
            pieces[-1] = (pieces[-1][0], pe)
        else:
            pieces.append((ps, pe))

    for ps, pe in pieces:
        while ps < pe and text[ps].isspace():
            ps += 1
        while pe > ps and text[pe - 1].isspace():
            pe -= 1
        if ps >= pe:
            continue
        if pe - ps <= max_chars:
            yield ps, pe, text[ps:pe]
            continue
        # Hard-window an oversized piece (long JSON line, minified blob…).
        p = ps
        while p < pe:
            end = min(p + max_chars, pe)
            if end < pe:
                dot = text.rfind(". ", p + max_chars // 2, end)
                if dot > p:
                    end = dot + 1
            ws, we = p, end
            while ws < we and text[ws].isspace():
                ws += 1
            while we > ws and text[we - 1].isspace():
                we -= 1
            if ws < we:
                yield ws, we, text[ws:we]
            p = end


def _fresh_exception(error: BaseException) -> BaseException:
    """Clone a failure without sharing its mutable traceback between callers."""
    fresh: BaseException | None = None
    try:
        fresh = copy.copy(error)
    except BaseException:
        try:
            fresh = type(error)(*error.args)
        except BaseException:
            try:
                fresh = RuntimeError(f"{type(error).__name__}: {error}")
            except BaseException:
                fresh = RuntimeError("model load failed")
    if fresh is error or not isinstance(fresh, BaseException):
        try:
            fresh = RuntimeError(f"{type(error).__name__}: {error}")
        except BaseException:
            fresh = RuntimeError("model load failed")
    try:
        return fresh.with_traceback(None)
    except BaseException:
        return RuntimeError("model load failed")


class _LoadAttempt:
    """One model-load generation shared by every caller that encounters it."""

    def __init__(self, generation: int) -> None:
        self.generation = generation
        self.done = threading.Event()
        self.result: Any | None = None
        self.error: BaseException | None = None
        self.waiters = 0


class TransformerDetector(Detector):
    """Wraps a HuggingFace text-classification model as a ShadowShield detector.

    Args:
        model: HF model id (or local path). Defaults to the ProtectAI DeBERTa v2
            prompt-injection classifier.
        threshold: minimum attack-class probability to raise a threat.
        max_length: token truncation length passed to the tokenizer.
        device: torch device string (e.g. "cpu", "cuda", "mps"). ``None`` lets
            transformers choose.
        lazy: if True (default) the model loads on first scan, not at construction,
            so importing/constructing stays cheap.
        segment_spans: if True, also classify the text segment-by-segment
            (blank-line blocks, split further to fit ``max_length``) and emit a
            span-carrying threat for every segment that fires. This lets the
            sanitizer redact *just the attacking sentences* — the classifier
            tranche's answer to semantic-pretext injections that survive
            signature-based span redaction. Segment classification runs on the
            **original** text so spans align; the normalized whole-text pass
            still runs as the evasion-resistant backstop (a threat with no span
            when the aggregate is hostile but no single segment crosses).
        segment_threshold: attack probability a segment must reach to fire.
            Defaults to ``threshold``.
    """

    name = "transformer_classifier"
    directions = (Direction.INPUT,)

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        threshold: float = 0.5,
        max_length: int = 512,
        device: str | None = None,
        lazy: bool = True,
        segment_spans: bool = False,
        segment_threshold: float | None = None,
    ) -> None:
        self.model_id = model
        self.threshold = threshold
        self.max_length = max_length
        self.device = device
        self.segment_spans = segment_spans
        self.segment_threshold = threshold if segment_threshold is None else segment_threshold
        self._pipeline: Any | None = None
        self._load_lock = threading.Lock()
        self._load_condition = threading.Condition(self._load_lock)
        self._load_generation = 0
        self._load_attempt: _LoadAttempt | None = None
        if not lazy:
            self._ensure_pipeline()

    def _ensure_pipeline(self) -> Any:
        loaded_pipeline = self._pipeline
        if loaded_pipeline is not None:
            return loaded_pipeline

        with self._load_condition:
            loaded_pipeline = self._pipeline
            if loaded_pipeline is not None:
                return loaded_pipeline

            attempt = self._load_attempt
            if attempt is None:
                self._load_generation += 1
                attempt = _LoadAttempt(self._load_generation)
                self._load_attempt = attempt
                is_loader = True
            else:
                attempt.waiters += 1
                self._load_condition.notify_all()
                is_loader = False

        if not is_loader:
            attempt.done.wait()
            if attempt.error is not None:
                raise _fresh_exception(attempt.error)
            return attempt.result

        # Loading a model is expensive and may allocate scarce GPU memory.
        # Construct outside the coordination lock so concurrent callers can join
        # this exact attempt rather than queueing independent loads.
        try:
            try:
                from transformers import pipeline
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise ImportError(
                    "TransformerDetector requires the 'transformers' extra: "
                    "pip install shadowshield[transformers]"
                ) from exc
            kwargs: dict[str, Any] = {
                "task": "text-classification",
                "model": self.model_id,
                "truncation": True,
                "max_length": self.max_length,
            }
            if self.device is not None:
                kwargs["device"] = self.device
            loaded = pipeline(**kwargs)
        except BaseException as exc:
            prototype: BaseException = RuntimeError("model load failed")
            try:
                # Keep a traceback-free prototype. The loader re-raises ``exc``;
                # each waiter clones the prototype so exception tracebacks cannot
                # race or grow as the same object is raised across threads.
                prototype = _fresh_exception(exc)
            except BaseException:
                # Exception subclasses can make copying, construction, or even
                # stringification fail. They must never strand this generation.
                pass
            finally:
                with self._load_condition:
                    attempt.error = prototype
                    self._load_attempt = None
                    attempt.done.set()
                    self._load_condition.notify_all()
            raise

        with self._load_condition:
            # Publish only after construction succeeds. All callers that joined
            # this generation observe the same fully initialized pipeline.
            self._pipeline = loaded
            attempt.result = loaded
            self._load_attempt = None
            attempt.done.set()
            self._load_condition.notify_all()
            return loaded

    def warmup(self) -> None:
        """Load the classifier explicitly for fail-fast startup."""
        self._ensure_pipeline()

    def is_ready(self) -> bool:
        """Report whether the classifier is loaded without triggering a load."""
        return self._pipeline is not None

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        if not text.strip():
            return []
        clf = self._ensure_pipeline()
        # Classify the de-obfuscated view so evasion tricks don't fool the model.
        whole_prob = self._attack_prob(clf(context.normalized.normalized or text))

        threats: list[Threat] = []
        if self.segment_spans:
            segments = list(_segments(text, max_chars=_SEGMENT_MAX_CHARS))
            if segments:
                probs = [self._attack_prob(p) for p in clf([seg for _, _, seg in segments])]
                for (start, end, seg), prob in zip(segments, probs, strict=True):
                    if prob >= self.segment_threshold:
                        threats.append(
                            Threat(
                                category=ThreatCategory.PROMPT_INJECTION,
                                severity=Severity.from_score(prob),
                                score=prob,
                                detector=self.name,
                                message=(
                                    f"ML classifier flagged a prompt-injection segment "
                                    f"(p={prob:.2f}, model={self.model_id})."
                                ),
                                matched=seg,
                                span=(start, end),
                                metadata={"model": self.model_id, "segment": True},
                            )
                        )
                if threats:
                    # Localized: spans carry the signal; suppress the whole-text
                    # threat so noisy-or doesn't double-count the same attack.
                    return threats

        if whole_prob < self.threshold:
            return threats
        threats.append(
            Threat(
                category=ThreatCategory.PROMPT_INJECTION,
                severity=Severity.from_score(whole_prob),
                score=whole_prob,
                detector=self.name,
                message=f"ML classifier flagged prompt injection (p={whole_prob:.2f}, model={self.model_id}).",
                metadata={"model": self.model_id},
            )
        )
        return threats

    @staticmethod
    def _attack_prob(preds: Any) -> float:
        """Attack-class probability from a pipeline result (either label shape)."""
        pred = preds[0] if isinstance(preds, list) else preds
        label = str(pred.get("label", "")).upper()
        score = float(pred.get("score", 0.0))
        return score if label in _ATTACK_LABELS else 1.0 - score
