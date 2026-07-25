"""Vector-similarity detector — catch *paraphrases* of known attacks.

Signatures match exact-ish phrasings; a classifier generalises but is a black box.
This third tier (the Rebuff/Vigil idea, now maintained) embeds the incoming text
and measures cosine similarity to a corpus of known attack templates. A novel
rephrasing of "ignore previous instructions" that dodges the regex still lands
*near* it in embedding space — and with a **multilingual** embedding model, a
German or Spanish attack lands near its English template, so one corpus covers
many languages.

It is **opt-in** (it loads an embedding model) and **self-hardening**: confirmed
attacks (e.g. a canary-caught exfiltration) can be appended to the live index via
:meth:`add_attack` so the guard learns from each incident.

Requires the ``vectors`` extra: ``pip install shadowshield[vectors]``.
"""

from __future__ import annotations

import copy
import threading
from importlib import resources
from typing import Any

from ..core.types import Direction, Severity, Threat, ThreatCategory
from .base import Detector, ScanContext

# Multilingual by default so one corpus covers many languages (cross-lingual
# embedding alignment). Override with any sentence-transformers model id.
DEFAULT_EMBED_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


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
                fresh = RuntimeError("index build failed")
    if fresh is error or not isinstance(fresh, BaseException):
        try:
            fresh = RuntimeError(f"{type(error).__name__}: {error}")
        except BaseException:
            fresh = RuntimeError("index build failed")
    try:
        return fresh.with_traceback(None)
    except BaseException:
        return RuntimeError("index build failed")


class _LoadAttempt:
    """One index-build generation shared by every caller that encounters it."""

    def __init__(self, generation: int) -> None:
        self.generation = generation
        self.done = threading.Event()
        self.result: Any | None = None
        self.error: BaseException | None = None
        self.waiters = 0


def _load_corpus() -> list[str]:
    raw = (
        resources.files("shadowshield.detectors.data")
        .joinpath("attack_corpus.txt")
        .read_text(encoding="utf-8")
    )
    out: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


class VectorSimilarityDetector(Detector):
    """Flags inputs whose embedding is close to a known-attack corpus.

    Args:
        model: sentence-transformers model id (default: a multilingual MiniLM).
        threshold: cosine similarity at/above which a match is flagged.
        corpus: optional custom attack strings (defaults to the bundled corpus).
        lazy: load the model on first scan rather than at construction.

    The detector is not auto-registered — add it via
    ``Shield(..., use_vectors=True)`` or ``extra_detectors=[VectorSimilarityDetector()]``.
    """

    name = "vector_similarity"
    directions = (Direction.INPUT,)

    def __init__(
        self,
        model: str = DEFAULT_EMBED_MODEL,
        *,
        threshold: float = 0.72,
        corpus: list[str] | None = None,
        lazy: bool = True,
    ) -> None:
        self.model_id = model
        self.threshold = threshold
        # Own the mutable corpus so caller-side list changes cannot invalidate the
        # embedding row-to-corpus invariant.
        self._corpus: list[str] = list(corpus) if corpus is not None else _load_corpus()
        self._model: Any = None
        self._corpus_emb: Any = None
        self._index_lock = threading.Lock()
        self._load_condition = threading.Condition(self._index_lock)
        self._load_generation = 0
        self._load_attempt: _LoadAttempt | None = None
        self._ready = threading.Event()
        if not lazy:
            self._ensure_index()

    def _ensure_index(self) -> Any:
        if self._ready.is_set():
            return self._model

        with self._load_condition:
            if self._ready.is_set():
                return self._model

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

        try:
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise ImportError(
                    "VectorSimilarityDetector requires the 'vectors' extra: "
                    "pip install shadowshield[vectors]"
                ) from exc

            # Build both pieces locally and publish them only after encoding
            # succeeds. This prevents scans from observing a half-built index and
            # lets a later call retry cleanly after a transient load failure.
            model = SentenceTransformer(self.model_id)
            corpus_emb = model.encode(
                list(self._corpus), normalize_embeddings=True, show_progress_bar=False
            )
        except BaseException as exc:
            prototype: BaseException = RuntimeError("index build failed")
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
            self._corpus_emb = corpus_emb
            self._model = model
            attempt.result = model
            self._load_attempt = None
            self._ready.set()
            attempt.done.set()
            self._load_condition.notify_all()
            return model

    def warmup(self) -> None:
        """Load and encode the attack index explicitly for fail-fast startup."""
        self._ensure_index()

    def is_ready(self) -> bool:
        """Report atomic index publication without loading or waiting on it."""
        return self._ready.is_set()

    def add_attack(self, text: str) -> None:
        """Append a confirmed attack to the live index (self-hardening).

        Future inputs resembling ``text`` (or its paraphrases / translations) will
        now match. Call this when an incident is confirmed — e.g. a canary leak.
        """
        if not text.strip():
            return
        model = self._ensure_index()
        import numpy as np

        emb = model.encode([text], normalize_embeddings=True, show_progress_bar=False)
        # Encoding is intentionally outside the mutation lock. Only the short
        # read-modify-publish transaction is serialized, so concurrent hardening
        # cannot lose rows while scans retain a stable immutable array snapshot.
        with self._index_lock:
            updated_corpus = [*self._corpus, text]
            updated_emb = np.vstack([self._corpus_emb, emb])
            self._corpus = updated_corpus
            self._corpus_emb = updated_emb

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        body = context.normalized.normalized or text
        if not body.strip():
            return []
        self._ensure_index()
        import numpy as np

        # Take a consistent reference snapshot, then perform model inference and
        # matrix work without blocking index mutation.
        with self._index_lock:
            model = self._model
            corpus_emb = self._corpus_emb
        query = model.encode([body], normalize_embeddings=True, show_progress_bar=False)
        # Cosine similarity = dot product on L2-normalised vectors.
        sims = (corpus_emb @ query[0]).astype(float)
        best_idx = int(np.argmax(sims))
        best = float(sims[best_idx])
        if best < self.threshold:
            return []
        # Map [threshold, 1.0] -> [0.5, 1.0] for the threat score.
        score = 0.5 + 0.5 * (best - self.threshold) / max(1e-6, 1.0 - self.threshold)
        score = min(1.0, score)
        return [
            Threat(
                category=ThreatCategory.PROMPT_INJECTION,
                severity=Severity.from_score(score),
                score=score,
                detector=self.name,
                message=(
                    f"Input is semantically close to a known attack "
                    f"(cosine {best:.2f} ≥ {self.threshold:.2f})."
                ),
                metadata={"similarity": round(best, 3), "model": self.model_id},
            )
        ]
