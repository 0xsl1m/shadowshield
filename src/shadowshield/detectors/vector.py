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

from importlib import resources
from typing import Any

from ..core.types import Direction, Severity, Threat, ThreatCategory
from .base import Detector, ScanContext

# Multilingual by default so one corpus covers many languages (cross-lingual
# embedding alignment). Override with any sentence-transformers model id.
DEFAULT_EMBED_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"


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
        self._corpus: list[str] = corpus if corpus is not None else _load_corpus()
        self._model: Any = None
        self._corpus_emb: Any = None
        if not lazy:
            self._ensure_index()

    def _ensure_index(self) -> Any:
        if self._model is not None:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ImportError(
                "VectorSimilarityDetector requires the 'vectors' extra: "
                "pip install shadowshield[vectors]"
            ) from exc
        self._model = SentenceTransformer(self.model_id)
        self._corpus_emb = self._model.encode(
            self._corpus, normalize_embeddings=True, show_progress_bar=False
        )
        return self._model

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
        self._corpus.append(text)
        self._corpus_emb = np.vstack([self._corpus_emb, emb])

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        body = context.normalized.normalized or text
        if not body.strip():
            return []
        model = self._ensure_index()
        import numpy as np

        query = model.encode([body], normalize_embeddings=True, show_progress_bar=False)
        # Cosine similarity = dot product on L2-normalised vectors.
        sims = (self._corpus_emb @ query[0]).astype(float)
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
