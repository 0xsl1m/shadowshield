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

from typing import Any

from ..core.types import Direction, Severity, Threat, ThreatCategory
from .base import Detector, ScanContext

# Well-known, permissively-licensed prompt-injection classifier. Override via the
# ``model`` argument (e.g. "meta-llama/Llama-Prompt-Guard-2-86M").
DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"

# Label strings different models use for the "this is an attack" class.
_ATTACK_LABELS = {"INJECTION", "JAILBREAK", "LABEL_1", "1", "UNSAFE", "MALICIOUS"}


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
    ) -> None:
        self.model_id = model
        self.threshold = threshold
        self.max_length = max_length
        self.device = device
        self._pipeline: Any | None = None
        if not lazy:
            self._ensure_pipeline()

    def _ensure_pipeline(self) -> Any:
        if self._pipeline is not None:
            return self._pipeline
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
        self._pipeline = pipeline(**kwargs)
        return self._pipeline

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        if not text.strip():
            return []
        clf = self._ensure_pipeline()
        # Classify the de-obfuscated view so evasion tricks don't fool the model.
        preds = clf(context.normalized.normalized or text)
        pred = preds[0] if isinstance(preds, list) else preds
        label = str(pred.get("label", "")).upper()
        score = float(pred.get("score", 0.0))

        is_attack = label in _ATTACK_LABELS
        # Some pipelines return the SAFE label with its own probability; convert
        # to attack-probability so the threshold means the same thing either way.
        attack_prob = score if is_attack else (1.0 - score)
        if attack_prob < self.threshold:
            return []
        return [
            Threat(
                category=ThreatCategory.PROMPT_INJECTION,
                severity=Severity.from_score(attack_prob),
                score=attack_prob,
                detector=self.name,
                message=f"ML classifier flagged prompt injection (p={attack_prob:.2f}, model={self.model_id}).",
                metadata={"model": self.model_id, "label": label},
            )
        ]
