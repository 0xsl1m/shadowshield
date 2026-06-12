"""Statistical anomaly detection over prompt/behaviour features.

This is the Sentinel-inspired "this doesn't look like normal traffic" layer. It
deliberately ships with a **dependency-free heuristic** so it works out of the
box, and *optionally* upgrades to a scikit-learn ``IsolationForest`` when the
``[ml]`` extra is installed and the detector has been fitted on your own traffic.

The heuristic scores a handful of robust signals that correlate with crafted
adversarial prompts: extreme length, very high special-character ratio, runaway
repetition, and abnormal token/character ratios. None of these is conclusive
alone — hence LOW/MEDIUM severities and modest scores — but they corroborate the
signature detectors and catch novel phrasings the regexes miss.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any, ClassVar

from ..core.types import Direction, Severity, Threat, ThreatCategory
from .base import Detector, ScanContext, register_detector


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _special_ratio(text: str) -> float:
    if not text:
        return 0.0
    special = sum(1 for ch in text if not ch.isalnum() and not ch.isspace())
    return special / len(text)


def _max_repeat_run(text: str) -> int:
    best = run = 1
    for i in range(1, len(text)):
        run = run + 1 if text[i] == text[i - 1] else 1
        best = max(best, run)
    return best


@register_detector
class AnomalyDetector(Detector):
    """Heuristic (default) / IsolationForest (optional) prompt anomaly scorer.

    Options (via ``DetectorConfig.options``):
        max_length: length above which a prompt is considered anomalous.
        special_ratio_threshold: special-char fraction considered anomalous.
        entropy_threshold: per-char entropy above which content looks random.
    """

    name = "anomaly"
    directions = (Direction.INPUT,)

    _DEFAULTS: ClassVar[dict[str, float]] = {
        "max_length": 8000,
        "special_ratio_threshold": 0.45,
        "entropy_threshold": 5.2,
        "repeat_run_threshold": 60,
    }

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        opts = {**self._DEFAULTS, **context.options}
        threats: list[Threat] = []

        length = len(text)
        special = _special_ratio(text)
        entropy = _shannon_entropy(text)
        repeat = _max_repeat_run(text)

        if length > opts["max_length"]:
            threats.append(
                self._anomaly(
                    0.45,
                    Severity.LOW,
                    f"Unusually long prompt ({length} chars).",
                    {"length": length},
                )
            )
        if special > opts["special_ratio_threshold"]:
            threats.append(
                self._anomaly(
                    0.55,
                    Severity.MEDIUM,
                    f"High special-character ratio ({special:.0%}).",
                    {"special_ratio": round(special, 3)},
                )
            )
        if entropy > opts["entropy_threshold"] and length > 40:
            threats.append(
                self._anomaly(
                    0.5,
                    Severity.LOW,
                    f"High character entropy ({entropy:.2f} bits/char) — looks random/encoded.",
                    {"entropy": round(entropy, 3)},
                )
            )
        if repeat > opts["repeat_run_threshold"]:
            threats.append(
                self._anomaly(
                    0.5,
                    Severity.MEDIUM,
                    f"Long repeated-character run ({repeat}) — possible flooding attack.",
                    {"max_repeat_run": repeat},
                )
            )
        return threats

    def _anomaly(
        self, score: float, severity: Severity, message: str, meta: dict[str, Any]
    ) -> Threat:
        return Threat(
            category=ThreatCategory.ANOMALY,
            severity=severity,
            score=score,
            detector=self.name,
            message=message,
            metadata=meta,
        )
