"""Benchmark harness — measure detection quality and latency on a dataset.

Runs a :class:`~shadowshield.Shield` over labelled examples and reports the
metrics that actually matter for a prompt-injection guard:

- **recall / detection rate** on attacks (did we catch them?),
- **false-positive rate** on benign inputs — *especially the hard negatives*
  (the over-defense problem; this is the metric the field hides),
- **precision, F1, balanced accuracy**, and
- **latency p50/p95** per scan.

"Best benchmark practice" (per the 2026 distribution-shift literature) is to
always report the false-positive / hard-negative number next to the headline
detection rate — a guard that blocks everything has perfect recall and is useless.
"""

from __future__ import annotations

import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field

from ..core.shield import Shield
from ..core.types import Direction, ScanResult
from .dataset import EvalExample

# Default prediction rule: the guard "flagged" an example if any detector fired.
# This is the most sensitive measure and the one that exposes false positives.
DefaultPredicate = Callable[[ScanResult], bool]


def _default_predicate(result: ScanResult) -> bool:
    return bool(result.threats)


@dataclass(slots=True)
class CategoryStat:
    category: str
    total: int = 0
    flagged: int = 0

    @property
    def rate(self) -> float:
        return self.flagged / self.total if self.total else 0.0


@dataclass(slots=True)
class BenchmarkReport:
    """Aggregated metrics from a benchmark run."""

    n: int
    tp: int
    fp: int
    tn: int
    fn: int
    latencies_ms: list[float] = field(default_factory=list)
    by_category: dict[str, CategoryStat] = field(default_factory=dict)

    # -- core metrics --------------------------------------------------- #
    @property
    def recall(self) -> float:
        """Detection rate on attacks = TP / (TP + FN)."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def false_positive_rate(self) -> float:
        """FP / (FP + TN) — fraction of benign inputs wrongly flagged."""
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def specificity(self) -> float:
        return 1.0 - self.false_positive_rate

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.n if self.n else 0.0

    @property
    def balanced_accuracy(self) -> float:
        """Mean of recall and specificity — robust to class imbalance."""
        return (self.recall + self.specificity) / 2

    # -- latency -------------------------------------------------------- #
    def _pct(self, p: float) -> float:
        if not self.latencies_ms:
            return 0.0
        ordered = sorted(self.latencies_ms)
        k = max(0, min(len(ordered) - 1, round(p / 100 * (len(ordered) - 1))))
        return ordered[k]

    @property
    def latency_p50_ms(self) -> float:
        return self._pct(50)

    @property
    def latency_p95_ms(self) -> float:
        return self._pct(95)

    @property
    def latency_mean_ms(self) -> float:
        return sum(self.latencies_ms) / len(self.latencies_ms) if self.latencies_ms else 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "n": self.n,
            "recall_detection_rate": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "f1": round(self.f1, 4),
            "balanced_accuracy": round(self.balanced_accuracy, 4),
            "accuracy": round(self.accuracy, 4),
            "confusion": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "latency_ms": {
                "p50": round(self.latency_p50_ms, 3),
                "p95": round(self.latency_p95_ms, 3),
                "mean": round(self.latency_mean_ms, 3),
            },
            "by_category": {
                c: {"total": s.total, "flagged": s.flagged, "rate": round(s.rate, 4)}
                for c, s in sorted(self.by_category.items())
            },
        }

    def format_text(self) -> str:
        lines = [
            f"ShadowShield benchmark — {self.n} examples",
            "-" * 48,
            f"detection rate (recall) : {self.recall:6.1%}",
            f"false-positive rate     : {self.false_positive_rate:6.1%}",
            f"precision               : {self.precision:6.1%}",
            f"F1                      : {self.f1:6.1%}",
            f"balanced accuracy       : {self.balanced_accuracy:6.1%}",
            f"confusion (tp/fp/tn/fn) : {self.tp}/{self.fp}/{self.tn}/{self.fn}",
            f"latency p50 / p95 (ms)  : {self.latency_p50_ms:.2f} / {self.latency_p95_ms:.2f}",
            "",
            "per-category flag rate:",
        ]
        for cat, stat in sorted(self.by_category.items()):
            lines.append(f"  {cat:24} {stat.flagged:>3}/{stat.total:<3} ({stat.rate:5.1%})")
        return "\n".join(lines)


def evaluate_shield(
    shield: Shield,
    examples: list[EvalExample],
    *,
    direction: Direction = Direction.INPUT,
    predicate: DefaultPredicate = _default_predicate,
) -> BenchmarkReport:
    """Run ``shield`` over ``examples`` and return a :class:`BenchmarkReport`.

    ``predicate`` decides whether a scan counts as "flagged as attack"; the
    default is "any detector fired", which is the most sensitive (and most
    honest about false positives).
    """
    tp = fp = tn = fn = 0
    latencies: list[float] = []
    by_category: dict[str, CategoryStat] = defaultdict(lambda: CategoryStat(""))

    for i, ex in enumerate(examples):
        # Each example is an INDEPENDENT request — give it a unique identity so a
        # rate-limiter (if enabled) doesn't treat the benchmark as one abuser and
        # pollute detection metrics.
        start = time.perf_counter()
        result = shield.scan(ex.text, direction=direction, identity=f"bench-{i}")
        latencies.append((time.perf_counter() - start) * 1000.0)

        flagged = predicate(result)
        cat = ex.category or ("attack" if ex.is_attack else "benign")
        stat = by_category[cat]
        stat.category = cat
        stat.total += 1
        if flagged:
            stat.flagged += 1

        if ex.is_attack and flagged:
            tp += 1
        elif ex.is_attack and not flagged:
            fn += 1
        elif not ex.is_attack and flagged:
            fp += 1
        else:
            tn += 1

    return BenchmarkReport(
        n=len(examples),
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        latencies_ms=latencies,
        by_category=dict(by_category),
    )
