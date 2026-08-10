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
from math import sqrt

from ..core.shield import Shield
from ..core.types import Direction, ScanResult
from .dataset import EvalExample

# Default prediction rule: the guard "flagged" an example if any detector fired.
# This is the most sensitive measure and the one that exposes false positives.
DefaultPredicate = Callable[[ScanResult], bool]
_WILSON_Z_95 = 1.959963984540054


def _default_predicate(result: ScanResult) -> bool:
    return bool(result.threats)


@dataclass(slots=True)
class CategoryStat:
    category: str
    total: int = 0
    flagged: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def rate(self) -> float:
        return self.flagged / self.total if self.total else 0.0

    @property
    def recall(self) -> float | None:
        """Attack recall for this category, or ``None`` without attack rows."""
        denom = self.tp + self.fn
        return self.tp / denom if denom else None

    @property
    def false_positive_rate(self) -> float | None:
        """Benign false-positive rate, or ``None`` without benign rows."""
        denom = self.fp + self.tn
        return self.fp / denom if denom else None

    @property
    def recall_ci95(self) -> tuple[float, float] | None:
        """Two-sided 95% Wilson interval for attack recall."""
        return _wilson_interval(self.tp, self.tp + self.fn)

    @property
    def false_positive_rate_ci95(self) -> tuple[float, float] | None:
        """Two-sided 95% Wilson interval for benign false-positive rate."""
        return _wilson_interval(self.fp, self.fp + self.tn)

    @property
    def balanced_accuracy(self) -> float | None:
        """Balanced accuracy when both attack and benign rows are present."""
        recall = self.recall
        fpr = self.false_positive_rate
        if recall is None or fpr is None:
            return None
        return (recall + (1.0 - fpr)) / 2

    def to_dict(self) -> dict[str, object]:
        return {
            # Retain the original public fields for output compatibility.
            "total": self.total,
            "flagged": self.flagged,
            "rate": round(self.rate, 4),
            "confusion": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "recall_detection_rate": _rounded_optional(self.recall),
            "recall_detection_rate_ci95": _interval_to_dict(self.recall_ci95),
            "false_positive_rate": _rounded_optional(self.false_positive_rate),
            "false_positive_rate_ci95": _interval_to_dict(self.false_positive_rate_ci95),
            "balanced_accuracy": _rounded_optional(self.balanced_accuracy),
        }


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
    warmup_attempted: bool = False
    warmup_error: str | None = None
    ready: bool | None = None
    not_ready: list[str] = field(default_factory=list)
    readiness_error: str | None = None
    detector_errors: dict[str, int] = field(default_factory=dict)

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
    def recall_ci95(self) -> tuple[float, float] | None:
        """Two-sided 95% Wilson interval for aggregate attack recall."""
        return _wilson_interval(self.tp, self.tp + self.fn)

    @property
    def false_positive_rate_ci95(self) -> tuple[float, float] | None:
        """Two-sided 95% Wilson interval for aggregate benign FPR."""
        return _wilson_interval(self.fp, self.fp + self.tn)

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

    @property
    def detector_error_count(self) -> int:
        """Total detector failures observed across all benchmark scans."""
        return sum(self.detector_errors.values())

    @property
    def reliable(self) -> bool:
        """Whether initialization and every measured scan completed cleanly."""
        return (
            self.warmup_error is None
            and self.readiness_error is None
            and self.ready is not False
            and self.detector_error_count == 0
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "n": self.n,
            "recall_detection_rate": round(self.recall, 4),
            "recall_detection_rate_ci95": _interval_to_dict(self.recall_ci95),
            "precision": round(self.precision, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "false_positive_rate_ci95": _interval_to_dict(self.false_positive_rate_ci95),
            "f1": round(self.f1, 4),
            "balanced_accuracy": round(self.balanced_accuracy, 4),
            "accuracy": round(self.accuracy, 4),
            "confusion": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn},
            "latency_ms": {
                "p50": round(self.latency_p50_ms, 3),
                "p95": round(self.latency_p95_ms, 3),
                "mean": round(self.latency_mean_ms, 3),
            },
            "by_category": {c: s.to_dict() for c, s in sorted(self.by_category.items())},
            "runtime": {
                "reliable": self.reliable,
                "warmup": {
                    "attempted": self.warmup_attempted,
                    "error": self.warmup_error,
                },
                "readiness": {
                    "ready": self.ready,
                    "not_ready": list(self.not_ready),
                    "error": self.readiness_error,
                },
                "detector_errors": {
                    "total": self.detector_error_count,
                    "by_detector": dict(sorted(self.detector_errors.items())),
                },
            },
        }

    def format_text(self) -> str:
        lines = [
            f"ShadowShield benchmark — {self.n} examples",
            "-" * 48,
            f"detection rate (recall) : {self.recall:6.1%}"
            f"  95% CI {_format_interval(self.recall_ci95)}",
            f"false-positive rate     : {self.false_positive_rate:6.1%}"
            f"  95% CI {_format_interval(self.false_positive_rate_ci95)}",
            f"precision               : {self.precision:6.1%}",
            f"F1                      : {self.f1:6.1%}",
            f"balanced accuracy       : {self.balanced_accuracy:6.1%}",
            f"confusion (tp/fp/tn/fn) : {self.tp}/{self.fp}/{self.tn}/{self.fn}",
            f"latency p50 / p95 (ms)  : {self.latency_p50_ms:.2f} / {self.latency_p95_ms:.2f}",
            f"benchmark reliability   : {'reliable' if self.reliable else 'UNRELIABLE'}",
            f"detector errors          : {self.detector_error_count}",
            self._format_readiness(),
            self._format_warmup(),
            "",
            "per-category flag rate:",
        ]
        for cat, stat in sorted(self.by_category.items()):
            lines.append(
                f"  {cat:24} {stat.flagged:>3}/{stat.total:<3} ({stat.rate:5.1%})"
                f"  tp/fp/tn/fn={stat.tp}/{stat.fp}/{stat.tn}/{stat.fn}"
                f"  recall={_format_optional_percent(stat.recall)}"
                f" CI={_format_interval(stat.recall_ci95)}"
                f"  FPR={_format_optional_percent(stat.false_positive_rate)}"
                f" CI={_format_interval(stat.false_positive_rate_ci95)}"
                f"  BA={_format_optional_percent(stat.balanced_accuracy)}"
            )
        return "\n".join(lines)

    def _format_readiness(self) -> str:
        if self.readiness_error is not None:
            return f"readiness               : ERROR ({self.readiness_error})"
        if self.ready is None:
            return "readiness               : not checked"
        if self.ready:
            return "readiness               : ready"
        names = ", ".join(self.not_ready) if self.not_ready else "unspecified detector"
        return f"readiness               : NOT READY ({names})"

    def _format_warmup(self) -> str:
        if not self.warmup_attempted:
            return "warmup                 : not requested"
        if self.warmup_error is not None:
            return f"warmup                 : FAILED ({self.warmup_error})"
        return "warmup                 : complete"


def _rounded_optional(value: float | None) -> float | None:
    return round(value, 4) if value is not None else None


def _wilson_interval(successes: int, total: int) -> tuple[float, float] | None:
    """Return a two-sided 95% Wilson score interval for a binomial rate."""
    if total <= 0:
        return None
    proportion = successes / total
    z_squared = _WILSON_Z_95 * _WILSON_Z_95
    denominator = 1.0 + z_squared / total
    center = (proportion + z_squared / (2.0 * total)) / denominator
    margin = (
        _WILSON_Z_95
        * sqrt(proportion * (1.0 - proportion) / total + z_squared / (4.0 * total * total))
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def _interval_to_dict(
    interval: tuple[float, float] | None,
) -> dict[str, float] | None:
    if interval is None:
        return None
    low, high = interval
    return {"low": round(low, 4), "high": round(high, 4)}


def _format_optional_percent(value: float | None) -> str:
    return f"{value:.1%}" if value is not None else "n/a"


def _format_interval(interval: tuple[float, float] | None) -> str:
    if interval is None:
        return "n/a"
    low, high = interval
    return f"[{low:.1%}, {high:.1%}]"


def _bounded_exception(error: Exception) -> str:
    """Return only a bounded error type; exception text may contain secrets."""
    return type(error).__name__[:128]


def _readiness(shield: Shield) -> tuple[bool | None, list[str], str | None]:
    try:
        status = shield.readiness()
    except Exception as exc:
        return None, [], _bounded_exception(exc)

    ready = status.get("ready")
    raw_names = status.get("not_ready", [])
    names = [str(name)[:64] for name in raw_names[:32]] if isinstance(raw_names, list) else []
    return ready if isinstance(ready, bool) else None, names, None


def _record_detector_errors(result: ScanResult, aggregate: dict[str, int]) -> None:
    """Add the engine's bounded per-scan detector failure counters."""
    errors = result.metadata.get("detector_errors")
    if not isinstance(errors, dict):
        return
    for raw_name, raw_count in errors.items():
        if not isinstance(raw_name, str):
            continue
        if not isinstance(raw_count, int) or isinstance(raw_count, bool) or raw_count <= 0:
            continue
        name = raw_name[:128]
        aggregate[name] = aggregate.get(name, 0) + raw_count


def evaluate_shield(
    shield: Shield,
    examples: list[EvalExample],
    *,
    direction: Direction = Direction.INPUT,
    predicate: DefaultPredicate = _default_predicate,
    warmup: bool = False,
) -> BenchmarkReport:
    """Run ``shield`` over ``examples`` and return a :class:`BenchmarkReport`.

    ``predicate`` decides whether a scan counts as "flagged as attack"; the
    default is "any detector fired", which is the most sensitive (and most
    honest about false positives).

    Set ``warmup=True`` for production-style measurements. Initialization runs
    before timed scans, and warmup/readiness failures are captured on the report
    instead of being mistaken for clean predictions. The default remains
    ``False`` for compatibility with existing programmatic callers.
    """
    tp = fp = tn = fn = 0
    latencies: list[float] = []
    by_category: dict[str, CategoryStat] = defaultdict(lambda: CategoryStat(""))
    detector_errors: dict[str, int] = {}
    warmup_error: str | None = None

    if warmup:
        try:
            shield.warmup()
        except Exception as exc:
            warmup_error = _bounded_exception(exc)

    for i, ex in enumerate(examples):
        # Each example is an INDEPENDENT request — give it a unique identity so a
        # rate-limiter (if enabled) doesn't treat the benchmark as one abuser and
        # pollute detection metrics.
        start = time.perf_counter()
        result = shield.scan(ex.text, direction=direction, identity=f"bench-{i}")
        latencies.append((time.perf_counter() - start) * 1000.0)
        _record_detector_errors(result, detector_errors)

        flagged = predicate(result)
        cat = ex.category or ("attack" if ex.is_attack else "benign")
        stat = by_category[cat]
        stat.category = cat
        stat.total += 1
        if flagged:
            stat.flagged += 1

        if ex.is_attack and flagged:
            tp += 1
            stat.tp += 1
        elif ex.is_attack and not flagged:
            fn += 1
            stat.fn += 1
        elif not ex.is_attack and flagged:
            fp += 1
            stat.fp += 1
        else:
            tn += 1
            stat.tn += 1

    ready, not_ready, readiness_error = _readiness(shield)

    return BenchmarkReport(
        n=len(examples),
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        latencies_ms=latencies,
        by_category=dict(by_category),
        warmup_attempted=warmup,
        warmup_error=warmup_error,
        ready=ready,
        not_ready=not_ready,
        readiness_error=readiness_error,
        detector_errors=detector_errors,
    )
