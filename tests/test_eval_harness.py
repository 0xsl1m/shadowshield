"""Focused tests for benchmark measurement integrity."""

from __future__ import annotations

from typing import Any, cast

import pytest

from shadowshield.core.shield import Shield
from shadowshield.core.types import Decision, Direction, ScanResult, Threat
from shadowshield.detectors.base import Detector, ScanContext
from shadowshield.eval import BenchmarkReport, CategoryStat, EvalExample, evaluate_shield


class _FakeShield:
    def __init__(
        self,
        results: list[ScanResult],
        *,
        readiness: dict[str, Any] | None = None,
        warmup_error: Exception | None = None,
    ) -> None:
        self.results = list(results)
        self.readiness_report = readiness or {"ready": True, "not_ready": []}
        self.warmup_error = warmup_error
        self.warmed = False

    def warmup(self) -> None:
        self.warmed = True
        if self.warmup_error is not None:
            raise self.warmup_error

    def readiness(self) -> dict[str, Any]:
        return self.readiness_report

    def scan(
        self,
        text: str,
        *,
        direction: Direction,
        identity: str,
    ) -> ScanResult:
        del text, direction, identity
        return self.results.pop(0)


class _BrokenDetector(Detector):
    name = "benchmark_broken"

    def scan(self, text: str, *, context: ScanContext) -> list[Threat]:
        del text, context
        raise RuntimeError("must not enter benchmark output")


def _result(
    flagged: bool,
    *,
    detector_errors: dict[str, int] | None = None,
) -> ScanResult:
    metadata: dict[str, Any] = {"flagged": flagged}
    if detector_errors is not None:
        metadata["detector_errors"] = detector_errors
    return ScanResult(
        text="example",
        direction=Direction.INPUT,
        decision=Decision.FLAG if flagged else Decision.ALLOW,
        metadata=metadata,
    )


def test_category_confusion_is_class_conditional_and_compatible() -> None:
    examples = [
        EvalExample("a1", 1, "paired"),
        EvalExample("a2", 1, "paired"),
        EvalExample("b1", 0, "paired"),
        EvalExample("b2", 0, "paired"),
        EvalExample("a3", 1, "attack_only"),
        EvalExample("b3", 0, "benign_only"),
    ]
    fake = _FakeShield(
        [
            _result(True),
            _result(False),
            _result(True),
            _result(False),
            _result(True),
            _result(False),
        ]
    )

    report = evaluate_shield(
        cast(Shield, fake),
        examples,
        predicate=lambda result: bool(result.metadata["flagged"]),
        warmup=True,
    )

    paired = report.by_category["paired"]
    assert (paired.tp, paired.fp, paired.tn, paired.fn) == (1, 1, 1, 1)
    assert paired.recall == pytest.approx(0.5)
    assert paired.false_positive_rate == pytest.approx(0.5)
    assert paired.balanced_accuracy == pytest.approx(0.5)

    assert report.by_category["attack_only"].recall == pytest.approx(1.0)
    assert report.by_category["attack_only"].recall_ci95 == pytest.approx((0.2065493144, 1.0))
    assert report.by_category["attack_only"].false_positive_rate is None
    assert report.by_category["attack_only"].false_positive_rate_ci95 is None
    assert report.by_category["attack_only"].balanced_accuracy is None
    assert report.by_category["benign_only"].recall is None
    assert report.by_category["benign_only"].recall_ci95 is None
    assert report.by_category["benign_only"].false_positive_rate == pytest.approx(0.0)

    serialized = report.to_dict()
    paired_json = serialized["by_category"]["paired"]  # type: ignore[index]
    # Original fields remain present for API/output compatibility.
    assert paired_json["total"] == 4  # type: ignore[index]
    assert paired_json["flagged"] == 2  # type: ignore[index]
    assert paired_json["rate"] == pytest.approx(0.5)  # type: ignore[index]
    assert paired_json["confusion"] == {"tp": 1, "fp": 1, "tn": 1, "fn": 1}  # type: ignore[index]
    assert fake.warmed is True
    assert report.reliable is True


def test_wilson_confidence_intervals_are_additive_and_class_conditional() -> None:
    category = CategoryStat(
        category="paired",
        total=400,
        flagged=150,
        tp=140,
        fp=10,
        tn=190,
        fn=60,
    )
    report = BenchmarkReport(
        n=400,
        tp=140,
        fp=10,
        tn=190,
        fn=60,
        by_category={"paired": category},
        ready=True,
    )

    assert report.recall_ci95 == pytest.approx((0.6332093163, 0.7592525532))
    assert report.false_positive_rate_ci95 == pytest.approx((0.0273826456, 0.0895781481))
    assert category.recall_ci95 == pytest.approx(report.recall_ci95)
    assert category.false_positive_rate_ci95 == pytest.approx(report.false_positive_rate_ci95)

    serialized = report.to_dict()
    assert serialized["recall_detection_rate"] == pytest.approx(0.7)
    assert serialized["recall_detection_rate_ci95"] == {
        "low": 0.6332,
        "high": 0.7593,
    }
    assert serialized["false_positive_rate"] == pytest.approx(0.05)
    assert serialized["false_positive_rate_ci95"] == {
        "low": 0.0274,
        "high": 0.0896,
    }
    category_json = serialized["by_category"]["paired"]  # type: ignore[index]
    assert category_json["recall_detection_rate_ci95"] == {  # type: ignore[index]
        "low": 0.6332,
        "high": 0.7593,
    }
    assert category_json["false_positive_rate_ci95"] == {  # type: ignore[index]
        "low": 0.0274,
        "high": 0.0896,
    }
    assert "95% CI [63.3%, 75.9%]" in report.format_text()


def test_runtime_failures_are_aggregated_and_mark_report_unreliable() -> None:
    examples = [
        EvalExample("a", 1, "attack"),
        EvalExample("b", 0, "benign"),
        EvalExample("c", 0, "benign"),
    ]
    fake = _FakeShield(
        [
            _result(False, detector_errors={"semantic": 1}),
            _result(False, detector_errors={"semantic": 2, "vector": 1}),
            _result(False, detector_errors={"ignored": 0}),
        ],
        readiness={"ready": False, "not_ready": ["semantic"]},
        warmup_error=RuntimeError("model unavailable"),
    )

    report = evaluate_shield(
        cast(Shield, fake),
        examples,
        predicate=lambda result: bool(result.metadata["flagged"]),
        warmup=True,
    )

    assert report.detector_errors == {"semantic": 3, "vector": 1}
    assert report.detector_error_count == 4
    assert report.warmup_error == "RuntimeError"
    assert report.ready is False
    assert report.not_ready == ["semantic"]
    assert report.reliable is False

    runtime = report.to_dict()["runtime"]
    assert runtime["reliable"] is False  # type: ignore[index]
    assert runtime["detector_errors"] == {  # type: ignore[index]
        "total": 4,
        "by_detector": {"semantic": 3, "vector": 1},
    }
    text = report.format_text()
    assert "UNRELIABLE" in text
    assert "NOT READY (semantic)" in text
    assert "FAILED (RuntimeError)" in text
    assert "model unavailable" not in text


def test_programmatic_default_preserves_no_warmup_behavior() -> None:
    fake = _FakeShield([_result(False)])

    report = evaluate_shield(
        cast(Shield, fake),
        [EvalExample("clean", 0, "benign")],
        predicate=lambda result: bool(result.metadata["flagged"]),
    )

    assert fake.warmed is False
    assert report.warmup_attempted is False
    assert report.reliable is True


def test_real_shield_detector_failure_marks_benchmark_unreliable() -> None:
    shield = Shield.for_mode("balanced", extra_detectors=[_BrokenDetector()])

    report = evaluate_shield(
        shield,
        [EvalExample("ordinary request", 0, "benign")],
        warmup=True,
    )

    assert report.detector_errors == {"benchmark_broken": 1}
    assert report.detector_error_count == 1
    assert report.reliable is False
