"""Score calibration — make ``block_threshold`` mean the same thing everywhere.

Raw detector scores are hand-tuned constants aggregated by a noisy-or, so a raw
0.8 from one detector mix is not the same *probability of attack* as 0.8 from
another. This module fits an **isotonic regression** (pool-adjacent-violators,
stdlib only — no sklearn) from labelled benchmark scores to empirical attack
probabilities. Applied to the engine's aggregate score, ``block_threshold``
becomes a calibrated probability cut that transfers across detector configs.

The fitted artifact is a small, schema-validated JSON file
(``shadowshield calibrate --out calibration.json``). Loading is tainted-input
safe: bounded size, bounded knot count, strict type/range checks, no evaluation.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..eval.dataset import EvalExample
    from .shield import Shield

_SCHEMA_VERSION = 1
_MAX_ARTIFACT_BYTES = 1_048_576
_MAX_KNOTS = 4_096
_MIN_EXAMPLES = 20


@dataclass(slots=True)
class IsotonicCalibrator:
    """A monotone step calibrator: raw aggregate score -> attack probability.

    ``xs`` are knot scores (strictly increasing), ``ys`` the calibrated
    probability at each knot. Prediction is linear between knots, clamped to
    the end-plateaus outside the fitted range.
    """

    xs: list[float]
    ys: list[float]
    meta: dict[str, Any] = field(default_factory=dict)

    def predict(self, score: float) -> float:
        """Map a raw aggregate score to a calibrated attack probability."""
        if not self.xs:
            return max(0.0, min(1.0, score))
        x = max(0.0, min(1.0, score))
        xs, ys = self.xs, self.ys
        if x <= xs[0]:
            return ys[0]
        if x >= xs[-1]:
            return ys[-1]
        # Binary search for the enclosing knot interval.
        lo, hi = 0, len(xs) - 1
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if xs[mid] <= x:
                lo = mid
            else:
                hi = mid
        span = xs[hi] - xs[lo]
        if span <= 0:
            return ys[hi]
        t = (x - xs[lo]) / span
        return ys[lo] + t * (ys[hi] - ys[lo])

    # ------------------------------------------------------------------ #
    def save(self, path: str | Path) -> Path:
        """Write the calibration artifact (canonical JSON)."""
        body = {
            "schema_version": _SCHEMA_VERSION,
            "method": "isotonic-pav",
            "xs": self.xs,
            "ys": self.ys,
            **self.meta,
        }
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        if len(encoded) > _MAX_ARTIFACT_BYTES:
            raise ValueError("calibration artifact exceeds size limit")
        target = Path(path)
        target.write_text(encoded, encoding="utf-8")
        return target

    @classmethod
    def load(cls, path: str | Path) -> IsotonicCalibrator:
        """Load and strictly validate a calibration artifact (tainted-input safe)."""
        source = Path(path)
        raw = source.read_bytes()
        if len(raw) > _MAX_ARTIFACT_BYTES:
            raise ValueError("calibration artifact exceeds size limit")
        obj = json.loads(raw.decode("utf-8"))
        if not isinstance(obj, dict):
            raise ValueError("calibration artifact must be a JSON object")
        if obj.get("schema_version") != _SCHEMA_VERSION:
            raise ValueError("unsupported calibration schema version")
        xs, ys = obj.get("xs"), obj.get("ys")
        if (
            not isinstance(xs, list)
            or not isinstance(ys, list)
            or not xs
            or len(xs) != len(ys)
            or len(xs) > _MAX_KNOTS
        ):
            raise ValueError("invalid calibration knots")
        knots_x: list[float] = []
        knots_y: list[float] = []
        for xv, yv in zip(xs, ys, strict=True):
            if (
                isinstance(xv, bool)
                or isinstance(yv, bool)
                or not isinstance(xv, (int, float))
                or not isinstance(yv, (int, float))
            ):
                raise ValueError("calibration knots must be numbers")
            fx, fy = float(xv), float(yv)
            if not (0.0 <= fx <= 1.0) or not (0.0 <= fy <= 1.0):
                raise ValueError("calibration knots out of range")
            if knots_x and fx <= knots_x[-1]:
                raise ValueError("calibration knots must be strictly increasing")
            knots_x.append(fx)
            knots_y.append(fy)
        meta = {k: v for k, v in obj.items() if k not in {"schema_version", "xs", "ys"}}
        return cls(xs=knots_x, ys=knots_y, meta=meta)


def fit_isotonic(scores: list[float], labels: list[int]) -> IsotonicCalibrator:
    """Fit isotonic regression (PAV) on raw scores with binary labels.

    Requires both classes to be present; with too little data the fit is
    meaningless and a :class:`ValueError` is raised instead of shipping a
    misleading calibrator.
    """
    if len(scores) != len(labels) or len(scores) < _MIN_EXAMPLES:
        raise ValueError(f"calibration needs at least {_MIN_EXAMPLES} labelled examples")
    if not any(labels) or all(labels):
        raise ValueError("calibration needs both attack and benign examples")

    pairs = sorted(zip(scores, labels, strict=True), key=lambda p: p[0])
    # PAV: blocks of (weight, value_sum, x_sum); merge while monotone violated.
    blocks: list[list[float]] = [[1.0, float(y), x] for x, y in pairs]
    merged: list[list[float]] = []
    for block in blocks:
        merged.append(block)
        while len(merged) >= 2:
            w2, s2, x2 = merged[-1]
            w1, s1, x1 = merged[-2]
            if s1 / w1 <= s2 / w2 + 1e-12:
                break
            merged[-2:] = [[w1 + w2, s1 + s2, x1 + x2]]
    # Coalesce equal knot positions (separate PAV blocks can share an x) so the
    # saved artifact satisfies the strictly-increasing load invariant.
    knot_x: list[float] = []
    knot_y: list[float] = []
    knot_w: list[float] = []
    for w, s, x_sum in merged:
        x = x_sum / w
        y = min(1.0, max(0.0, s / w))
        if knot_x and abs(x - knot_x[-1]) <= 1e-12:
            total = knot_w[-1] + w
            knot_y[-1] = min(1.0, max(0.0, (knot_y[-1] * knot_w[-1] + y * w) / total))
            knot_w[-1] = total
        else:
            knot_x.append(x)
            knot_y.append(y)
            knot_w.append(w)
    return IsotonicCalibrator(
        xs=knot_x,
        ys=knot_y,
        meta={
            "n": len(scores),
            "positives": sum(labels),
            "fitted_at": round(time.time(), 3),
        },
    )


def fit_from_examples(
    shield: Shield,
    examples: list[EvalExample],
    *,
    dataset: str = "custom",
) -> IsotonicCalibrator:
    """Scan labelled examples and calibrate the shield's aggregate score.

    Fit on a *held-out* set whenever possible — calibrating on the same data
    the signatures were tuned against overstates the calibration quality.
    """
    from ..core.types import Direction

    scores: list[float] = []
    labels: list[int] = []
    for ex in examples:
        result = shield.scan(ex.text, direction=Direction.INPUT)
        scores.append(result.score)
        labels.append(1 if ex.is_attack else 0)
    calibrator = fit_isotonic(scores, labels)
    calibrator.meta["dataset"] = dataset
    return calibrator
