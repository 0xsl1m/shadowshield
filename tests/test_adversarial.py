"""Regression checks for the curated adversarial benchmark."""

from __future__ import annotations

import shadowshield as ss
from shadowshield.eval import evaluate_shield, load_adversarial


def test_adversarial_set_loads() -> None:
    ex = load_adversarial()
    assert len(ex) == 36
    assert sum(1 for e in ex if e.is_attack) == 18
    assert sum(1 for e in ex if not e.is_attack) == 18


def test_adversarial_curated_regression_baseline() -> None:
    rep = evaluate_shield(ss.Shield.for_mode("balanced"), load_adversarial())
    assert rep.n == 36
    assert (rep.tp, rep.fp, rep.tn, rep.fn) == (18, 0, 18, 0)
