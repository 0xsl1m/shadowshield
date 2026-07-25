"""The adversarial benchmark must load and yield honest (sub-100%) numbers."""

from __future__ import annotations

import shadowshield as ss
from shadowshield.eval import evaluate_shield, load_adversarial


def test_adversarial_set_loads() -> None:
    ex = load_adversarial()
    assert len(ex) == 36
    assert sum(1 for e in ex if e.is_attack) == 18
    assert sum(1 for e in ex if not e.is_attack) == 18


def test_adversarial_is_genuinely_harder_than_builtin() -> None:
    # The whole point of the adversarial set: it is NOT a 100%/0% marketing number.
    rep = evaluate_shield(ss.Shield.for_mode("balanced"), load_adversarial())
    assert rep.n == 36
    # core install (no ML layers) should miss at least one obfuscated/laundered attack
    assert rep.recall < 1.0
    # and the hard negatives should surface some over-defense
    assert rep.false_positive_rate > 0.0
    # but it must still be a useful detector, not random
    assert rep.recall > 0.5
