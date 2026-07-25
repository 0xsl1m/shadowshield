"""Integrity and frozen-result checks for independent generalization snapshots."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from importlib import resources
from typing import Any

import pytest

import shadowshield as ss
from shadowshield.eval import EvalExample, evaluate_shield, load_generalization

_CATEGORIES = {
    "fictional_roleplay_hidden_instruction_extraction",
    "named_unrestricted_jailbreak_persona",
    "forged_role_transition_frame",
    "instruction_priority_override",
    "ai_privileged_mode_unlock",
}
_SNAPSHOT_SHA256 = {
    "generalization_benchmark_v1.jsonl": (
        "b3281ba1a42d266bb930bbb41943016d47b38dbc822ff7cff5131f3448a0248f"
    ),
    "generalization_benchmark_v2.jsonl": (
        "aa8b8c81c00a55bb65180e15ff743b6241d24845b3886e8e60b52b9b23db47fa"
    ),
}


def _load_snapshot(name: str) -> tuple[list[EvalExample], list[dict[str, Any]]]:
    data = resources.files("shadowshield.eval.data").joinpath(name)
    encoded = data.read_bytes()
    assert hashlib.sha256(encoded).hexdigest() == _SNAPSHOT_SHA256[name]
    rows = [json.loads(line) for line in encoded.decode("utf-8").splitlines()]
    examples = [
        EvalExample(text=row["text"], label=int(row["label"]), category=row["category"])
        for row in rows
    ]
    return examples, rows


def test_generalization_benchmark_v1_integrity() -> None:
    examples, rows = _load_snapshot("generalization_benchmark_v1.jsonl")

    assert len(examples) == 30
    assert sum(example.is_attack for example in examples) == 15
    assert Counter(example.category for example in examples) == dict.fromkeys(_CATEGORIES, 6)
    assert {row["provenance"] for row in rows} == {"independent_blind_v1"}


def test_generalization_benchmark_v2_integrity() -> None:
    examples, rows = _load_snapshot("generalization_benchmark_v2.jsonl")

    assert len(examples) == 20
    assert sum(example.is_attack for example in examples) == 10
    assert Counter(example.category for example in examples) == dict.fromkeys(_CATEGORIES, 4)
    assert {row["provenance"] for row in rows} == {"independent_blind_v2"}


def test_public_generalization_loader() -> None:
    assert len(load_generalization("v1")) == 30
    assert len(load_generalization("v2")) == 20
    assert len(load_generalization("all")) == 50
    with pytest.raises(ValueError, match="snapshot"):
        load_generalization("unknown")


def test_generalization_snapshots_record_current_core_limit() -> None:
    # These are anti-gaming snapshots, not quality gates. Update them consciously
    # only when a separately justified detector change alters generalization.
    v1, _ = _load_snapshot("generalization_benchmark_v1.jsonl")
    v2, _ = _load_snapshot("generalization_benchmark_v2.jsonl")
    shield = ss.Shield.for_mode("balanced")

    report_v1 = evaluate_shield(shield, v1)
    report_v2 = evaluate_shield(shield, v2)

    assert (report_v1.tp, report_v1.fp, report_v1.tn, report_v1.fn) == (4, 2, 13, 11)
    assert (report_v2.tp, report_v2.fp, report_v2.tn, report_v2.fn) == (0, 1, 9, 10)
