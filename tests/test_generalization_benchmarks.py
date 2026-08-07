"""Integrity and frozen-result checks for independent generalization snapshots."""

from __future__ import annotations

import hashlib
import json
import unicodedata
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
_V3_CATEGORIES = {
    "code_and_serialized_data",
    "delimiter_and_role_boundaries",
    "multilingual_context_switch",
    "quoted_and_fictional_content",
    "retrieval_and_secret_access",
    "security_analysis_language",
    "semantic_instruction_hierarchy",
    "tool_and_metadata_output",
    "unicode_token_obfuscation",
    "untrusted_document_content",
}
_V4_CATEGORIES = {
    "blended_summarization",
    "blended_translation",
    "indirect_tool_result",
    "multilingual_direct",
    "multilingual_role",
    "semantic_authority",
    "semantic_extraction",
    "semantic_pretext",
    "semantic_urgency",
}
_SNAPSHOT_SHA256 = {
    "generalization_benchmark_v1.jsonl": (
        "b3281ba1a42d266bb930bbb41943016d47b38dbc822ff7cff5131f3448a0248f"
    ),
    "generalization_benchmark_v2.jsonl": (
        "aa8b8c81c00a55bb65180e15ff743b6241d24845b3886e8e60b52b9b23db47fa"
    ),
    "generalization_benchmark_v3.jsonl": (
        "2285031e8143572311a522a4b6ec1a39c96a34ac2b42785f17818e8a145342bf"
    ),
    "generalization_benchmark_v4.jsonl": (
        "9095f877c30d2c15f51831b3141c19037c7293b7df3ea3ebe957c57a880c7844"
    ),
}


def _load_snapshot(name: str) -> tuple[list[EvalExample], list[dict[str, Any]]]:
    data = resources.files("shadowshield.eval.data").joinpath(name)
    encoded = data.read_bytes()
    assert hashlib.sha256(encoded).hexdigest() == _SNAPSHOT_SHA256[name]
    assert not encoded.startswith(b"\xef\xbb\xbf")
    assert b"\r" not in encoded
    assert encoded.endswith(b"\n")
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


def test_generalization_benchmark_v3_integrity() -> None:
    examples, rows = _load_snapshot("generalization_benchmark_v3.jsonl")

    assert len(examples) == 40
    assert sum(example.is_attack for example in examples) == 20
    assert Counter(example.label for example in examples) == {0: 20, 1: 20}
    assert Counter(example.category for example in examples) == dict.fromkeys(_V3_CATEGORIES, 4)
    assert Counter((example.category, example.label) for example in examples) == {
        (category, label): 2 for category in _V3_CATEGORIES for label in (0, 1)
    }
    assert {row["provenance"] for row in rows} == {"independent_blind_v3"}
    assert all(set(row) == {"text", "label", "category", "provenance"} for row in rows)
    assert all(type(row["label"]) is int for row in rows)
    assert all(isinstance(row["text"], str) and row["text"].strip() for row in rows)


def test_generalization_benchmark_v4_integrity() -> None:
    examples, rows = _load_snapshot("generalization_benchmark_v4.jsonl")

    assert len(examples) == 58
    assert sum(example.is_attack for example in examples) == 29
    assert Counter(example.label for example in examples) == {0: 29, 1: 29}
    assert Counter((example.category, example.label) for example in examples) == {
        ("indirect_tool_result", label): 8 for label in (0, 1)
    } | {("multilingual_direct", label): 5 for label in (0, 1)} | {
        ("semantic_pretext", label): 5 for label in (0, 1)
    } | {("semantic_extraction", label): 4 for label in (0, 1)} | {
        ("multilingual_role", label): 3 for label in (0, 1)
    } | {
        (category, label): 1
        for category in (
            "semantic_authority",
            "blended_translation",
            "blended_summarization",
            "semantic_urgency",
        )
        for label in (0, 1)
    }
    assert {row["provenance"] for row in rows} == {"independent_blind_v4"}
    assert all(set(row) == {"text", "label", "category", "provenance"} for row in rows)
    assert all(type(row["label"]) is int for row in rows)
    assert all(isinstance(row["text"], str) and row["text"].strip() for row in rows)


def test_generalization_snapshots_have_unique_text() -> None:
    examples = [example for name in _SNAPSHOT_SHA256 for example in _load_snapshot(name)[0]]
    normalized = [
        "".join(
            char
            for char in unicodedata.normalize("NFKC", example.text).casefold()
            if char.isalnum()
        )
        for example in examples
    ]

    assert len({example.text for example in examples}) == len(examples)
    assert len(set(normalized)) == len(examples)


def test_public_generalization_loader() -> None:
    assert len(load_generalization("v1")) == 30
    assert len(load_generalization("v2")) == 20
    assert len(load_generalization("v3")) == 40
    assert len(load_generalization("v4")) == 58
    assert len(load_generalization("all")) == 148
    with pytest.raises(ValueError, match="snapshot"):
        load_generalization("unknown")


def test_generalization_snapshots_record_current_core_limit() -> None:
    # These are anti-gaming snapshots, not quality gates. Update them consciously
    # only when a separately justified detector change alters generalization.
    v1, _ = _load_snapshot("generalization_benchmark_v1.jsonl")
    v2, _ = _load_snapshot("generalization_benchmark_v2.jsonl")
    v3, _ = _load_snapshot("generalization_benchmark_v3.jsonl")
    v4, _ = _load_snapshot("generalization_benchmark_v4.jsonl")
    shield = ss.Shield.for_mode("balanced")

    report_v1 = evaluate_shield(shield, v1)
    report_v2 = evaluate_shield(shield, v2)
    report_v3 = evaluate_shield(shield, v3)
    report_v4 = evaluate_shield(shield, v4)
    report_all = evaluate_shield(shield, [*v1, *v2, *v3])

    assert (report_v1.tp, report_v1.fp, report_v1.tn, report_v1.fn) == (4, 2, 13, 11)
    assert (report_v2.tp, report_v2.fp, report_v2.tn, report_v2.fn) == (0, 1, 9, 10)
    assert (report_v3.tp, report_v3.fp, report_v3.tn, report_v3.fn) == (6, 6, 14, 14)
    assert (report_v4.tp, report_v4.fp, report_v4.tn, report_v4.fn) == (17, 2, 27, 12)
    assert (report_all.tp, report_all.fp, report_all.tn, report_all.fn) == (10, 9, 36, 35)
