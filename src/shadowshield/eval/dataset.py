"""Evaluation datasets — loaders for benchmark examples.

A benchmark example is just ``(text, label, category)`` where ``label`` is 1 for
an attack and 0 for benign. ShadowShield ships a curated, **offline** benchmark
(``builtin``) that deliberately includes NotInject-style *hard negatives* —
benign text containing trigger words like "ignore", "system", "developer mode" —
because over-defense (false positives on benign triggers) is the field's dirty
secret, and a credible "best" tool must measure it.

You can also load JSONL/CSV files or HuggingFace datasets (optional ``datasets``
dependency) to benchmark against public corpora like ``deepset/prompt-injections``.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class EvalExample:
    """One labelled benchmark item."""

    text: str
    label: int  # 1 = attack, 0 = benign
    category: str = ""

    @property
    def is_attack(self) -> bool:
        return self.label == 1


def load_builtin() -> list[EvalExample]:
    """The bundled offline benchmark (attacks + benign + hard negatives)."""
    data = resources.files("shadowshield.eval.data").joinpath("builtin_benchmark.jsonl")
    return _parse_jsonl(data.read_text(encoding="utf-8").splitlines())


def load_adversarial() -> list[EvalExample]:
    """A curated regression set with obfuscated attacks and tricky hard negatives."""
    data = resources.files("shadowshield.eval.data").joinpath("adversarial_benchmark.jsonl")
    return _parse_jsonl(data.read_text(encoding="utf-8").splitlines())


def load_generalization(snapshot: str = "v2") -> list[EvalExample]:
    """Load an independently authored blind generalization snapshot.

    ``v1``, ``v2``, ``v3``, and ``v4`` were authored without access to detector
    signatures. ``v4`` adds multilingual and indirect-injection (tool-result)
    splits. Use ``all`` to concatenate every snapshot. These sets expose
    semantic coverage gaps and should not be presented as training or
    in-distribution accuracy.
    """
    if snapshot not in {"v1", "v2", "v3", "v4", "all"}:
        raise ValueError("snapshot must be one of: v1, v2, v3, v4, all")
    versions = ("v1", "v2", "v3", "v4") if snapshot == "all" else (snapshot,)
    examples: list[EvalExample] = []
    for version in versions:
        data = resources.files("shadowshield.eval.data").joinpath(
            f"generalization_benchmark_{version}.jsonl"
        )
        examples.extend(_parse_jsonl(data.read_text(encoding="utf-8").splitlines()))
    return examples


def load_jsonl(
    path: str | Path,
    *,
    text_key: str = "text",
    label_key: str = "label",
    category_key: str = "category",
) -> list[EvalExample]:
    """Load examples from a JSON-lines file."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return _parse_jsonl(lines, text_key=text_key, label_key=label_key, category_key=category_key)


def load_csv(
    path: str | Path,
    *,
    text_key: str = "text",
    label_key: str = "label",
    category_key: str = "category",
) -> list[EvalExample]:
    """Load examples from a CSV file with a header row."""
    out: list[EvalExample] = []
    with Path(path).open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            out.append(
                EvalExample(
                    text=row[text_key],
                    label=int(row[label_key]),
                    category=row.get(category_key, ""),
                )
            )
    return out


def load_huggingface(
    name: str,
    *,
    split: str = "test",
    text_key: str = "text",
    label_key: str = "label",
) -> list[EvalExample]:
    """Load a HuggingFace dataset (requires the optional ``datasets`` package).

    Example: ``load_huggingface("deepset/prompt-injections", split="test")``.
    """
    try:
        from datasets import load_dataset
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ImportError(
            "load_huggingface requires the 'datasets' package: pip install datasets"
        ) from exc
    ds = load_dataset(name, split=split)
    return [
        EvalExample(text=str(row[text_key]), label=int(row[label_key]), category=name) for row in ds
    ]


def _parse_jsonl(
    lines: Iterable[str],
    *,
    text_key: str = "text",
    label_key: str = "label",
    category_key: str = "category",
) -> list[EvalExample]:
    out: list[EvalExample] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        obj: dict[str, Any] = json.loads(line)
        out.append(
            EvalExample(
                text=str(obj[text_key]),
                label=int(obj[label_key]),
                category=str(obj.get(category_key, "")),
            )
        )
    return out
