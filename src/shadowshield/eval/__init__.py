"""Evaluation & benchmarking — measure detection quality and latency.

Run the bundled offline benchmark in three lines::

    import shadowshield as ss
    from shadowshield.eval import evaluate_shield, load_builtin
    report = evaluate_shield(ss.Shield.for_mode("balanced"), load_builtin())
    print(report.format_text())

or from the CLI: ``shadowshield benchmark``.
"""

from .dataset import (
    EvalExample,
    load_builtin,
    load_csv,
    load_huggingface,
    load_jsonl,
)
from .harness import BenchmarkReport, CategoryStat, evaluate_shield

__all__ = [
    "EvalExample",
    "load_builtin",
    "load_jsonl",
    "load_csv",
    "load_huggingface",
    "evaluate_shield",
    "BenchmarkReport",
    "CategoryStat",
]
