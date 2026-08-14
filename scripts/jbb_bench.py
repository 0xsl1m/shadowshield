"""JailbreakBench (JBB-Behaviors) detection benchmark for ShadowShield.

Dataset: JailbreakBench/JBB-Behaviors (gated; HF token from the vault)
  - harmful split: 100 harmful goals (sourced from HarmBench + AdvBench)
  - benign split:  100 benign goals (matched categories)

Framing: ShadowShield is a prompt-injection / agent-safety guard, not a
content moderator. JBB harmful goals are mostly *direct* harmful requests
rather than injections, so this measures out-of-distribution safety coverage:
how much of a canonical harmful-behavior suite the shipped deterministic
stack flags, and at what benign false-positive cost. Injection-specific
attack success is covered by AgentDojo / InjecAgent / BIPIA.

Config: Shield.for_mode("balanced") — the shipped default deterministic stack.
Token pulled in-process from the vault; never printed.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path

VAULT = Path.home() / ".openclaw-vault" / "vault-local.py"
OUT = Path(__file__).resolve().parent.parent / "jbb_bench_results.json"


def hf_token() -> str:
    return subprocess.run(
        [sys.executable, str(VAULT), "get", "HF_FULLACCESS", "--quiet"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def main() -> None:
    os.environ["HF_TOKEN"] = hf_token()
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["DATASETS_DISABLE_PROGRESS_BARS"] = "1"

    from datasets import load_dataset

    from shadowshield import Shield
    from shadowshield.eval.dataset import EvalExample
    from shadowshield.eval.harness import evaluate_shield

    ds = load_dataset("JailbreakBench/JBB-Behaviors", "behaviors")
    examples = [
        EvalExample(text=row["Goal"], label=1, category=f"harmful/{row['Category']}")
        for row in ds["harmful"]
    ] + [
        EvalExample(text=row["Goal"], label=0, category=f"benign/{row['Category']}")
        for row in ds["benign"]
    ]
    print(f"jbb-behaviors: {len(ds['harmful'])} harmful + {len(ds['benign'])} benign")

    configs: dict[str, object] = {
        # Shipped default: deterministic stack only.
        "balanced_deterministic": lambda: Shield.for_mode("balanced"),
        # + multilingual mDeBERTa prompt-injection classifier.
        "plus_classifier_mdeberta": lambda: Shield(
            use_transformer="proventra/mdeberta-v3-base-prompt-injection"
        ),
        # + Meta Llama-Prompt-Guard-2-22M (gated; detects jailbreak+injection).
        "plus_prompt_guard_2_22m": lambda: Shield(
            use_transformer="meta-llama/Llama-Prompt-Guard-2-22M"
        ),
    }

    results: dict[str, dict] = {}
    for name, build in configs.items():
        shield = build()  # type: ignore[operator]
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rep = evaluate_shield(shield, examples, warmup=True)
        d = rep.to_dict()
        results[name] = d
        print(
            f"== {name} (n={d['n']}) recall={d['recall_detection_rate']:.4f} "
            f"FPR={d['false_positive_rate']:.4f} precision={d['precision']:.4f} "
            f"confusion={d['confusion']} p50={d['latency_ms']['p50']}ms "
            f"p95={d['latency_ms']['p95']}ms reliable={d['runtime']['reliable']}"
        )

    OUT.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"results written to {OUT.name}")


if __name__ == "__main__":
    main()
