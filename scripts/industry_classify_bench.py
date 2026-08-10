"""Industry-standard local classification benchmarks for ShadowShield.

Datasets:
  - leolee99/NotInject (339 benign prompts with trigger words) — over-defense FPR
  - microsoft/llmail-inject-challenge (sampled attack submissions + FP emails)

Config: Shield.for_mode("balanced") — the shipped default deterministic stack.
Token pulled in-process from the vault; never printed.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import random
import subprocess
import sys
from pathlib import Path

VAULT = Path.home() / ".openclaw-vault" / "vault-local.py"
OUT = Path(__file__).resolve().parent.parent / "industry_bench_results.json"
LLMAIL_ATTACK_SAMPLE = 2000
SEED = 42


def hf_token() -> str:
    return subprocess.run(
        [sys.executable, str(VAULT), "get", "HF_FULLACCESS", "--quiet"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def main() -> None:
    os.environ["HF_TOKEN"] = hf_token()
    os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
    os.environ["DATASETS_DISABLE_PROGRESS_BARS"] = "1"

    from shadowshield import Shield
    from shadowshield.eval.dataset import EvalExample
    from shadowshield.eval.harness import evaluate_shield

    results: dict[str, dict] = {}

    def run(name: str, examples: list[EvalExample]) -> None:
        shield = Shield.for_mode("balanced")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rep = evaluate_shield(shield, examples, warmup=True)
        results[name] = rep.to_dict()
        d = results[name]
        print(f"== {name} (n={d['n']}) recall={d['recall_detection_rate']:.4f} "
              f"FPR={d['false_positive_rate']:.4f} precision={d['precision']:.4f} "
              f"confusion={d['confusion']} p50={d['latency_ms']['p50']}ms "
              f"p95={d['latency_ms']['p95']}ms reliable={d['runtime']['reliable']}")

    # --- NotInject (all-benign over-defense eval) ---
    from datasets import load_dataset
    ni = load_dataset("leolee99/NotInject")
    examples = [
        EvalExample(text=row["prompt"], label=0, category=f"notinject_{split}")
        for split in ("NotInject_one", "NotInject_two", "NotInject_three")
        for row in ni[split]
    ]
    run("notinject_overdefense", examples)

    # --- LLMail-Inject (sampled real-world attacks + benign FP emails) ---
    from huggingface_hub import hf_hub_download
    p1 = hf_hub_download(
        "microsoft/llmail-inject-challenge",
        "data/labelled_unique_submissions_phase1.json",
        repo_type="dataset", token=os.environ["HF_TOKEN"],
    )
    subs = json.loads(Path(p1).read_text(encoding="utf-8"))
    attacks = [text for text, meta in subs.items()
               if str(meta.get("attack_attempt")) == "True"]
    rng = random.Random(SEED)
    attack_sample = rng.sample(attacks, min(LLMAIL_ATTACK_SAMPLE, len(attacks)))
    print(f"llmail: {len(attacks)} unique attacks in phase1, sampled {len(attack_sample)}")

    fp_path = hf_hub_download(
        "microsoft/llmail-inject-challenge",
        "data/emails_for_fp_tests.json",
        repo_type="dataset", token=os.environ["HF_TOKEN"],
    )
    benign = json.loads(Path(fp_path).read_text(encoding="utf-8"))

    examples = [EvalExample(text=t, label=1, category="llmail_attack") for t in attack_sample]
    examples += [EvalExample(text=t, label=0, category="llmail_benign") for t in benign]
    run("llmail_inject_challenge", examples)

    OUT.write_text(json.dumps(results, indent=2))
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
