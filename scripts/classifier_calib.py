"""Offline calibration for the classifier tranche (zero LLM-API cost).

Three measurements, all from cached data and logged trajectories:

1. **InjecAgent residual coverage** — over the published sanitize-arm results
   (``_bench/InjecAgent/results_ss_sanitized/``), how many *successful* attacks
   (the residual ASR) would the transformer classifier flag on the exact text
   the agent saw? Those are the cases a classifier-informed arm converts to
   full redaction. Also counts non-succ cases the classifier flags (behavior
   changes that need live re-running).

2. **Benign false-positive rate** — classifier attack-probability over
   NotInject (n=339), LLMail FP emails (n=203), and deepset benign, so the
   threshold can be chosen at ~0% FPR.

3. **AgentDojo trajectory replay** — over the logged no-defense traces in
   ``agentdojo_runs/``, scan every tool output in order. An abort-defense
   prevents the attack iff any tool output is flagged; a utility run is broken
   iff any tool output is flagged on a clean trajectory. Validates the method
   by replaying the *deterministic* shield against the published defended
   numbers before trusting the classifier predictions.

Classifier probabilities are computed once per text; every threshold in
``THRESHOLDS`` is then evaluated from the stored probabilities.

Usage (from repo root, venv python):
    python scripts/classifier_calib.py --part injecagent
    python scripts/classifier_calib.py --part benign
    python scripts/classifier_calib.py --part agentdojo
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IA_RESULTS = ROOT / "_bench" / "InjecAgent" / "results_ss_sanitized"
ADOJO_RUNS = ROOT / "agentdojo_runs"
BASELINE_DIR = "gpt-4o-mini-2024-07-18 no-defense"
OUT = ROOT / "classifier_calib_results.json"

MODEL = "proventra/mdeberta-v3-base-prompt-injection"
THRESHOLDS = [0.5, 0.7, 0.8, 0.9, 0.95, 0.99]

_ATTACK_LABELS = {"INJECTION", "JAILBREAK", "LABEL_1", "1", "UNSAFE", "MALICIOUS"}

CACHE = ROOT / "classifier_calib_cache.json"


def classifier_probs(texts: list[str], batch: int = 32, cache_key: str | None = None) -> list[float]:
    """Attack-class probability per text using the tranche classifier.

    Checkpointed to ``classifier_calib_cache.json`` after every batch so a
    300 s-capped shell call can be re-run and resume where it stopped.
    """
    cache: dict[str, list[float]] = json.loads(CACHE.read_text()) if CACHE.exists() else {}
    done = cache.get(cache_key or "", []) if cache_key else []
    if len(done) >= len(texts):
        print(f"  cache hit: {len(done)}/{len(texts)}")
        return done[: len(texts)]

    import torch
    from transformers import pipeline

    torch.set_num_threads(os.cpu_count() or 4)
    clf = pipeline(
        task="text-classification",
        model=MODEL,
        truncation=True,
        max_length=512,
        batch_size=batch,
    )
    probs: list[float] = list(done)
    for i in range(len(probs), len(texts), batch):
        chunk = texts[i : i + batch]
        preds = clf(chunk)
        for pred in preds:
            label = str(pred["label"]).upper()
            score = float(pred["score"])
            probs.append(score if label in _ATTACK_LABELS else 1.0 - score)
        if cache_key:
            cache[cache_key] = probs
            CACHE.write_text(json.dumps(cache))
        print(f"  classified {min(i + batch, len(texts))}/{len(texts)}", flush=True)
    return probs


def at_thresholds(probs: list[float]) -> dict[str, float]:
    """Fraction of texts flagged at each threshold."""
    return {str(t): sum(p >= t for p in probs) / max(len(probs), 1) for t in THRESHOLDS}


def deterministic_shield():
    from shadowshield import Shield

    return Shield.for_mode("balanced")


def scan_det(shield, text: str) -> bool:
    """Mirror the AgentDojo adapter: abort iff the scan is not safe (decision),
    not merely when any low-severity flag exists."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        res = shield.scan(text)
    return not res.is_safe


# --------------------------------------------------------------------- #
# Part 1: InjecAgent residual coverage
# --------------------------------------------------------------------- #
def part_injecagent() -> dict:
    items: list[dict] = []
    for attack in ("dh", "ds"):
        path = IA_RESULTS / f"test_cases_{attack}_enhanced.jsonl"
        for line in path.read_text().splitlines():
            item = json.loads(line)
            if attack == "dh":
                succ = item.get("eval") == "succ"
            else:
                succ = item.get("eval Step 2") == "succ"
            items.append(
                {
                    "attack": attack,
                    "idx": item["_idx"],
                    "succ": succ,
                    "valid": item.get("eval") != "invalid",
                    "det_blocked": bool(item.get("defense_blocked")),
                    "text": item["Tool Response"],  # sanitized text the agent saw
                }
            )
    print(f"injecagent: {len(items)} cases "
          f"({sum(i['succ'] for i in items)} succ = residual ASR population)")

    texts = [i["text"] for i in items]
    probs = classifier_probs(texts, cache_key="injecagent")
    for item, p in zip(items, probs, strict=True):
        item["clf_prob"] = round(p, 4)

    succ = [i for i in items if i["succ"]]
    nonsucc_valid = [i for i in items if not i["succ"] and i["valid"]]
    out = {
        "n_cases": len(items),
        "n_succ_residual": len(succ),
        "residual_coverage_by_threshold": at_thresholds([i["clf_prob"] for i in succ]),
        "nonsucc_valid_flagrate_by_threshold": at_thresholds(
            [i["clf_prob"] for i in nonsucc_valid]
        ),
        "cases": [
            {k: i[k] for k in ("attack", "idx", "succ", "valid", "det_blocked", "clf_prob")}
            for i in items
        ],
    }
    print("  residual coverage:",
          json.dumps(out["residual_coverage_by_threshold"], indent=2))
    print("  non-succ valid flag-rate:",
          json.dumps(out["nonsucc_valid_flagrate_by_threshold"], indent=2))
    return out


# --------------------------------------------------------------------- #
# Part 2: benign FP
# --------------------------------------------------------------------- #
def part_benign() -> dict:
    import os
    import subprocess

    os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
    os.environ.setdefault("DATASETS_DISABLE_PROGRESS_BARS", "1")
    token = subprocess.run(
        [sys.executable, str(Path.home() / ".openclaw-vault" / "vault-local.py"),
         "get", "HF_FULLACCESS", "--quiet"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    os.environ["HF_TOKEN"] = token

    corpora: dict[str, list[str]] = {}

    from datasets import load_dataset

    ni = load_dataset("leolee99/NotInject")
    corpora["notinject"] = [
        row["prompt"]
        for split in ("NotInject_one", "NotInject_two", "NotInject_three")
        for row in ni[split]
    ]

    from huggingface_hub import hf_hub_download

    fp_path = hf_hub_download(
        "microsoft/llmail-inject-challenge",
        "data/emails_for_fp_tests.json",
        repo_type="dataset", token=token,
    )
    corpora["llmail_fp_emails"] = json.loads(Path(fp_path).read_text(encoding="utf-8"))

    ds = load_dataset("deepset/prompt-injections")
    corpora["deepset_benign"] = [r["text"] for r in ds["test"] if r["label"] == 0]

    out: dict[str, dict] = {}
    for name, texts in corpora.items():
        print(f"benign corpus {name}: n={len(texts)}")
        probs = classifier_probs(texts, cache_key=f"benign_{name}")
        out[name] = {"n": len(texts), "fpr_by_threshold": at_thresholds(probs)}
        print(f"  FPR: {json.dumps(out[name]['fpr_by_threshold'], indent=2)}")
    return out


# --------------------------------------------------------------------- #
# Part 3: AgentDojo replay
# --------------------------------------------------------------------- #
def _tool_texts(messages: list[dict]) -> list[str]:
    texts: list[str] = []
    for m in messages:
        if m.get("role") != "tool":
            continue
        content = m.get("content")
        if isinstance(content, list):
            texts.append(
                "\n".join(str(c.get("content", "")) for c in content if isinstance(c, dict))
            )
        elif isinstance(content, str):
            texts.append(content)
    return texts


def part_agentdojo() -> dict:
    shield = deterministic_shield()
    suites: dict[str, dict] = {}
    base = ADOJO_RUNS / BASELINE_DIR
    for suite_dir in sorted(p for p in base.iterdir() if p.is_dir()):
        suite = suite_dir.name
        attack_traces = sorted(suite_dir.glob("*/important_instructions/*.json"))
        utility_traces = sorted(suite_dir.glob("*/none/none.json"))

        # --- attack replay ---
        attack_rows = []
        all_texts: list[str] = []
        spans: list[tuple[int, int]] = []
        det_prevented = 0
        for tp in attack_traces:
            trace = json.loads(tp.read_text())
            texts = _tool_texts(trace["messages"])
            det_flags = [scan_det(shield, t) for t in texts]
            det_prevented += int(any(det_flags))
            start = len(all_texts)
            all_texts.extend(texts)
            spans.append((start, len(all_texts)))
            attack_rows.append(
                {
                    "trace": str(tp.relative_to(base)),
                    "baseline_security": bool(trace["security"]),
                    "det_prevented": any(det_flags),
                }
            )
        print(f"{suite}: {len(attack_rows)} attack traces, "
              f"{len(all_texts)} tool outputs; det replay prevented {det_prevented}")
        probs = classifier_probs(all_texts, cache_key=f"agentdojo_{suite}_attack") if all_texts else []
        for row, (s, e) in zip(attack_rows, spans, strict=True):
            row["clf_max_prob"] = round(max(probs[s:e], default=0.0), 4)

        # --- utility replay ---
        util_rows = []
        util_texts: list[str] = []
        util_spans: list[tuple[int, int]] = []
        det_broken = 0
        for tp in utility_traces:
            trace = json.loads(tp.read_text())
            texts = _tool_texts(trace["messages"])
            det_flags = [scan_det(shield, t) for t in texts]
            det_broken += int(any(det_flags))
            start = len(util_texts)
            util_texts.extend(texts)
            util_spans.append((start, len(util_texts)))
            util_rows.append(
                {
                    "trace": str(tp.relative_to(base)),
                    "baseline_utility": bool(trace["utility"]),
                    "det_would_abort": any(det_flags),
                }
            )
        print(f"{suite}: {len(util_rows)} utility traces, "
              f"{len(util_texts)} tool outputs; det replay broke {det_broken}")
        uprobs = classifier_probs(util_texts, cache_key=f"agentdojo_{suite}_util") if util_texts else []
        for row, (s, e) in zip(util_rows, util_spans, strict=True):
            row["clf_max_prob"] = round(max(uprobs[s:e], default=0.0), 4)

        suites[suite] = {
            "n_attack": len(attack_rows),
            "n_utility": len(util_rows),
            "baseline_security_rate": (
                sum(r["baseline_security"] for r in attack_rows) / max(len(attack_rows), 1)
            ),
            "baseline_utility_rate": (
                sum(r["baseline_utility"] for r in util_rows) / max(len(util_rows), 1)
            ),
            "det_replay_prevented_rate": det_prevented / max(len(attack_rows), 1),
            "det_replay_utility_break_rate": det_broken / max(len(util_rows), 1),
            "clf_predicted_security_by_threshold": {
                str(t): (
                    sum(r["baseline_security"] or r["clf_max_prob"] >= t for r in attack_rows)
                    / max(len(attack_rows), 1)
                )
                for t in THRESHOLDS
            },
            "clf_predicted_utility_by_threshold": {
                str(t): (
                    sum(
                        r["baseline_utility"] and r["clf_max_prob"] < t for r in util_rows
                    )
                    / max(len(util_rows), 1)
                )
                for t in THRESHOLDS
            },
            "attack_traces": attack_rows,
            "utility_traces": util_rows,
        }
        print(f"  clf predicted security: "
              f"{json.dumps(suites[suite]['clf_predicted_security_by_threshold'], indent=2)}")
        print(f"  clf predicted utility: "
              f"{json.dumps(suites[suite]['clf_predicted_utility_by_threshold'], indent=2)}")
    return suites


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--part", choices=["injecagent", "benign", "agentdojo"], required=True)
    args = ap.parse_args()

    result = {"model": MODEL, "thresholds": THRESHOLDS}
    existing = json.loads(OUT.read_text()) if OUT.exists() else {}
    result = {**existing, **result}

    if args.part == "injecagent":
        result["injecagent"] = part_injecagent()
    elif args.part == "benign":
        result["benign"] = part_benign()
    else:
        result["agentdojo"] = part_agentdojo()

    OUT.write_text(json.dumps(result, indent=2))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
