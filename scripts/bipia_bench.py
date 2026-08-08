"""BIPIA detection eval — faithful composition, local classification.

Attacks are inserted into task contexts exactly as BIPIA does
(end / start / middle, rotated). ShadowShield scans the composed text;
clean contexts measure FPR. Email + table + code tasks (WebQA/XSum
contexts need external datasets and are excluded — documented).
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BIPIA = ROOT / "_bench" / "BIPIA"  # download from github.com/microsoft/BIPIA benchmark/
OUT = ROOT / "_bench" / "bipia_results.json"
N_CONTEXTS = {"email": 100, "table": 100, "code": 50}


def insert_end(ctx: str, atk: str) -> str:
    return f"{ctx}\n{atk}"


def insert_start(ctx: str, atk: str) -> str:
    return f"{atk}\n{ctx}"


def insert_middle(ctx: str, atk: str) -> str:
    mid = len(ctx) // 2
    return f"{ctx[:mid]}\n{atk}\n{ctx[mid:]}"


INSERTERS = [insert_end, insert_start, insert_middle]


def flat_attacks(path: Path) -> list[str]:
    raw = json.loads(path.read_text())
    return [s for v in raw.values() for s in v]


def main() -> None:
    from shadowshield import Shield
    from shadowshield.eval.dataset import EvalExample
    from shadowshield.eval.harness import evaluate_shield

    results: dict[str, dict] = {}
    for task, n in N_CONTEXTS.items():
        contexts = []
        for line in BIPIA.joinpath(f"{task}-test.jsonl").read_text(encoding="utf-8").splitlines()[:n]:
            ctx = json.loads(line)["context"]
            contexts.append(ctx if isinstance(ctx, str) else json.dumps(ctx, ensure_ascii=False))
        attack_file = "code_attack_test.json" if task == "code" else "text_attack_test.json"
        attacks = flat_attacks(BIPIA / attack_file)

        examples: list[EvalExample] = []
        for i, ctx in enumerate(contexts):
            atk = attacks[i % len(attacks)]
            composed = INSERTERS[i % 3](ctx, atk)
            examples.append(EvalExample(text=composed, label=1, category=f"{task}_ipi"))
        for ctx in contexts:
            examples.append(EvalExample(text=ctx, label=0, category=f"{task}_clean"))

        for pred_name, predicate in (("any_threat", None), ("block_only", lambda r: r.blocked)):
            shield = Shield.for_mode("balanced")
            buf = io.StringIO()
            kwargs = {} if predicate is None else {"predicate": predicate}
            with contextlib.redirect_stdout(buf):
                rep = evaluate_shield(shield, examples, warmup=True, **kwargs)
            results[f"bipia_{task}_{pred_name}"] = rep.to_dict()
            d = results[f"bipia_{task}_{pred_name}"]
            print(f"== bipia_{task} [{pred_name}] (n={d['n']}) recall={d['recall_detection_rate']:.4f} "
                  f"FPR={d['false_positive_rate']:.4f} confusion={d['confusion']}", flush=True)

    OUT.write_text(json.dumps(results, indent=2))
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
