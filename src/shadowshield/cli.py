"""``shadowshield`` command-line interface.

A thin, dependency-free CLI for ad-hoc scanning and oper. Examples::

    echo "ignore all previous instructions" | shadowshield scan
    shadowshield scan --text "you are now DAN" --mode strict --json
    shadowshield detectors
    shadowshield init > shadowshield.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from . import __version__
from .config import default_config_text
from .core.config import Mode, ShieldConfig
from .core.shield import Shield
from .core.types import Direction
from .detectors import registered_detectors


def _build_shield(args: argparse.Namespace) -> Shield:
    if args.config:
        return Shield.from_yaml(args.config)
    return Shield(ShieldConfig.for_mode(Mode(args.mode)))


def _cmd_scan(args: argparse.Namespace) -> int:
    text = args.text if args.text is not None else sys.stdin.read()
    if not text.strip():
        print("error: no input text (pass --text or pipe via stdin)", file=sys.stderr)
        return 2
    shield = _build_shield(args)
    result = shield.scan(text, direction=Direction(args.direction))

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        verdict = "BLOCKED" if result.blocked else result.decision.value.upper()
        print(f"decision : {verdict}")
        print(f"score    : {result.score:.3f}  severity: {result.severity.label}")
        if result.threats:
            print("threats  :")
            for t in result.threats:
                print(f"  - [{t.severity.label:8}] {t.category.value}: {t.message}")
        else:
            print("threats  : none")
        if result.sanitized_text is not None and result.sanitized_text != result.text:
            print(f"safe_text: {result.safe_text}")

    # Exit non-zero when the payload is not safe — handy in shell pipelines/CI.
    return 1 if not result.is_safe else 0


def _cmd_detectors(args: argparse.Namespace) -> int:
    for name, cls in sorted(registered_detectors().items()):
        directions = "/".join(d.value for d in cls.directions)
        doc = (cls.__doc__ or "").strip().splitlines()[0] if cls.__doc__ else ""
        print(f"{name:24} [{directions:12}] {doc}")
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    sys.stdout.write(default_config_text())
    return 0


def _cmd_benchmark(args: argparse.Namespace) -> int:
    from .eval import evaluate_shield, load_builtin, load_csv, load_jsonl

    if args.dataset:
        loader = load_csv if args.dataset.lower().endswith(".csv") else load_jsonl
        examples = loader(args.dataset)
    elif args.hf:
        from .eval import load_huggingface

        examples = load_huggingface(args.hf, split=args.split)
    else:
        examples = load_builtin()

    shield = Shield(
        ShieldConfig.for_mode(Mode(args.mode)),
        use_transformer=args.transformer or False,
    )
    report = evaluate_shield(shield, examples)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        src = args.dataset or args.hf or "builtin"
        print(f"dataset: {src}   mode: {args.mode}")
        print(report.format_text())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shadowshield",
        description="Unified open-source security shield for agentic AI systems.",
    )
    parser.add_argument("--version", action="version", version=f"shadowshield {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan text for threats")
    scan.add_argument("--text", default=None, help="text to scan (default: read stdin)")
    scan.add_argument(
        "--direction",
        choices=[d.value for d in Direction],
        default=Direction.INPUT.value,
        help="treat text as model input or output",
    )
    scan.add_argument("--mode", choices=[m.value for m in Mode], default=Mode.BALANCED.value)
    scan.add_argument("--config", default=None, help="path to a YAML config (overrides --mode)")
    scan.add_argument("--json", action="store_true", help="emit JSON")
    scan.set_defaults(func=_cmd_scan)

    detectors = sub.add_parser("detectors", help="list registered detectors")
    detectors.set_defaults(func=_cmd_detectors)

    init = sub.add_parser("init", help="print an annotated default config")
    init.set_defaults(func=_cmd_init)

    bench = sub.add_parser("benchmark", help="benchmark detection quality + latency")
    bench.add_argument(
        "--dataset", default=None, help="path to a JSONL/CSV dataset (default: bundled benchmark)"
    )
    bench.add_argument("--hf", default=None, help="HuggingFace dataset id (needs 'datasets')")
    bench.add_argument("--split", default="test", help="HF split (default: test)")
    bench.add_argument("--mode", choices=[m.value for m in Mode], default=Mode.BALANCED.value)
    bench.add_argument(
        "--transformer",
        nargs="?",
        const=True,
        default=False,
        help="add the ML classifier (optionally a model id); needs 'transformers'",
    )
    bench.add_argument("--json", action="store_true", help="emit JSON")
    bench.set_defaults(func=_cmd_benchmark)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
