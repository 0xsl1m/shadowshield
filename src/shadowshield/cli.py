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
import os
import sys
from collections.abc import Sequence
from typing import Any

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

    # Exit non-zero when the payload is not safe - handy in shell pipelines/CI.
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


def _cmd_schema(args: argparse.Namespace) -> int:
    # The config is a Pydantic model, so its JSON Schema comes for free - useful for
    # editor validation, CI checks, and generating config UIs.
    print(json.dumps(ShieldConfig.model_json_schema(), indent=2))
    return 0


def _cmd_owasp(args: argparse.Namespace) -> int:
    from .core.coverage import format_coverage_text, owasp_coverage

    if args.json:
        print(json.dumps(owasp_coverage(), indent=2))
    else:
        print(format_coverage_text())
    return 0


def _resolve_benchmark_examples(args: argparse.Namespace) -> tuple[list[Any], str]:
    """Shared dataset resolution for ``benchmark`` and ``calibrate``."""
    from .eval import (
        load_adversarial,
        load_builtin,
        load_csv,
        load_generalization,
        load_jsonl,
    )

    if args.dataset:
        loader = load_csv if args.dataset.lower().endswith(".csv") else load_jsonl
        return loader(args.dataset), args.dataset
    if args.hf:
        from .eval import load_huggingface

        return load_huggingface(args.hf, split=args.split), args.hf
    if args.adversarial:
        return load_adversarial(), "adversarial"
    if args.generalization:
        return load_generalization(args.generalization), f"generalization-{args.generalization}"
    return load_builtin(), "builtin"


def _benchmark_shield(args: argparse.Namespace, *, calibrated: bool) -> Any:
    benchmark_config = ShieldConfig.for_mode(Mode(args.mode))
    # Audit output is unrelated to detector quality, distorts latency, and can
    # corrupt the benchmark command's JSON stdout. Benchmark reports still
    # retain bounded runtime-integrity counters.
    benchmark_config.logging.enabled = False
    calibrator = None
    if calibrated and args.calibration:
        from .core.calibration import IsotonicCalibrator

        calibrator = IsotonicCalibrator.load(args.calibration)
    return Shield(
        benchmark_config,
        use_transformer=args.transformer or False,
        calibrator=calibrator,
    )


def _cmd_benchmark(args: argparse.Namespace) -> int:
    from .eval import evaluate_shield

    examples, src = _resolve_benchmark_examples(args)
    # Model/index initialization is deliberately outside timed scans. Any
    # warmup, readiness, or per-scan detector failure makes the benchmark
    # explicitly unreliable and produces a non-zero exit status.
    shield = _benchmark_shield(args, calibrated=True)
    report = evaluate_shield(shield, examples, warmup=True)

    raw_report = None
    if args.calibration:
        raw_report = evaluate_shield(_benchmark_shield(args, calibrated=False), examples)

    if args.json:
        out = report.to_dict()
        if raw_report is not None:
            out = {"calibrated": out, "raw": raw_report.to_dict()}
        print(json.dumps(out, indent=2))
    else:
        print(f"dataset: {src}   mode: {args.mode}")
        if raw_report is not None:
            print("== raw scores ==")
            print(raw_report.format_text())
            print("== calibrated scores ==")
        print(report.format_text())
    return 0 if report.reliable else 1


def _cmd_calibrate(args: argparse.Namespace) -> int:
    from .core.calibration import fit_from_examples

    examples, src = _resolve_benchmark_examples(args)
    shield = _benchmark_shield(args, calibrated=False)
    calibrator = fit_from_examples(shield, examples, dataset=src)
    calibrator.save(args.out)
    print(
        f"calibrated on {src}: n={calibrator.meta['n']} "
        f"positives={calibrator.meta['positives']} knots={len(calibrator.xs)} -> {args.out}"
    )
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    if args.control:
        from .control import serve_control

        print(
            f"ShadowShield control dashboard on http://{args.host}:{args.port}  (mode={args.mode})"
        )
        serve_control(
            host=args.host,
            port=args.port,
            mode=args.mode,
            api_keys=args.api_key,
            admin_keys=args.admin_key,
            cors_origins=args.cors_origin,
            policy_key=args.policy_key,
            policy_state_path=args.policy_state_path,
            policy_state_key=args.policy_state_key,
        )
        return 0

    from .server import serve

    print(f"ShadowShield server on http://{args.host}:{args.port}  (mode={args.mode})")
    serve(
        host=args.host,
        port=args.port,
        mode=args.mode,
        api_keys=args.api_key,
        cors_origins=args.cors_origin,
    )
    return 0


def _cmd_proxy(args: argparse.Namespace) -> int:
    from .proxy import serve_proxy

    print(
        f"ShadowShield proxy on http://{args.host}:{args.port} -> {args.upstream}  "
        f"(mode={args.mode})"
    )
    serve_proxy(
        args.upstream,
        host=args.host,
        port=args.port,
        mode=args.mode,
        api_keys=args.api_key,
        scan_response=not args.no_scan_response,
        timeout_seconds=args.timeout,
    )
    return 0


def _cmd_migrate_policy_state(args: argparse.Namespace) -> int:
    from .control import migrate_policy_state

    old_key = args.old_key or os.environ.get("SHADOWSHIELD_POLICY_KEY")
    new_key = args.new_key or os.environ.get("SHADOWSHIELD_POLICY_STATE_KEY")
    if not old_key or not new_key:
        print(
            "error: migration requires the old policy key and new state key; "
            "prefer SHADOWSHIELD_POLICY_KEY and SHADOWSHIELD_POLICY_STATE_KEY",
            file=sys.stderr,
        )
        return 2
    try:
        backup = migrate_policy_state(
            args.path,
            old_key=old_key,
            new_key=new_key,
            backup_path=args.backup,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"migrated policy state: {args.path}")
    print(f"verified backup: {backup}")
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

    schema = sub.add_parser("schema", help="print the config JSON Schema (for tooling/CI)")
    schema.set_defaults(func=_cmd_schema)

    owasp = sub.add_parser("owasp", help="show OWASP LLM Top 10 (2025) coverage")
    owasp.add_argument("--json", action="store_true", help="emit JSON")
    owasp.set_defaults(func=_cmd_owasp)

    bench = sub.add_parser("benchmark", help="benchmark detection quality + latency")
    dataset_source = bench.add_mutually_exclusive_group()
    dataset_source.add_argument(
        "--dataset", default=None, help="path to a JSONL/CSV dataset (default: bundled benchmark)"
    )
    dataset_source.add_argument(
        "--hf",
        default=None,
        help="HuggingFace dataset id (needs 'datasets')",
    )
    dataset_source.add_argument(
        "--adversarial",
        action="store_true",
        help="use the curated adversarial regression set",
    )
    dataset_source.add_argument(
        "--generalization",
        choices=["v1", "v2", "v3", "v4", "all"],
        default=None,
        help="use an independently authored blind semantic snapshot",
    )
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
    bench.add_argument(
        "--calibration",
        default=None,
        metavar="PATH",
        help="apply a fitted calibration artifact (shadowshield calibrate) and "
        "print a raw-vs-calibrated comparison",
    )
    bench.set_defaults(func=_cmd_benchmark)

    cal = sub.add_parser(
        "calibrate",
        help="fit an isotonic score calibrator on a labelled dataset",
    )
    cal_source = cal.add_mutually_exclusive_group()
    cal_source.add_argument("--dataset", default=None, help="path to a JSONL/CSV dataset")
    cal_source.add_argument("--hf", default=None, help="HuggingFace dataset id (needs 'datasets')")
    cal_source.add_argument(
        "--adversarial", action="store_true", help="use the curated adversarial regression set"
    )
    cal_source.add_argument(
        "--generalization",
        choices=["v1", "v2", "v3", "v4", "all"],
        default=None,
        help="use an independently authored blind semantic snapshot",
    )
    cal.add_argument("--split", default="test", help="HF split (default: test)")
    cal.add_argument("--mode", choices=[m.value for m in Mode], default=Mode.BALANCED.value)
    cal.add_argument(
        "--transformer",
        nargs="?",
        const=True,
        default=False,
        help="add the ML classifier (optionally a model id); needs 'transformers'",
    )
    cal.add_argument("--out", required=True, metavar="PATH", help="calibration artifact path")
    cal.set_defaults(func=_cmd_calibrate)

    migrate = sub.add_parser(
        "migrate-policy-state",
        help="offline re-key of a stopped 0.6.0 durable policy-state file",
    )
    migrate.add_argument("--path", required=True, metavar="PATH")
    migrate.add_argument(
        "--backup",
        default=None,
        metavar="PATH",
        help="exclusive backup path (default: PATH.pre-0.6.1.bak)",
    )
    migrate.add_argument(
        "--old-key",
        default=None,
        metavar="KEY",
        help="legacy state key; prefer SHADOWSHIELD_POLICY_KEY to avoid shell history",
    )
    migrate.add_argument(
        "--new-key",
        default=None,
        metavar="KEY",
        help="new 32+ byte key; prefer SHADOWSHIELD_POLICY_STATE_KEY",
    )
    migrate.set_defaults(func=_cmd_migrate_policy_state)

    serve_p = sub.add_parser("serve", help="run the HTTP server + dashboard")
    serve_p.add_argument("--host", default="127.0.0.1")
    serve_p.add_argument("--port", type=int, default=8000)
    serve_p.add_argument("--mode", choices=[m.value for m in Mode], default=Mode.BALANCED.value)
    serve_p.add_argument(
        "--control",
        action="store_true",
        help="serve the full control dashboard (live feed, metrics, config, benchmark)",
    )
    serve_p.add_argument(
        "--api-key",
        action="append",
        default=None,
        metavar="KEY",
        help="require this API key (X-API-Key/Bearer); repeatable. Also SHADOWSHIELD_API_KEY",
    )
    serve_p.add_argument(
        "--admin-key",
        action="append",
        default=None,
        metavar="KEY",
        help=(
            "independent key for control, metrics, policy, and benchmark routes. "
            "Also SHADOWSHIELD_ADMIN_KEY"
        ),
    )
    serve_p.add_argument(
        "--cors-origin",
        action="append",
        default=None,
        metavar="ORIGIN",
        help="allow this browser origin (repeatable). Also SHADOWSHIELD_CORS_ORIGINS",
    )
    serve_p.add_argument(
        "--policy-key",
        default=None,
        metavar="KEY",
        help=(
            "HMAC key required to accept pushed policy bundles (control mode). "
            "Also SHADOWSHIELD_POLICY_KEY"
        ),
    )
    serve_p.add_argument(
        "--policy-state-path",
        default=None,
        metavar="PATH",
        help=(
            "durable policy anti-replay state file (control mode). "
            "Also SHADOWSHIELD_POLICY_STATE_PATH"
        ),
    )
    serve_p.add_argument(
        "--policy-state-key",
        default=None,
        metavar="KEY",
        help=(
            "independent HMAC key (at least 32 bytes) for durable policy state "
            "(control mode). Also SHADOWSHIELD_POLICY_STATE_KEY. Existing state "
            "authenticated with the policy signing key is not auto-migrated"
        ),
    )
    serve_p.set_defaults(func=_cmd_serve)

    proxy_p = sub.add_parser(
        "proxy",
        help="reverse-proxy guard in front of an OpenAI-compatible LLM endpoint",
    )
    proxy_p.add_argument(
        "--upstream",
        required=True,
        metavar="URL",
        help="base URL of the upstream API, e.g. https://api.openai.com",
    )
    proxy_p.add_argument("--host", default="127.0.0.1")
    proxy_p.add_argument("--port", type=int, default=8100)
    proxy_p.add_argument("--mode", choices=[m.value for m in Mode], default=Mode.BALANCED.value)
    proxy_p.add_argument(
        "--api-key",
        action="append",
        default=None,
        metavar="KEY",
        help="require this proxy access key (X-API-Key/Bearer); repeatable. "
        "Also SHADOWSHIELD_API_KEY. Upstream credentials travel in Authorization.",
    )
    proxy_p.add_argument(
        "--no-scan-response",
        action="store_true",
        help="scan requests only; forward completions unchecked",
    )
    proxy_p.add_argument(
        "--timeout",
        type=float,
        default=120.0,
        metavar="SECONDS",
        help="upstream request timeout (default: 120)",
    )
    proxy_p.set_defaults(func=_cmd_proxy)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
