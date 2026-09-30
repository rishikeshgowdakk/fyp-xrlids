"""Unified Phase 1 CLI.

    python -m xrlids.cli info
    python -m xrlids.cli compatibility
    python -m xrlids.cli verify-datasets
    python -m xrlids.cli audit --dataset cicids2017 --input <file.csv>
    python -m xrlids.cli smoke --rung R10

Commands that require real data fail with a clear DATA_NOT_AVAILABLE message rather than
producing placeholder numbers.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from xrlids import PROJECT_NAME, __version__
from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


def _registry():
    from xrlids.features.registry import load_feature_registry

    return load_feature_registry("configs/features/features.yaml")


def cmd_info(_args: argparse.Namespace) -> int:
    from xrlids.utils.env import environment_fingerprint

    registry = _registry()
    print(f"{PROJECT_NAME} (package xrlids {__version__})")
    print(json.dumps(environment_fingerprint(), indent=2, default=str))
    print(f"feature registry: version={registry.version} status={registry.status}")
    for rung, spec in registry.rungs.items():
        print(f"  {rung}: {len(spec['features'])} features (hash {registry.schema_hash(rung)[:12]})")
    return 0


def cmd_compatibility(_args: argparse.Namespace) -> int:
    registry = _registry()
    print(f"{'dataset':20s} {'rung':6s} {'supported':>10s}  unsupported")
    for dataset in registry.column_maps:
        for rung in registry.rungs:
            sup = registry.features_supported(dataset, rung)
            unsup = registry.unsupported_features(dataset, rung)
            print(f"{dataset:20s} {rung:6s} {len(sup):>4d}/{len(registry.rung_features(rung)):<4d}  {unsup}")
    return 0


def cmd_verify_datasets(_args: argparse.Namespace) -> int:
    from xrlids.datasets.loading import dataset_availability, load_manifest

    manifest = load_manifest()
    out = [dataset_availability(manifest, entry["key"]) for entry in manifest["datasets"]]
    print(json.dumps(out, indent=2))
    return 0 if all(o["status"] == "available" for o in out) else 1


def cmd_audit(args: argparse.Namespace) -> int:
    from xrlids.datasets.audit import audit_file, summarize_audits
    from xrlids.labels.contract import load_label_contract

    path = Path(args.input)
    if not path.is_file():
        print(f"DATA_NOT_AVAILABLE: no such file {path}", file=sys.stderr)
        return 2
    contract = load_label_contract()
    registry = _registry()
    audit = audit_file(path, dataset=args.dataset, contract=contract, registry=registry)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{args.dataset}_audit.json"
    out.write_text(json.dumps({"audits": [audit], "summary": summarize_audits([audit])}, indent=2, default=str), encoding="utf-8")
    print(f"wrote {out}")
    print(json.dumps(audit["label_audit"], indent=2, default=str))
    return 0


def cmd_smoke(args: argparse.Namespace) -> int:
    from xrlids.experiments.registry import write_experiment_record
    from xrlids.labels.contract import load_label_contract
    from xrlids.pipeline import run_single_dataset
    from xrlids.testing import synthetic_cic_frame

    registry = _registry()
    contract = load_label_contract()
    frame = synthetic_cic_frame(n_rows=args.rows, seed=args.seed)
    result = run_single_dataset(
        frame,
        dataset="cicids2017",
        rung=args.rung,
        contract=contract,
        registry=registry,
        seq_len=args.seq_len,
        seed=args.seed,
        lstm_params={"epochs": 3, "patience": 2, "batch_size": 128},
        smoke=True,
    )
    out_dir = Path("results/smoke")
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"smoke_{args.rung}.json"
    out.write_text(json.dumps(result.to_dict(), indent=2, default=str), encoding="utf-8")
    print(f"SMOKE run complete -> {out}")
    print(f"status: {result.status}")
    print("test metrics (synthetic fixture - NOT evidence):")
    print(json.dumps(result.payload["test_metrics"], indent=2, default=str))
    if result.warnings:
        print("warnings:")
        for w in result.warnings:
            print(f"  - {w}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="xrlids", description=f"{PROJECT_NAME} Phase 1 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("info", help="print environment and feature-registry status").set_defaults(func=cmd_info)
    sub.add_parser("compatibility", help="print the feature/dataset compatibility matrix").set_defaults(func=cmd_compatibility)
    sub.add_parser("verify-datasets", help="check which datasets are present and checksummed").set_defaults(func=cmd_verify_datasets)

    p_audit = sub.add_parser("audit", help="audit one dataset file")
    p_audit.add_argument("--dataset", required=True)
    p_audit.add_argument("--input", required=True)
    p_audit.add_argument("--out", default="results/audits")
    p_audit.set_defaults(func=cmd_audit)

    p_smoke = sub.add_parser("smoke", help="run the full chain on a synthetic fixture (not evidence)")
    p_smoke.add_argument("--rung", default="R10")
    p_smoke.add_argument("--rows", type=int, default=1200)
    p_smoke.add_argument("--seed", type=int, default=42)
    p_smoke.add_argument("--seq-len", type=int, default=5)
    p_smoke.set_defaults(func=cmd_smoke)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
