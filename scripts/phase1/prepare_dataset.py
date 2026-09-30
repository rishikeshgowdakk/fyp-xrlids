#!/usr/bin/env python
"""Reproducible dataset preparation CLI.

    # 1. after placing files in data/raw/<dataset>/, register checksums (computes SHA256):
    python scripts/phase1/prepare_dataset.py register --dataset cicids2017 --all
    python scripts/phase1/prepare_dataset.py register --dataset cicids2017 --file <path.csv>

    # 2. re-verify checksums (fails on mismatch):
    python scripts/phase1/prepare_dataset.py verify --dataset cicids2017

    # 3. what is present / missing / verified?
    python scripts/phase1/prepare_dataset.py status
    python scripts/phase1/prepare_dataset.py instructions
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from xrlids.datasets.prepare import (  # noqa: E402
    acquisition_instructions,
    dataset_status,
    load_manifest,
    register_file,
    verify_dataset,
)


def cmd_register(args: argparse.Namespace) -> int:
    if not args.all and not args.file:
        print("--all or --file is required", file=sys.stderr)
        return 2

    if args.all:
        raw_dir = Path("data/raw") / args.dataset
        if not raw_dir.is_dir():
            print(f"NOTHING TO REGISTER: {raw_dir} does not exist.", file=sys.stderr)
            print("Download the files first; see:", file=sys.stderr)
            print("  python scripts/phase1/prepare_dataset.py instructions", file=sys.stderr)
            return 2
        csvs = sorted(raw_dir.glob("*.csv"))
        if not csvs:
            print(f"NOTHING TO REGISTER: no CSV files in {raw_dir}", file=sys.stderr)
            return 2
        for path in csvs:
            record = register_file(args.dataset, path, source=args.source)
            print(f"registered {record['filename']}  sha256={record['sha256'][:16]}...  size={record['size_bytes']}")
        return 0

    path = Path(args.file)
    if not path.is_file():
        print(f"DATA_NOT_AVAILABLE: {path} does not exist", file=sys.stderr)
        return 2
    record = register_file(args.dataset, path, source=args.source)
    print(json.dumps(record, indent=2))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    manifest = load_manifest()
    keys = (
        [d["key"] for d in manifest["datasets"]]
        if args.dataset is None
        else [args.dataset]
    )
    exit_code = 0
    for key in keys:
        try:
            report = verify_dataset(key)
        except Exception as exc:
            print(f"VERIFY FAILED for {key}: {exc}", file=sys.stderr)
            exit_code = 1
            continue
        print(f"{key}: {report['overall']} ({len(report['files'])} file(s))")
        for f in report["files"]:
            print(f"  - {f['filename']}: {f['status']}")
        if report["overall"] == "no_files_registered":
            exit_code = 2
    return exit_code


def cmd_status(_args: argparse.Namespace) -> int:
    manifest = load_manifest()
    statuses = [
        dataset_status(d["key"]) for d in manifest["datasets"]
    ]
    print(json.dumps(statuses, indent=2))
    all_ready = all(s["ready_for_training"] for s in statuses)
    if not all_ready:
        print(
            "\nNot all datasets are ready for training. Run: "
            "python scripts/phase1/prepare_dataset.py instructions",
            file=sys.stderr,
        )
    return 0 if all_ready else 1


def cmd_instructions(_args: argparse.Namespace) -> int:
    print(acquisition_instructions())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="dataset preparation and verification")
    sub = parser.add_subparsers(dest="command", required=True)

    p_reg = sub.add_parser("register", help="compute and record SHA256 for real files")
    p_reg.add_argument("--dataset", required=True)
    p_reg.add_argument("--file", default=None, help="register one specific file")
    p_reg.add_argument("--all", action="store_true", help="register every CSV in data/raw/<dataset>/")
    p_reg.add_argument("--source", default=None, help="where the file came from (recorded in the manifest)")
    p_reg.set_defaults(func=cmd_register)

    p_ver = sub.add_parser("verify", help="recompute checksums and compare to the manifest")
    p_ver.add_argument("--dataset", default=None, help="verify one dataset (default: all)")
    p_ver.set_defaults(func=cmd_verify)

    sub.add_parser("status", help="per-dataset acquisition/audit readiness").set_defaults(func=cmd_status)
    sub.add_parser("instructions", help="print exact acquisition instructions").set_defaults(func=cmd_instructions)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
