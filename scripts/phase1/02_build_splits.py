#!/usr/bin/env python
"""Phase 1 step 2: build leakage-audited splits for one dataset file.

    python scripts/phase1/02_build_splits.py --dataset cicids2017 --rung R10 --input data/raw/cicids2017/x.csv

Writes results/splits/<dataset>_<rung>_splits.json including the leakage audit.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import pandas as pd  # noqa: E402

from xrlids.features import build_feature_matrix  # noqa: E402
from xrlids.features.registry import load_feature_registry  # noqa: E402
from xrlids.labels.contract import load_label_contract  # noqa: E402
from xrlids.preprocessing.cleaning import clean_dataset_frame  # noqa: E402
from xrlids.splitting.splitter import SplitConfig, build_splits  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Build leakage-audited splits")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--rung", default="R10")
    parser.add_argument("--input", required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default="results/splits")
    parser.add_argument("--group-column", default=None)
    args = parser.parse_args()

    path = Path(args.input)
    if not path.is_file():
        print(f"DATA_NOT_AVAILABLE: {path} not found.", file=sys.stderr)
        return 2

    registry = load_feature_registry()
    contract = load_label_contract()
    raw = pd.read_csv(path, low_memory=False)

    cleaned = clean_dataset_frame(raw, args.dataset, contract)
    fm = build_feature_matrix(cleaned.frame, args.dataset, args.rung, registry, strict=True, validate=False)

    result = build_splits(
        fm.frame,
        cleaned.labels.binary.reset_index(drop=True),
        fm.available,
        SplitConfig(seed=args.seed, group_column=args.group_column),
        dataset=args.dataset,
    )

    payload = {
        "dataset": args.dataset,
        "rung": args.rung,
        "schema_hash": fm.schema_hash,
        "cleaning": cleaned.accounting,
        "manifest": result.manifest,
        "leakage_audit": result.leakage,
    }
    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    dest = out / f"{args.dataset}_{args.rung}_splits.json"
    dest.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    print(f"wrote {dest}")
    print(f"leakage status: {result.leakage.get('status')}")
    if result.leakage.get("status") == "fail":
        print("LEAKAGE DETECTED - fix the split methodology and regenerate.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
