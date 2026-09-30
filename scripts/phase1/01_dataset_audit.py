#!/usr/bin/env python
"""Phase 1 step 1: audit a dataset file.

    python scripts/phase1/01_dataset_audit.py --dataset cicids2017 --input data/raw/cicids2017/x.csv

Writes machine-readable findings to results/audits/<dataset>_audit.json and a
human-readable summary to reports/generated/audits/<dataset>_audit.md.
Fails loudly if the file is absent; never substitutes synthetic rows.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from xrlids.datasets.audit import audit_file, summarize_audits  # noqa: E402
from xrlids.features.registry import load_feature_registry  # noqa: E402
from xrlids.labels.contract import load_label_contract  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit one dataset file")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--input", required=True, help="path to the CSV file")
    parser.add_argument("--out", default="results/audits")
    parser.add_argument("--report-out", default="reports/generated/audits")
    args = parser.parse_args()

    path = Path(args.input)
    if not path.is_file():
        print(f"DATA_NOT_AVAILABLE: {path} not found. Acquire the dataset first.", file=sys.stderr)
        return 2

    audit = audit_file(
        path,
        dataset=args.dataset,
        contract=load_label_contract(),
        registry=load_feature_registry(),
    )
    summary = summarize_audits([audit])

    out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
    (out / f"{args.dataset}_audit.json").write_text(
        json.dumps({"audits": [audit], "summary": summary}, indent=2, default=str), encoding="utf-8"
    )

    rep = Path(args.report_out); rep.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Dataset audit - {args.dataset}",
        "",
        f"Source file: `{path}`",
        f"Rows: {audit['rows']}  Columns: {audit['columns']}",
        f"Duplicate rows: {audit['duplicate_rows']} ({audit['duplicate_row_fraction']:.4%})",
        f"NaN cells: {audit['total_nan']}  Infinite cells: {audit['total_inf']}",
        "",
        "## Label audit",
        "",
        "```json",
        json.dumps(audit["label_audit"], indent=2, default=str),
        "```",
        "",
        "## Unknown-label rejections",
        "",
        "```json",
        json.dumps(audit["unknown_label_rejections"], indent=2, default=str),
        "```",
        "",
    ]
    (rep / f"{args.dataset}_audit.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"wrote {out / f'{args.dataset}_audit.json'}")
    print(json.dumps(summary, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
