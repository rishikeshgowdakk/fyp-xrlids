#!/usr/bin/env python
"""Summarize multi-seed Phase 1 runs into mean ± std tables.

Multi-seed sweeps write each seed to ``<experiment>/seed_<n>/``. This utility
aggregates the aligned test metrics (random forest, LSTM, fusion) across those
runs, writes ``multi_seed_metrics.json`` next to them, and emits a consolidated
markdown report.

Usage:
    python scripts/phase1/summarize_multi_seed.py \
        --experiments results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001 \
        --out reports/generated/multi_seed_report.md

The frozen single-seed run at the experiment root (if present) is reported as a
reproducibility reference and is never mixed into the aggregate.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

MODELS = ("random_forest", "lstm", "fusion")
METRICS = ("accuracy", "f1", "roc_auc")


def _load_metrics(record_path: Path) -> dict[str, dict[str, float]] | None:
    """Return {model: {metric: value}} for one run, or None if unreadable."""
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"  ! skipping unreadable record {record_path}: {exc}", file=sys.stderr)
        return None
    models = (record.get("metrics") or {}).get("aligned", {}).get("models") or {}
    out: dict[str, dict[str, float]] = {}
    for model in MODELS:
        values = models.get(model)
        if not isinstance(values, dict):
            continue
        out[model] = {m: float(values[m]) for m in METRICS if values.get(m) is not None}
    return out or None


def _summary(values: list[float]) -> dict[str, float | int]:
    if len(values) == 1:
        return {
            "n": 1,
            "mean": values[0],
            "std": 0.0,
            "min": values[0],
            "max": values[0],
        }
    return {
        "n": len(values),
        "mean": statistics.fmean(values),
        # Population std (ddof=0) to match the runner's multi_seed_summary.json.
        "std": statistics.pstdev(values),
        "min": min(values),
        "max": max(values),
    }


def summarize_experiment(exp_dir: Path) -> dict | None:
    seed_runs = sorted(
        (p for p in exp_dir.glob("seed_*/experiment_record.json")),
        key=lambda p: int(p.parent.name.split("_", 1)[1]),
    )
    if not seed_runs:
        return None

    runs: list[dict] = []
    per_model: dict[str, dict[str, list[float]]] = {m: {k: [] for k in METRICS} for m in MODELS}
    for path in seed_runs:
        seed = int(path.parent.name.split("_", 1)[1])
        metrics = _load_metrics(path)
        if metrics is None:
            continue
        runs.append({"seed": seed, "record": str(path), "models": metrics})
        for model, values in metrics.items():
            for metric, value in values.items():
                per_model[model][metric].append(value)

    root_record = exp_dir / "experiment_record.json"
    reference = None
    if root_record.exists():
        ref_metrics = _load_metrics(root_record)
        if ref_metrics is not None:
            reference = {
                "record": str(root_record),
                "models": ref_metrics,
            }

    summary = {
        model: {
            metric: _summary(per_model[model][metric])
            for metric in METRICS
            if per_model[model][metric]
        }
        for model in MODELS
    }
    payload = {
        "experiment_id": exp_dir.name,
        "seeds": [r["seed"] for r in runs],
        "models": list(MODELS),
        "std_convention": "population std (ddof=0), matching multi_seed_summary.json",
        "summary": summary,
        "frozen_single_seed_reference": reference,
    }
    (exp_dir / "multi_seed_metrics.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate multi-seed Phase 1 runs")
    parser.add_argument("--experiments", nargs="+", required=True, type=Path)
    parser.add_argument("--out", default="reports/generated/multi_seed_report.md", type=Path)
    args = parser.parse_args()

    payloads = []
    for exp_dir in args.experiments:
        payload = summarize_experiment(exp_dir)
        if payload is None:
            print(f"  - {exp_dir.name}: no seed_*/ runs found; skipped (single-seed or not yet run)")
            continue
        payloads.append(payload)
        print(f"  - {exp_dir.name}: aggregated seeds {payload['seeds']}")

    if not payloads:
        print("No multi-seed runs found; nothing to write.")
        return 1

    lines = [
        "# Multi-Seed Robustness Report (generated)",
        "",
        "Aligned test metrics aggregated across seeds (population std, ddof=0, matching",
        "`multi_seed_summary.json`) via `scripts/phase1/summarize_multi_seed.py`.",
        "Per-seed records: `seed_*/experiment_record.json`.",
        "",
        "Bootstrap 95% confidence intervals are generated separately by",
        "`scripts/phase1/bootstrap_confidence_intervals.py` and published in",
        "`reports/generated/bootstrap_ci_report.md`.",
        "",
        "| Dataset | Model | Accuracy (mean ± std) | F1 (mean ± std) | ROC-AUC (mean ± std) | Seeds |",
        "|:---|:---|:---:|:---:|:---:|:---:|",
    ]
    labels = {
        "EXP-P1-CIC2017-R10-001": "CIC-IDS2017",
        "EXP-P1-CSE2018-R10-MULTI-001": "CSE-CIC-IDS2018",
        "EXP-P1-UNSWNB15-R10-MULTI-001": "UNSW-NB15",
    }
    for payload in payloads:
        dataset = labels.get(payload["experiment_id"], payload["experiment_id"])
        seeds = ", ".join(str(s) for s in payload["seeds"])
        for model in MODELS:
            cells = []
            for metric in METRICS:
                stat = payload["summary"].get(model, {}).get(metric)
                cells.append(f"{stat['mean']:.4f} ± {stat['std']:.4f}" if stat else "—")
            lines.append(f"| {dataset} | {model} | {cells[0]} | {cells[1]} | {cells[2]} | {seeds} |")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
