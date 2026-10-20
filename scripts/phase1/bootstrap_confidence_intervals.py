#!/usr/bin/env python
"""Bootstrap confidence intervals for held-out Phase 1 test predictions (GAP-M03).

The detector metrics in the Phase 1 report are point estimates on a finite test
population. This script adds non-parametric bootstrap confidence intervals using
the saved per-seed ``predictions_test.csv`` artifacts. It does not retrain any model
and does not touch the test population to select anything.

Method
------
* Threshold metrics (accuracy, precision, recall, F1): exact row-bootstrap of the
  held-out confusion matrix. A bootstrap sample is drawn from the four confusion
  cells with probabilities equal to their observed frequencies; this is
  distributionally identical to resampling rows with replacement and is fast even
  for the 1.66M-row CSE test population.
* ROC-AUC: 1,000 stratified bootstrap resamples of a fixed 100,000-flow sample
  (class ratio preserved). The point estimate is computed on the full test set.
  Full-population AUC resampling is computationally prohibitive in Python; the
  sample-based CI is reported explicitly and is slightly conservative.

Usage::

    python scripts/phase1/bootstrap_confidence_intervals.py \
        --experiments \
            results/experiments/EXP-P1-CIC2017-R10-001 \
            results/experiments/EXP-P1-CSE2018-R10-MULTI-001 \
            results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001 \
        --out reports/generated/bootstrap_ci_report.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import roc_auc_score  # noqa: E402

MODELS = ("random_forest", "lstm", "fusion")
SCORE_COLUMNS = {
    "random_forest": "rf_score",
    "lstm": "lstm_score",
    "fusion": "fusion_score",
}
DATASET_LABELS = {
    "EXP-P1-CIC2017-R10-001": "CIC-IDS2017",
    "EXP-P1-CSE2018-R10-MULTI-001": "CSE-CIC-IDS2018",
    "EXP-P1-UNSWNB15-R10-MULTI-001": "UNSW-NB15",
    "EXP-P1-CSE2018-TEMPORAL-R10-001": "CSE-CIC-IDS2018 (temporal)",
}


def _threshold_counts(y: np.ndarray, score: np.ndarray, threshold: float) -> dict[str, int]:
    predicted = score >= threshold
    tp = int(np.sum((y == 1) & predicted))
    fp = int(np.sum((y == 0) & predicted))
    fn = int(np.sum((y == 1) & ~predicted))
    tn = int(np.sum((y == 0) & ~predicted))
    return {"tn": tn, "fp": fp, "fn": fn, "tp": tp}


def _threshold_point(counts: dict[str, int]) -> dict[str, float]:
    tn, fp, fn, tp = counts["tn"], counts["fp"], counts["fn"], counts["tp"]
    n = tn + fp + fn + tp
    return {
        "accuracy": float((tn + tp) / n) if n else 0.0,
        "precision": float(tp / (tp + fp)) if (tp + fp) else 0.0,
        "recall": float(tp / (tp + fn)) if (tp + fn) else 0.0,
        "f1": float(2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) else 0.0,
    }


def _bootstrap_threshold_ci(
    counts: dict[str, int],
    *,
    n_bootstraps: int,
    ci_level: float,
    seed: int,
) -> dict[str, dict[str, float]]:
    n = counts["tn"] + counts["fp"] + counts["fn"] + counts["tp"]
    point = _threshold_point(counts)
    if n == 0:
        return {
            metric: {
                "point_estimate": 0.0,
                "ci_lower": 0.0,
                "ci_upper": 0.0,
                "n_bootstraps": n_bootstraps,
                "ci_level": ci_level,
            }
            for metric in point
        }

    pvals = np.array([counts["tn"], counts["fp"], counts["fn"], counts["tp"]], dtype=float) / n
    rng = np.random.default_rng(seed)
    boot = rng.multinomial(n, pvals, size=n_bootstraps)
    tn, fp, fn, tp = boot.T

    def _safe_ratio(num: np.ndarray, den: np.ndarray) -> np.ndarray:
        return np.divide(num, den, out=np.zeros_like(num, dtype=float), where=den > 0)

    distributions = {
        "accuracy": (tn + tp) / n,
        "precision": _safe_ratio(tp, tp + fp),
        "recall": _safe_ratio(tp, tp + fn),
        "f1": _safe_ratio(2 * tp, 2 * tp + fp + fn),
    }
    alpha = 1.0 - ci_level
    out: dict[str, dict[str, float]] = {}
    for metric, values in distributions.items():
        out[metric] = {
            "point_estimate": round(float(point[metric]), 6),
            "ci_lower": round(float(np.percentile(values, (alpha / 2.0) * 100)), 6),
            "ci_upper": round(float(np.percentile(values, (1.0 - alpha / 2.0) * 100)), 6),
            "n_bootstraps": int(n_bootstraps),
            "ci_level": float(ci_level),
        }
    return out


def _bootstrap_auc_ci(
    y: np.ndarray,
    score: np.ndarray,
    *,
    n_bootstraps: int,
    ci_level: float,
    seed: int,
    sample_size: int,
) -> dict[str, Any]:
    y = np.asarray(y, dtype=np.int8)
    score = np.asarray(score, dtype=np.float64)
    if len(y) == 0 or len(np.unique(y)) < 2:
        return {
            "point_estimate": 0.5,
            "ci_lower": 0.5,
            "ci_upper": 0.5,
            "n_bootstraps": int(n_bootstraps),
            "ci_level": float(ci_level),
            "sample_size": 0,
            "method": "not_applicable_single_class",
        }

    point = float(roc_auc_score(y, score))
    pos = score[y == 1]
    neg = score[y == 0]
    rng = np.random.default_rng(seed)

    if sample_size and sample_size < len(score):
        n_pos_sample = max(2, int(round(sample_size * len(pos) / len(score))))
        n_neg_sample = max(2, int(sample_size - n_pos_sample))
        n_pos_sample = min(n_pos_sample, len(pos))
        n_neg_sample = min(n_neg_sample, len(neg))
        pos_sample = rng.choice(pos, size=n_pos_sample, replace=False)
        neg_sample = rng.choice(neg, size=n_neg_sample, replace=False)
    else:
        pos_sample, neg_sample = pos, neg
        n_pos_sample, n_neg_sample = len(pos), len(neg)

    if n_pos_sample < 2 or n_neg_sample < 2:
        return {
            "point_estimate": round(point, 6),
            "ci_lower": round(point, 6),
            "ci_upper": round(point, 6),
            "n_bootstraps": int(n_bootstraps),
            "ci_level": float(ci_level),
            "sample_size": int(n_pos_sample + n_neg_sample),
            "method": "insufficient_class_sample",
        }

    auc_values = np.empty(n_bootstraps, dtype=float)
    for i in range(n_bootstraps):
        boot_pos = rng.choice(pos_sample, size=n_pos_sample, replace=True)
        boot_neg = rng.choice(neg_sample, size=n_neg_sample, replace=True)
        sorted_neg = np.sort(boot_neg)
        left = np.searchsorted(sorted_neg, boot_pos, side="left")
        right = np.searchsorted(sorted_neg, boot_pos, side="right")
        # Mann-Whitney U with 0.5 credit for ties.
        auc_values[i] = (
            left.sum() + 0.5 * (right - left).sum()
        ) / (n_pos_sample * n_neg_sample)

    alpha = 1.0 - ci_level
    return {
        "point_estimate": round(point, 6),
        "ci_lower": round(float(np.percentile(auc_values, (alpha / 2.0) * 100)), 6),
        "ci_upper": round(float(np.percentile(auc_values, (1.0 - alpha / 2.0) * 100)), 6),
        "n_bootstraps": int(n_bootstraps),
        "ci_level": float(ci_level),
        "sample_size": int(n_pos_sample + n_neg_sample),
        "sample_positives": int(n_pos_sample),
        "sample_negatives": int(n_neg_sample),
        "method": "stratified_bootstrap_sample",
    }


def _seed_prediction_paths(exp_dir: Path) -> list[tuple[str, Path]]:
    seed_paths: list[tuple[int, Path]] = []
    for seed_dir in exp_dir.glob("seed_*"):
        path = seed_dir / "predictions_test.csv"
        if not path.is_file():
            continue
        try:
            seed = int(seed_dir.name.split("_", 1)[1])
        except (IndexError, ValueError):
            continue
        seed_paths.append((seed, path))
    if seed_paths:
        return [(str(seed), path) for seed, path in sorted(seed_paths)]
    root = exp_dir / "predictions_test.csv"
    if not root.is_file():
        return []
    # Single-seed experiments keep the frozen predictions at the experiment
    # root rather than under seed_<n>/. Use the recorded seed so the report
    # remains consistent with the multi-seed rows.
    label = "frozen"
    record_path = exp_dir / "experiment_record.json"
    if record_path.is_file():
        try:
            label = str(json.loads(record_path.read_text(encoding="utf-8")).get("random_seed", "frozen"))
        except (OSError, ValueError, TypeError):
            pass
    return [(label, root)]


def _evaluate_predictions(
    path: Path,
    *,
    threshold: float,
    n_bootstraps: int,
    n_bootstraps_auc: int,
    ci_level: float,
    auc_sample_size: int,
    seed: int,
) -> dict[str, Any]:
    header = pd.read_csv(path, nrows=0).columns
    models = [m for m in MODELS if SCORE_COLUMNS[m] in header]
    if not models or "true_label" not in header:
        return {"path": str(path), "models": {}}

    usecols = ["true_label"] + [SCORE_COLUMNS[m] for m in models]
    frame = pd.read_csv(path, usecols=usecols)
    y_all = frame["true_label"].to_numpy(dtype=np.int8)

    result: dict[str, Any] = {"path": str(path), "n_rows": int(len(frame)), "models": {}}
    for model in models:
        score = frame[SCORE_COLUMNS[model]].to_numpy(dtype=np.float64)
        finite = np.isfinite(score)
        y = y_all[finite]
        s = score[finite]
        if len(y) == 0:
            continue

        counts = _threshold_counts(y, s, threshold)
        threshold_ci = _bootstrap_threshold_ci(
            counts,
            n_bootstraps=n_bootstraps,
            ci_level=ci_level,
            seed=seed,
        )
        auc_ci = _bootstrap_auc_ci(
            y,
            s,
            n_bootstraps=n_bootstraps_auc,
            ci_level=ci_level,
            seed=seed + 1,
            sample_size=auc_sample_size,
        )
        result["models"][model] = {
            "n": int(len(y)),
            "threshold": float(threshold),
            "confusion": counts,
            "threshold_metrics": threshold_ci,
            "roc_auc": auc_ci,
        }
    return result


def _format_ci(metric: dict[str, Any]) -> str:
    return (
        f"{metric['point_estimate']:.4f} "
        f"[{metric['ci_lower']:.4f}, {metric['ci_upper']:.4f}]"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap CIs for held-out Phase 1 predictions")
    parser.add_argument("--experiments", nargs="+", required=True, type=Path)
    parser.add_argument("--out", default="reports/generated/bootstrap_ci_report.md", type=Path)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--n-bootstraps", type=int, default=1000)
    parser.add_argument("--n-bootstraps-auc", type=int, default=1000)
    parser.add_argument("--auc-sample-size", type=int, default=100000)
    parser.add_argument("--ci-level", type=float, default=0.95)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    payloads: list[dict[str, Any]] = []
    for exp_dir in args.experiments:
        exp_dir = exp_dir.resolve()
        if not exp_dir.is_dir():
            print(f"  ! skipping missing experiment directory: {exp_dir}", file=sys.stderr)
            continue
        seed_paths = _seed_prediction_paths(exp_dir)
        if not seed_paths:
            print(f"  ! no predictions_test.csv found under {exp_dir}", file=sys.stderr)
            continue

        print(f"  - {exp_dir.name}: {len(seed_paths)} prediction file(s)")
        seeds: dict[str, Any] = {}
        for label, path in seed_paths:
            print(f"      seed {label}: {path.name}")
            seeds[label] = _evaluate_predictions(
                path,
                threshold=args.threshold,
                n_bootstraps=args.n_bootstraps,
                n_bootstraps_auc=args.n_bootstraps_auc,
                ci_level=args.ci_level,
                auc_sample_size=args.auc_sample_size,
                seed=args.seed,
            )

        payload = {
            "experiment_id": exp_dir.name,
            "dataset_label": DATASET_LABELS.get(exp_dir.name, exp_dir.name),
            "threshold": args.threshold,
            "ci_level": args.ci_level,
            "n_bootstraps_threshold": args.n_bootstraps,
            "n_bootstraps_auc": args.n_bootstraps_auc,
            "auc_sample_size": args.auc_sample_size,
            "seed": args.seed,
            "method": {
                "threshold_metrics": (
                    "exact row-bootstrap of the held-out confusion matrix "
                    "(multinomial cell resampling, full test population)"
                ),
                "roc_auc": (
                    "stratified bootstrap of a fixed test sample; point estimate on full test set"
                ),
            },
            "seeds": seeds,
        }
        (exp_dir / "bootstrap_cis.json").write_text(
            json.dumps(payload, indent=2) + "\n", encoding="utf-8"
        )
        payloads.append(payload)

    if not payloads:
        print("No prediction files found; nothing to write.", file=sys.stderr)
        return 1

    lines = [
        "# Bootstrap Confidence Intervals (generated)",
        "",
        "Non-parametric 95% confidence intervals for held-out Phase 1 test metrics.",
        "Generated by `scripts/phase1/bootstrap_confidence_intervals.py` from the saved",
        "`predictions_test.csv` artifacts. No model was retrained and no test row was",
        "used for selection.",
        "",
        "**Method.** Accuracy / precision / recall / F1 use an exact row-bootstrap of the",
        f"held-out confusion matrix (B={args.n_bootstraps}, full test population).",
        f"ROC-AUC uses B={args.n_bootstraps_auc} stratified bootstrap resamples of a fixed",
        f"{args.auc_sample_size:,}-flow sample; the point estimate is the full-test AUC.",
        "The AUC CI is therefore slightly conservative. CIs quantify **test-set sampling",
        "uncertainty**; they do not include training-seed variance, which is reported",
        "separately in `reports/generated/multi_seed_report.md`.",
        "",
        "Each row is a single seed's interval. On CSE-CIC-IDS2018 the validation-selected",
        "fusion weight is α=0.00, so the fusion row is numerically identical to the LSTM",
        "by design. UNSW-NB15 uses the auxiliary R4 contract; CIC-IDS2017 and",
        "CSE-CIC-IDS2018 use R10.",
        "",
        "| Dataset | Model | Seed | n | Accuracy [95% CI] | F1 [95% CI] | ROC-AUC [95% CI] |",
        "|:---|:---|:---:|:---:|:---:|:---:|:---:|",
    ]

    for payload in payloads:
        dataset = payload["dataset_label"]
        for seed_label, seed_payload in payload["seeds"].items():
            for model in MODELS:
                result = seed_payload.get("models", {}).get(model)
                if not result:
                    continue
                metrics = result["threshold_metrics"]
                lines.append(
                    f"| {dataset} | {model} | {seed_label} | {result['n']:,} | "
                    f"{_format_ci(metrics['accuracy'])} | "
                    f"{_format_ci(metrics['f1'])} | "
                    f"{_format_ci(result['roc_auc'])} |"
                )

    lines.extend([
        "",
        "## Artifact locations",
        "",
        "Each experiment directory now contains `bootstrap_cis.json` with the full",
        "per-seed, per-model confidence intervals and confusion counts.",
        "",
    ])
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nWrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
