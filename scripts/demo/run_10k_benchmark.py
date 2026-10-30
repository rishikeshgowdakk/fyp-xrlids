#!/usr/bin/env python3
"""Execute the authoritative 10,000-record benchmark evaluation for XRL-IDARS.

Evaluates:
1. Random Forest (Operational Champion, R10 contract)
2. PyTorch Supervised LSTM FlowSeq (T=5 causal sliding sequence)
3. Convex RF–LSTM Score Fusion (alpha * S_rf + (1 - alpha) * S_lstm)

Guarantees:
- Genuine records extracted from CIC-IDS2017 with exact source provenance.
- Zero target leakage: label and metadata isolated before inference.
- Sequence alignment: preserves temporal causal ordering within source files.
- Exports structured artifacts to results/final_evaluation/:
  - evaluation_summary.json
  - predictions_10k.csv
  - confusion_matrix.csv
  - classification_report.json
  - run_provenance.json
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.demo.replay_lab import ReplayLabEngine
from xrlids.evaluation.csv_evaluator import evaluate_csv_dataset
from xrlids.features.definitions import R10_FEATURES

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("run_10k_benchmark")

OUT_DIR = REPO_ROOT / "results" / "final_evaluation"
DATA_FILE = REPO_ROOT / "data" / "demo" / "evaluation_10k_records.csv"


def prepare_10k_dataset(seed: int = 42) -> pd.DataFrame:
    """Prepare and cache authoritative 10,000-record evaluation dataset."""
    if DATA_FILE.exists():
        logger.info(f"Loading existing 10k dataset from {DATA_FILE}")
        return pd.read_csv(DATA_FILE)

    logger.info("Sampling 10,000 genuine records from replay lab cache pool...")
    engine = ReplayLabEngine.get_instance()
    records = engine.sample_records(dataset="cicids2017", count=10000, selection="mixed", seed=seed)

    rows: list[dict[str, Any]] = []
    for r in records:
        row = dict(r["features"])
        row["label"] = int(r["binary_label"])
        row["attack_family"] = str(r["ground_truth_family"])
        row["source_file"] = str(r["source_file"])
        row["source_row_index"] = int(r["source_row_index"])
        rows.append(row)

    df = pd.DataFrame(rows)
    # Sort deterministically to maintain causal continuity within each source file
    df = df.sort_values(by=["source_file", "source_row_index"]).reset_index(drop=True)

    DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(DATA_FILE, index=False)
    logger.info(f"Saved 10,000 evaluation records to {DATA_FILE}")
    return df


def run_benchmark(df: pd.DataFrame | None = None) -> dict[str, Any]:
    """Execute complete multi-model evaluation and save authoritative artifacts."""
    if df is None:
        df = prepare_10k_dataset()

    logger.info(f"Starting multi-model evaluation across {len(df)} records...")
    t0 = time.time()
    res = evaluate_csv_dataset(df, contract="R10", benchmark="cicids2017")
    duration = time.time() - t0
    logger.info(f"Evaluation completed in {duration:.2f} seconds.")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Summary JSON
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_records": len(df),
        "evaluation_duration_s": round(duration, 3),
        "benchmark": "cicids2017",
        "contract": "R10",
        "models": {
            "random_forest": res.get("rf_metrics"),
            "lstm_flowseq": res.get("lstm_metrics"),
            "rf_lstm_fusion": res.get("fusion_metrics"),
        },
        "row_accounting": res.get("row_accounting"),
        "confusion_matrices": {
            "random_forest": res.get("rf_confusion_matrix"),
            "lstm_flowseq": res.get("lstm_confusion_matrix"),
            "rf_lstm_fusion": res.get("fusion_confusion_matrix"),
        },
    }

    with open(OUT_DIR / "evaluation_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    # 2. Confusion matrix CSV
    cm_rows = []
    for model_name, cm in summary["confusion_matrices"].items():
        if cm:
            cm_rows.append({
                "model": model_name,
                "true_negative": cm.get("tn", 0),
                "false_positive": cm.get("fp", 0),
                "false_negative": cm.get("fn", 0),
                "true_positive": cm.get("tp", 0),
            })
    pd.DataFrame(cm_rows).to_csv(OUT_DIR / "confusion_matrix.csv", index=False)

    # 3. Classification report CSV / JSON
    class_rows = []
    for model_name, m in summary["models"].items():
        if m:
            class_rows.append({
                "model": model_name,
                "accuracy": round(m.get("accuracy", 0.0), 4),
                "precision": round(m.get("precision", 0.0), 4),
                "recall": round(m.get("recall", 0.0), 4),
                "f1_score": round(m.get("f1", 0.0), 4),
                "macro_f1": round(m.get("macro_f1", 0.0), 4),
                "roc_auc": round(m.get("roc_auc", 0.0), 4),
                "evaluated_population": m.get("population", 0),
            })
    pd.DataFrame(class_rows).to_csv(OUT_DIR / "classification_report.csv", index=False)
    with open(OUT_DIR / "classification_report.json", "w", encoding="utf-8") as f:
        json.dump(class_rows, f, indent=2)

    # 4. Predictions CSV sample (first 1000 evaluated flows)
    flows = res.get("flows", [])
    if flows:
        pred_rows = []
        for fl in flows:
            pred_rows.append({
                "flow_id": fl.get("flow_id"),
                "ground_truth_label": fl.get("ground_truth_label"),
                "rf_score": fl.get("rf_score"),
                "rf_decision": fl.get("rf_decision"),
                "lstm_score": fl.get("lstm_score"),
                "fusion_score": fl.get("fusion_score"),
                "verdict": fl.get("verdict"),
            })
        pd.DataFrame(pred_rows).to_csv(OUT_DIR / "predictions_10k.csv", index=False)

    # 5. Run provenance
    provenance = {
        "dataset_source": "data/demo/replay_lab_cache.joblib",
        "dataset_csv": str(DATA_FILE),
        "total_rows": len(df),
        "label_distribution": df["label"].value_counts().to_dict(),
        "family_distribution": df["attack_family"].value_counts().to_dict(),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "git_branch": "fix/final-engineering-correctness",
    }
    with open(OUT_DIR / "run_provenance.json", "w", encoding="utf-8") as f:
        json.dump(provenance, f, indent=2)

    logger.info(f"Artifacts successfully written to {OUT_DIR}")
    return summary


if __name__ == "__main__":
    summary = run_benchmark()
    print("\n" + "=" * 70)
    print("  XRL-IDARS 10,000-RECORD BENCHMARK EVALUATION RESULTS")
    print("=" * 70)
    for model_name, m in summary["models"].items():
        if m:
            print(f"\nModel: {model_name.upper()}")
            print(f"  Population: {m.get('population')}")
            print(f"  Accuracy:   {m.get('accuracy') * 100:.2f}%")
            print(f"  Precision:  {m.get('precision'):.4f}")
            print(f"  Recall:     {m.get('recall'):.4f}")
            print(f"  F1-Score:   {m.get('f1'):.4f}")
            print(f"  ROC-AUC:    {m.get('roc_auc'):.4f}")
            cm = summary["confusion_matrices"].get(model_name, {})
            print(f"  Confusion:  TN={cm.get('tn')} | FP={cm.get('fp')} | FN={cm.get('fn')} | TP={cm.get('tp')}")
    print("=" * 70)
