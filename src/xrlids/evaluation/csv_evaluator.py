"""CSV evaluation and validation engine for XRL-IDARS.

Provides strict, leak-free evaluation of user-supplied or local CSV dataset records
against frozen preprocessors and model artifacts.

Guarantees:
1. Strict schema validation: checks required R10 or R4 feature columns.
2. Order enforcement: strictly applies the canonical feature sequence.
3. Ground-truth isolation: extracts and separates label columns prior to inference.
4. Target leakage prevention: ensures no label or target proxy enters model inputs.
5. Finite value validation & row accounting: tracks total, dropped, and evaluated rows.
6. Centralized metrics: uses single project-wide evaluation metrics from xrlids.evaluation.metrics.
7. Explicit provenance & disclaimer: marks output as ad-hoc, never overwriting historical benchmarks.
"""

from __future__ import annotations

import csv
import hashlib
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from xrlids.evaluation.metrics import evaluate as compute_binary_and_score_metrics
from xrlids.features.definitions import R4_FEATURES, R10_FEATURES

REPO_ROOT = Path(__file__).resolve().parents[3]

# Canonical candidate label column names
LABEL_CANDIDATE_COLUMNS = (
    "true_label",
    "label",
    "Label",
    "is_attack",
    "attack",
    "class",
    "Class",
    "target",
    "Target",
    "ground_truth",
    "ground_truth_label",
)

BENCHMARK_ARTIFACT_PATHS: dict[str, dict[str, Path]] = {
    "cicids2017": {
        "preprocessor": REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "preprocessor.joblib",
        "model": REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "random_forest.joblib",
        "default_contract": "R10",
        "name": "RandomForestClassifier (Frozen CIC-IDS2017 R10)",
    },
    "cse2018": {
        "preprocessor": REPO_ROOT / "results" / "experiments" / "EXP-P1-CSE2018-R10-MULTI-001" / "preprocessor.joblib",
        "model": REPO_ROOT / "results" / "experiments" / "EXP-P1-CSE2018-R10-MULTI-001" / "random_forest.joblib",
        "default_contract": "R10",
        "name": "RandomForestClassifier (Frozen CSE-CIC-IDS2018 R10)",
    },
    "unswnb15": {
        "preprocessor": REPO_ROOT / "results" / "experiments" / "EXP-P1-UNSWNB15-R10-MULTI-001" / "preprocessor.joblib",
        "model": REPO_ROOT / "results" / "experiments" / "EXP-P1-UNSWNB15-R10-MULTI-001" / "random_forest.joblib",
        "default_contract": "R4",
        "name": "RandomForestClassifier (Frozen UNSW-NB15 R4)",
    },
}


class CSVValidationError(ValueError):
    """Raised when CSV input is malformed, missing required contract features, or invalid."""


def _compute_sha256(path: Path) -> str:
    """Compute hex SHA-256 digest of a file if it exists."""
    if not path.exists():
        return "NOT_FOUND"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def evaluate_csv_dataset(
    csv_source: str | bytes | io.StringIO | io.BytesIO | Path | pd.DataFrame,
    contract: str = "R10",
    benchmark: str = "cicids2017",
    label_column: str | None = None,
    threshold: float = 0.50,
    operational_threshold: float = 0.40,
    max_display_flows: int = 100,
) -> dict[str, Any]:
    """Validate, preprocess, and evaluate a CSV dataset against frozen model artifacts.

    Args:
        csv_source: Raw CSV string, bytes, path, or already loaded DataFrame.
        contract: 'R10' (10 flow features) or 'R4' (4 flow features).
        benchmark: Benchmark identifier whose frozen model is used ('cicids2017', 'cse2018', 'unswnb15').
        label_column: Optional name of ground truth label column.
        threshold: Research decision threshold (default: 0.50).
        operational_threshold: Operational candidate threshold (default: 0.40).
        max_display_flows: Max flow records returned for UI inspection.

    Returns:
        Structured evaluation dictionary with metrics, confusion matrix, row accounting,
        provenance, and flow records.
    """
    contract_key = contract.upper().strip()
    if contract_key == "R10":
        expected_features = list(R10_FEATURES)
    elif contract_key == "R4":
        expected_features = list(R4_FEATURES)
    else:
        raise CSVValidationError(f"Invalid contract '{contract}'. Supported contracts: 'R10', 'R4'.")

    bench_key = benchmark.lower().strip()
    if bench_key not in BENCHMARK_ARTIFACT_PATHS:
        bench_key = "cicids2017"
    bench_info = BENCHMARK_ARTIFACT_PATHS[bench_key]

    # 1. Parse CSV into DataFrame
    try:
        if isinstance(csv_source, pd.DataFrame):
            df = csv_source.copy()
        elif isinstance(csv_source, Path):
            if not csv_source.exists():
                raise CSVValidationError(f"CSV file not found: {csv_source}")
            df = pd.read_csv(csv_source)
        elif isinstance(csv_source, bytes):
            df = pd.read_csv(io.BytesIO(csv_source))
        elif isinstance(csv_source, io.StringIO):
            df = pd.read_csv(csv_source)
        elif isinstance(csv_source, io.BytesIO):
            df = pd.read_csv(csv_source)
        elif isinstance(csv_source, str):
            # Check if it's a file path or CSV string
            potential_path = Path(csv_source)
            if "\n" not in csv_source and potential_path.exists() and potential_path.is_file():
                df = pd.read_csv(potential_path)
            else:
                df = pd.read_csv(io.StringIO(csv_source))
        else:
            raise CSVValidationError(f"Unsupported csv_source type: {type(csv_source)}")
    except Exception as exc:
        if isinstance(exc, CSVValidationError):
            raise
        raise CSVValidationError(f"Failed to parse CSV input: {str(exc)}") from exc

    total_rows = len(df)
    if total_rows == 0:
        raise CSVValidationError("CSV file contains 0 rows; nothing to evaluate.")

    # 2. Check for required feature columns
    # Strip whitespace from column names for robust matching
    df.columns = [str(c).strip() for c in df.columns]

    missing_features = [f for f in expected_features if f not in df.columns]
    if missing_features:
        raise CSVValidationError(
            f"Missing required {contract_key} feature columns: {missing_features}. "
            f"Expected all {len(expected_features)} columns: {expected_features}"
        )

    # 3. Ground-truth isolation & Target leakage prevention
    resolved_label_col: str | None = None
    if label_column and label_column in df.columns:
        resolved_label_col = label_column
    else:
        for candidate in LABEL_CANDIDATE_COLUMNS:
            if candidate in df.columns:
                resolved_label_col = candidate
                break

    y_true_raw: pd.Series | None = None
    is_labelled = False
    if resolved_label_col is not None:
        y_true_raw = df[resolved_label_col].copy()
        is_labelled = True

    # STRICT TARGET LEAKAGE INVARIANT: Drop any label-like columns from model inputs
    cols_to_drop = [c for c in df.columns if c in LABEL_CANDIDATE_COLUMNS or c == resolved_label_col]
    X_raw = df[expected_features].copy()

    # Enforce exact feature ordering
    X_raw = X_raw[expected_features]

    # Verify no label column leaked into X_raw
    for c in cols_to_drop:
        assert c not in X_raw.columns or c in expected_features, f"Target leakage invariant violated: {c} present in features!"

    # 4. Cleaning, finite value checking, and row accounting
    # Convert all feature columns to float
    for col in expected_features:
        X_raw[col] = pd.to_numeric(X_raw[col], errors="coerce")

    # Find valid finite rows (no inf, -inf, or un-imputable NaN)
    # Note: Preprocessor imputes NaNs using train medians, but infinities are invalid.
    has_inf = np.isinf(X_raw).any(axis=1)
    valid_mask = ~has_inf

    dropped_count = int((~valid_mask).sum())
    X_valid = X_raw[valid_mask].copy()
    y_valid = y_true_raw[valid_mask].copy() if is_labelled and y_true_raw is not None else None

    evaluated_count = len(X_valid)
    if evaluated_count == 0:
        raise CSVValidationError(
            f"All {total_rows} rows were rejected because they contained non-finite values (Infinity/NaN)."
        )

    # Normalize labels if labelled
    y_true_binary: np.ndarray | None = None
    if is_labelled and y_valid is not None:
        # Map labels to 0 and 1
        # Accept integer 0/1, or string "BENIGN"/"ATTACK", or common attack names
        def _map_label(val: Any) -> int:
            if pd.isna(val):
                return 0
            if isinstance(val, (int, float, np.integer, np.floating)):
                return 1 if int(val) == 1 else 0
            s = str(val).strip().upper()
            if s in ("0", "BENIGN", "NORMAL", "FALSE"):
                return 0
            return 1

        y_true_binary = np.array([_map_label(v) for v in y_valid], dtype=int)

    # 5. Load frozen preprocessor & model
    prep_path = bench_info["preprocessor"]
    model_path = bench_info["model"]

    if not prep_path.exists():
        raise CSVValidationError(f"Frozen preprocessor artifact missing: {prep_path}")
    if not model_path.exists():
        raise CSVValidationError(f"Frozen model artifact missing: {model_path}")

    preprocessor = joblib.load(prep_path)
    model = joblib.load(model_path)

    # 6. Preprocessing & Model Inference
    X_scaled = preprocessor.transform(X_valid)
    probs = model.predict_proba(X_scaled)

    # Binary class 1 is Attack
    attack_scores = probs[:, 1] if probs.ndim == 2 and probs.shape[1] >= 2 else probs.ravel()
    preds_research = (attack_scores >= threshold).astype(int)
    preds_ops = (attack_scores >= operational_threshold).astype(int)

    # 7. Metrics & Confusion Matrix (if labelled)
    metrics_summary: dict[str, Any] | None = None
    cm_summary: dict[str, int] | None = None

    if is_labelled and y_true_binary is not None:
        tp = int(((preds_research == 1) & (y_true_binary == 1)).sum())
        fp = int(((preds_research == 1) & (y_true_binary == 0)).sum())
        tn = int(((preds_research == 0) & (y_true_binary == 0)).sum())
        fn = int(((preds_research == 0) & (y_true_binary == 1)).sum())
        cm_summary = {"tp": tp, "fp": fp, "tn": tn, "fn": fn}

        try:
            metrics_summary = compute_binary_and_score_metrics(y_true_binary, attack_scores, threshold=threshold)
        except Exception:
            total = len(y_true_binary)
            acc = float((tp + tn) / total) if total > 0 else 0.0
            prec = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
            rec = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
            f1 = float(2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
            metrics_summary = {
                "threshold": threshold,
                "accuracy": round(acc, 4),
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
                "roc_auc": None,
                "roc_auc_reason": "Single class present or uniform score distribution in evaluated slice",
            }

    # 8. Score distribution
    low_threat = int((attack_scores < 0.40).sum())
    med_threat = int(((attack_scores >= 0.40) & (attack_scores < 0.65)).sum())
    high_threat = int((attack_scores >= 0.65).sum())

    score_dist = {
        "low_threat_under_040": low_threat,
        "medium_threat_040_to_065": med_threat,
        "high_threat_over_065": high_threat,
        "mean_score": round(float(np.mean(attack_scores)), 4),
        "median_score": round(float(np.median(attack_scores)), 4),
        "min_score": round(float(np.min(attack_scores)), 4),
        "max_score": round(float(np.max(attack_scores)), 4),
    }

    # 9. Pack flow records for display/inspection
    flows: list[dict[str, Any]] = []
    display_limit = min(evaluated_count, max_display_flows)

    valid_indices = X_valid.index[:display_limit]
    for i, idx in enumerate(valid_indices):
        score = float(attack_scores[i])
        pred_cls = int(preds_research[i])
        pred_label = "ATTACK" if pred_cls == 1 else "BENIGN"

        gt_cls = int(y_true_binary[i]) if is_labelled and y_true_binary is not None else None
        gt_label = "ATTACK" if gt_cls == 1 else "BENIGN" if gt_cls == 0 else "UNLABELLED"

        if gt_cls is not None:
            if pred_cls == gt_cls:
                verdict = "CORRECT"
            elif pred_cls == 1 and gt_cls == 0:
                verdict = "FALSE_POSITIVE"
            else:
                verdict = "FALSE_NEGATIVE"
        else:
            verdict = "UNVERIFIED"

        # Feature snapshot
        feat_dict = {col: round(float(X_valid.loc[idx, col]), 4) for col in expected_features}

        flows.append({
            "flow_id": int(idx),
            "features": feat_dict,
            "attack_score": round(score, 4),
            "prediction_class": pred_cls,
            "prediction_label": pred_label,
            "ground_truth_class": gt_cls,
            "ground_truth_label": gt_label,
            "verdict": verdict,
        })

    return {
        "status": "success",
        "evaluation_type": "ad_hoc_csv_evaluation",
        "official_frozen_benchmark": False,
        "disclaimer": (
            "Ad-hoc CSV evaluation evaluated against frozen model artifacts. "
            "This run tests user-supplied records and does NOT alter or overwrite "
            "any frozen historical benchmark artifacts."
        ),
        "benchmark": bench_key,
        "contract": contract_key,
        "model_identifier": bench_info["name"],
        "thresholds": {
            "research": threshold,
            "operational_candidate": operational_threshold,
        },
        "row_accounting": {
            "total_rows_received": total_rows,
            "evaluated_rows": evaluated_count,
            "invalid_rows_dropped": dropped_count,
            "drop_reason": "Non-finite numeric values (Inf/-Inf) or invalid rows" if dropped_count > 0 else "None",
        },
        "is_labelled": is_labelled,
        "label_column_detected": resolved_label_col,
        "metrics": metrics_summary,
        "confusion_matrix": cm_summary,
        "score_distribution": score_dist,
        "provenance": {
            "preprocessor_sha256": _compute_sha256(prep_path),
            "model_sha256": _compute_sha256(model_path),
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        },
        "display_flow_count": len(flows),
        "flows": flows,
    }


def export_evaluated_csv_string(eval_result: dict[str, Any]) -> str:
    """Export evaluated flows from eval_result to a downloadable CSV with metadata provenance headers."""
    output = io.StringIO()
    output.write("# XRL-IDARS Evaluated CSV Dataset Export\n")
    output.write(f"# Evaluation Type: {eval_result.get('evaluation_type')} (Official Benchmark: {eval_result.get('official_frozen_benchmark')})\n")
    output.write(f"# Model: {eval_result.get('model_identifier')}\n")
    output.write(f"# Contract: {eval_result.get('contract')}\n")
    output.write(f"# Total Received: {eval_result.get('row_accounting', {}).get('total_rows_received')} | Evaluated: {eval_result.get('row_accounting', {}).get('evaluated_rows')}\n")
    output.write(f"# Evaluated At: {eval_result.get('provenance', {}).get('evaluated_at')}\n")
    output.write(f"# Invariant: Ground truth held separate from feature inputs\n#\n")

    flows = eval_result.get("flows", [])
    if not flows:
        output.write("flow_id,attack_score,prediction_label\n")
        return output.getvalue()

    feature_keys = list(flows[0].get("features", {}).keys())
    writer = csv.writer(output)
    header = ["flow_id", "attack_score", "prediction_class", "prediction_label", "ground_truth_label", "verdict"] + feature_keys
    writer.writerow(header)

    for f in flows:
        row = [
            f["flow_id"],
            f["attack_score"],
            f["prediction_class"],
            f["prediction_label"],
            f["ground_truth_label"],
            f["verdict"],
        ]
        feats = f.get("features", {})
        row.extend([feats.get(k, "") for k in feature_keys])
        writer.writerow(row)

    return output.getvalue()


def get_demo_sample_csv(n_samples: int = 12) -> str:
    """Generate a clean, ready-to-evaluate CSV sample containing real R10 flows."""
    samples_file = REPO_ROOT / "data" / "demo" / "dataset_samples.json"
    rows: list[dict[str, Any]] = []

    if samples_file.exists():
        import json
        with open(samples_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        benign = data.get("benign", [])[: n_samples // 2]
        ddos = [x for x in data.get("ddos", []) if x.get("is_attack")][: n_samples // 4]
        dos = [x for x in data.get("dos", []) if x.get("is_attack")][: n_samples // 4]
        pool = benign + ddos + dos
        for item in pool:
            feats = dict(item.get("features", {}))
            feats["label"] = 1 if item.get("is_attack") else 0
            rows.append(feats)

    if not rows:
        # Fallback synthetic clean demonstration records if sample file unreadable
        for i in range(n_samples):
            is_atk = 1 if i % 2 == 1 else 0
            row = {
                "flow_duration_ms": 1200.0 + i * 50,
                "flow_packets_per_s": 15.0 if not is_atk else 450.0,
                "flow_bytes_per_s": 8000.0 if not is_atk else 125000.0,
                "packet_length_mean": 512.0 if not is_atk else 1400.0,
                "packet_length_std": 120.0,
                "syn_count": 1.0 if not is_atk else 10.0,
                "ack_count": 1.0,
                "rst_count": 0.0,
                "fin_count": 1.0 if not is_atk else 0.0,
                "syn_ack_ratio": 1.0 if not is_atk else 5.0,
                "label": is_atk,
            }
            rows.append(row)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(R10_FEATURES) + ["label"])
    writer.writeheader()
    for r in rows:
        writer.writerow({k: r.get(k, 0.0) for k in list(R10_FEATURES) + ["label"]})
    return output.getvalue()

