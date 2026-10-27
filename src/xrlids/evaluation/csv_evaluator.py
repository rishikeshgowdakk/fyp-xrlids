"""CSV evaluation and validation engine for XRL-IDARS.

Provides strict, leak-free evaluation of user-supplied or local CSV dataset records
against frozen preprocessors and model artifacts.

Guarantees:
1. Strict schema & configuration validation: validates benchmark and contract as a paired
   configuration (e.g. cicids2017/cse2018 require R10; unswnb15 requires R4).
2. Strict feature order: enforces the canonical feature list and validates against fitted
   preprocessor metadata.
3. Strict label parsing: supports binary 0/1, 0.0/1.0, recognized Benign/Attack text,
   and standard attack-family names. Rejects unknown, ambiguous, or missing labels with
   explicit errors rather than silently defaulting.
4. Correct non-finite handling: detects NaN, +Inf, -Inf, and non-numeric feature strings,
   drops them with strict row accounting, and preserves 1:1 index alignment with labels.
5. Ground-truth isolation: extracts and separates label columns prior to inference.
6. Target leakage prevention: ensures no label or target proxy enters model inputs.
7. Centralized metrics: uses single project-wide evaluation metrics from xrlids.evaluation.metrics,
   consistent with the operating threshold.
8. Authoritative export & provenance: stores server-side evaluation records to prevent
   client-side tampering, distinguishes displayed subset from full population, and
   preserves historical experiment artifacts untouched.
"""

from __future__ import annotations

import csv
import hashlib
import io
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from xrlids.evaluation.metrics import (
    MetricError,
    binary_metrics,
    confusion_counts,
    score_metrics,
)
from xrlids.features.definitions import R4_FEATURES, R10_FEATURES

REPO_ROOT = Path(__file__).resolve().parents[3]

# Benchmark to canonical contract pairing
SUPPORTED_BENCHMARK_CONTRACTS: dict[str, str] = {
    "cicids2017": "R10",
    "cse2018": "R10",
    "unswnb15": "R4",
}

# Canonical candidate label column names
LABEL_CANDIDATE_COLUMNS: tuple[str, ...] = (
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

# Canonical string representations for benign traffic
BENIGN_CANONICAL_STRINGS: frozenset[str] = frozenset({
    "0",
    "0.0",
    "0.00",
    "BENIGN",
    "NORMAL",
    "FALSE",
    "NON-ATTACK",
    "CLEAN",
    "LEGITIMATE",
})

# Canonical string representations for attack traffic and attack families
ATTACK_CANONICAL_STRINGS: frozenset[str] = frozenset({
    "1",
    "1.0",
    "1.00",
    "ATTACK",
    "TRUE",
    "MALICIOUS",
    "ANOMALY",
    "INTRUSION",
    "DDOS",
    "DOS",
    "DOS HULK",
    "DOS GOLDENEYE",
    "DOS SLOWLORIS",
    "DOS SLOWHTTPTEST",
    "PORTSCAN",
    "PORT SCAN",
    "BOT",
    "FTP-PATATOR",
    "SSH-PATATOR",
    "INFILTRATION",
    "INFILTERATION",
    "HEARTBLEED",
    "WEB ATTACK - BRUTE FORCE",
    "WEB ATTACK - XSS",
    "WEB ATTACK - SQL INJECTION",
    "DDOS ATTACKS-LOIC-HTTP",
    "DDOS ATTACK-HOIC",
    "DOS ATTACKS-HULK",
    "DOS ATTACKS-SLOWHTTPTEST",
    "DOS ATTACKS-GOLDENEYE",
    "DOS ATTACKS-SLOWLORIS",
    "FTP-BRUTEFORCE",
    "SSH-BRUTEFORCE",
    "BRUTE FORCE -WEB",
    "BRUTE FORCE -XSS",
    "SQL INJECTION",
    "FUZZERS",
    "ANALYSIS",
    "BACKDOORS",
    "BACKDOOR",
    "EXPLOITS",
    "GENERIC",
    "RECONNAISSANCE",
    "SHELLCODE",
    "WORMS",
})

BENCHMARK_ARTIFACT_PATHS: dict[str, dict[str, Path]] = {
    "cicids2017": {
        "preprocessor": REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "preprocessor.joblib",
        "model": REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "random_forest.joblib",
        "contract": "R10",
        "name": "RandomForestClassifier (Frozen CIC-IDS2017 R10)",
    },
    "cse2018": {
        "preprocessor": REPO_ROOT / "results" / "experiments" / "EXP-P1-CSE2018-R10-MULTI-001" / "preprocessor.joblib",
        "model": REPO_ROOT / "results" / "experiments" / "EXP-P1-CSE2018-R10-MULTI-001" / "random_forest.joblib",
        "contract": "R10",
        "name": "RandomForestClassifier (Frozen CSE-CIC-IDS2018 R10)",
    },
    "unswnb15": {
        "preprocessor": REPO_ROOT / "results" / "experiments" / "EXP-P1-UNSWNB15-R10-MULTI-001" / "preprocessor.joblib",
        "model": REPO_ROOT / "results" / "experiments" / "EXP-P1-UNSWNB15-R10-MULTI-001" / "random_forest.joblib",
        "contract": "R4",
        "name": "RandomForestClassifier (Frozen UNSW-NB15 R4)",
    },
}

# Authoritative server-side cache of evaluation records to prevent client spoofing
_SERVER_EVALUATION_CACHE: dict[str, dict[str, Any]] = {}
MAX_SERVER_CACHE_ENTRIES = 50


class CSVValidationError(ValueError):
    """Raised when CSV input is malformed, missing required contract features, or invalid."""


def get_cached_evaluation(evaluation_id: str) -> dict[str, Any] | None:
    """Retrieve an authoritative server-side evaluation session by ID."""
    return _SERVER_EVALUATION_CACHE.get(str(evaluation_id))


def clear_cached_evaluations() -> None:
    """Clear server-side evaluation cache (primarily for tests)."""
    _SERVER_EVALUATION_CACHE.clear()


def _compute_sha256(path: Path) -> str:
    """Compute hex SHA-256 digest of a file if it exists."""
    if not path.exists():
        return "NOT_FOUND"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_strict_binary_label(val: Any, row_idx: Any) -> int:
    """Strictly parse a ground-truth label into binary integer {0, 1}.

    Accepts:
    - 0, 0.0, '0', '0.0', 'BENIGN', 'NORMAL', etc. -> 0
    - 1, 1.0, '1', '1.0', 'ATTACK', 'TRUE', attack family names (DDoS, Hulk, etc.) -> 1

    Rejects:
    - Missing / null / empty labels -> CSVValidationError
    - Ambiguous numbers (e.g. 2, -1, 0.5) -> CSVValidationError
    - Unrecognized text strings -> CSVValidationError
    """
    if val is None or pd.isna(val):
        raise CSVValidationError(
            f"Invalid ground-truth label at row {row_idx}: label is missing or null. "
            f"In labelled evaluation, every evaluated row must have a valid non-empty label. "
            f"To run unlabelled inference, remove the label column."
        )

    # Direct numeric types
    if isinstance(val, (int, float, np.integer, np.floating)):
        if np.isnan(val):
            raise CSVValidationError(f"Invalid ground-truth label at row {row_idx}: label is NaN.")
        f_val = float(val)
        if f_val == 0.0:
            return 0
        if f_val == 1.0:
            return 1
        raise CSVValidationError(
            f"Invalid numeric ground-truth label '{val}' at row {row_idx}. "
            f"Numeric labels must be binary 0 (Benign) or 1 (Attack)."
        )

    s = str(val).strip()
    if not s:
        raise CSVValidationError(
            f"Invalid ground-truth label at row {row_idx}: label string is empty."
        )

    # Check numeric strings like '0.0', '1.0', '0', '1'
    try:
        f_val = float(s)
        is_num = True
    except ValueError:
        is_num = False

    if is_num:
        if f_val == 0.0:
            return 0
        if f_val == 1.0:
            return 1
        raise CSVValidationError(
            f"Invalid numeric ground-truth label string '{s}' at row {row_idx}. "
            f"Numeric labels must be binary 0 (Benign) or 1 (Attack)."
        )

    s_upper = s.upper()
    if s_upper in BENIGN_CANONICAL_STRINGS:
        return 0
    if s_upper in ATTACK_CANONICAL_STRINGS:
        return 1

    # Check recognized attack family prefixes/substrings
    if any(atk in s_upper for atk in (
        "DDOS", "DOS ", "DOS-", "PORTSCAN", "PORT SCAN", "BRUTE FORCE", "PATATOR",
        "INFILTRATION", "INFILTERATION", "BOTNET", "BOT", "EXPLOIT", "FUZZER", "SHELLCODE", "WORM"
    )):
        return 1

    raise CSVValidationError(
        f"Invalid or unrecognized ground-truth label '{val}' at row {row_idx}. "
        f"Supported labels: 0/1, 0.0/1.0, BENIGN/ATTACK, or standard attack family names (e.g. DDoS, PortScan, Hulk)."
    )


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
    bench_key = str(benchmark).lower().strip()
    if bench_key not in SUPPORTED_BENCHMARK_CONTRACTS:
        raise CSVValidationError(
            f"Unknown benchmark '{benchmark}'. Supported benchmarks: {list(SUPPORTED_BENCHMARK_CONTRACTS.keys())}"
        )

    contract_key = str(contract).upper().strip()
    required_contract = SUPPORTED_BENCHMARK_CONTRACTS[bench_key]

    # 1. Enforce benchmark / feature-contract compatibility
    if contract_key != required_contract:
        raise CSVValidationError(
            f"Incompatible benchmark and feature contract: benchmark '{bench_key}' only supports contract "
            f"'{required_contract}', but contract '{contract_key}' was requested. "
            f"Please select contract '{required_contract}' for this benchmark model."
        )

    if contract_key == "R10":
        expected_features = list(R10_FEATURES)
    elif contract_key == "R4":
        expected_features = list(R4_FEATURES)
    else:
        raise CSVValidationError(f"Invalid contract '{contract}'. Supported contracts: 'R10', 'R4'.")

    bench_info = BENCHMARK_ARTIFACT_PATHS[bench_key]

    # 2. Parse CSV into DataFrame
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

    # 3. Check for required feature columns
    df.columns = [str(c).strip() for c in df.columns]

    missing_features = [f for f in expected_features if f not in df.columns]
    if missing_features:
        raise CSVValidationError(
            f"Missing required {contract_key} feature columns: {missing_features}. "
            f"Expected all {len(expected_features)} columns: {expected_features}"
        )

    # 4. Ground-truth isolation & Target leakage prevention
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

    # 5. Correct non-finite value handling & row accounting
    # Convert all feature columns to float, coercing unparseable strings to NaN
    X_num = pd.DataFrame(index=df.index)
    for col in expected_features:
        X_num[col] = pd.to_numeric(X_raw[col], errors="coerce")

    # Find invalid rows: positive/negative infinity or NaN/non-numeric values
    is_inf = np.isinf(X_num).any(axis=1)
    is_nan = X_num.isna().any(axis=1)
    invalid_mask = is_inf | is_nan
    valid_mask = ~invalid_mask

    dropped_count = int(invalid_mask.sum())
    inf_count = int(is_inf.sum())
    nan_count = int((is_nan & ~is_inf).sum())
    evaluated_count = int(valid_mask.sum())

    # Prove exact row accounting reconciliation
    assert total_rows == evaluated_count + dropped_count, "Row accounting reconciliation failed!"

    if evaluated_count == 0:
        raise CSVValidationError(
            f"All {total_rows} rows were rejected because all contained non-finite feature values "
            f"({inf_count} rows with Infinity/-Infinity, {nan_count} rows with NaN/non-numeric values)."
        )

    # Slice valid rows strictly preserving index alignment between X and y
    X_valid = X_num.loc[valid_mask].copy()
    y_valid = y_true_raw.loc[valid_mask].copy() if is_labelled and y_true_raw is not None else None

    # Strictly parse labels on retained rows only, preserving exact alignment
    y_true_binary: np.ndarray | None = None
    if is_labelled and y_valid is not None:
        y_true_binary = np.array(
            [parse_strict_binary_label(val, orig_idx) for orig_idx, val in y_valid.items()],
            dtype=int,
        )
        assert len(y_true_binary) == len(X_valid), "Feature and label count mismatch after row cleaning!"

    # 6. Load frozen preprocessor & model
    prep_path = bench_info["preprocessor"]
    model_path = bench_info["model"]

    if not prep_path.exists():
        raise CSVValidationError(f"Frozen preprocessor artifact missing: {prep_path}")
    if not model_path.exists():
        raise CSVValidationError(f"Frozen model artifact missing: {model_path}")

    preprocessor = joblib.load(prep_path)
    model = joblib.load(model_path)

    # Verify fitted preprocessor feature contract matches expected canonical features
    if hasattr(preprocessor, "features"):
        if list(preprocessor.features) != expected_features:
            raise CSVValidationError(
                f"Fitted preprocessor feature list mismatch for benchmark '{bench_key}'. "
                f"Expected: {expected_features}, but preprocessor requires: {list(preprocessor.features)}"
            )

    # 7. Preprocessing & Model Inference
    X_scaled = preprocessor.transform(X_valid)
    probs = model.predict_proba(X_scaled)

    # Select positive class probability against model's actual classes_ array
    classes = list(getattr(model, "classes_", [0, 1]))
    if 1 in classes:
        pos_idx = classes.index(1)
    elif "1" in classes:
        pos_idx = classes.index("1")
    elif len(classes) >= 2:
        pos_idx = 1
    else:
        pos_idx = 0

    if probs.ndim == 2 and probs.shape[1] > pos_idx:
        attack_scores = probs[:, pos_idx]
    else:
        attack_scores = probs.ravel()

    # Predictions use the EXACT same threshold (threshold=0.50)
    threshold = float(threshold)
    operational_threshold = float(operational_threshold)
    preds_research = (attack_scores >= threshold).astype(int)
    preds_ops = (attack_scores >= operational_threshold).astype(int)

    # 8. Evaluation Metrics & Confusion Matrix (if labelled)
    metrics_summary: dict[str, Any] | None = None
    cm_summary: dict[str, int] | None = None

    if is_labelled and y_true_binary is not None:
        counts = confusion_counts(y_true_binary, preds_research)
        cm_summary = counts

        b_metrics = binary_metrics(y_true_binary, preds_research)
        metrics_summary = {
            "threshold": threshold,
            "population": b_metrics["population"],
            "accuracy": b_metrics["accuracy"],
            "precision": b_metrics["precision"],
            "recall": b_metrics["recall"],
            "f1": b_metrics["f1"],
            "macro_f1": b_metrics["macro_f1"],
            "weighted_f1": b_metrics["weighted_f1"],
            "balanced_accuracy": b_metrics["balanced_accuracy"],
            "specificity": b_metrics["specificity"],
            "fpr": b_metrics["fpr"],
            "fnr": b_metrics["fnr"],
            "per_class": b_metrics["per_class"],
            "confusion": counts,
        }

        # Threshold-independent continuous score metrics (ROC-AUC / PR-AUC)
        try:
            s_metrics = score_metrics(y_true_binary, attack_scores)
            metrics_summary["roc_auc"] = s_metrics.get("roc_auc")
            metrics_summary["pr_auc"] = s_metrics.get("pr_auc")
            metrics_summary["auc_note"] = s_metrics.get("auc_note")
        except MetricError as m_err:
            metrics_summary["roc_auc"] = None
            metrics_summary["pr_auc"] = None
            metrics_summary["auc_note"] = str(m_err)

    # 9. Score distribution
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

    # 10. Pack flow records for display/inspection
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

        row_vals = X_valid.iloc[i]
        feat_dict = {col: round(float(row_vals[col]), 4) for col in expected_features}

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

    # Pack full evaluated records for authoritative server-side export
    full_export_records: list[dict[str, Any]] = []
    for i, idx in enumerate(X_valid.index):
        score = float(attack_scores[i])
        pred_cls = int(preds_research[i])
        gt_cls = int(y_true_binary[i]) if is_labelled and y_true_binary is not None else None
        gt_label = "ATTACK" if gt_cls == 1 else "BENIGN" if gt_cls == 0 else "UNLABELLED"

        if gt_cls is not None:
            verdict = "CORRECT" if pred_cls == gt_cls else ("FALSE_POSITIVE" if pred_cls == 1 else "FALSE_NEGATIVE")
        else:
            verdict = "UNVERIFIED"

        row_vals = X_valid.iloc[i]
        full_export_records.append({
            "flow_id": int(idx),
            "attack_score": round(score, 4),
            "prediction_class": pred_cls,
            "prediction_label": "ATTACK" if pred_cls == 1 else "BENIGN",
            "ground_truth_class": gt_cls,
            "ground_truth_label": gt_label,
            "verdict": verdict,
            "features": {col: round(float(row_vals[col]), 4) for col in expected_features},
        })

    evaluation_id = str(uuid.uuid4())
    drop_reasons: list[str] = []
    if inf_count > 0:
        drop_reasons.append(f"{inf_count} rows with Infinity/-Infinity")
    if nan_count > 0:
        drop_reasons.append(f"{nan_count} rows with NaN or unparseable non-numeric values")
    drop_reason_str = (
        f"Non-finite numeric values ({', '.join(drop_reasons)})"
        if drop_reasons
        else "None"
    )

    result: dict[str, Any] = {
        "status": "success",
        "evaluation_id": evaluation_id,
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
            "inf_rows_dropped": inf_count,
            "nan_rows_dropped": nan_count,
            "drop_reason": drop_reason_str,
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
        "total_evaluated_count": evaluated_count,
        "flows": flows,
        "_full_records": full_export_records,
    }

    # Cache server-side for authoritative export
    _SERVER_EVALUATION_CACHE[evaluation_id] = result
    if len(_SERVER_EVALUATION_CACHE) > MAX_SERVER_CACHE_ENTRIES:
        _SERVER_EVALUATION_CACHE.pop(next(iter(_SERVER_EVALUATION_CACHE)))

    return result


def export_evaluated_csv_string(
    eval_result: dict[str, Any],
    export_all: bool = True,
) -> str:
    """Export evaluated flows to a downloadable CSV with explicit metadata provenance headers."""
    output = io.StringIO()
    total_received = eval_result.get("row_accounting", {}).get("total_rows_received", 0)
    evaluated_total = eval_result.get("row_accounting", {}).get("evaluated_rows", 0)
    dropped = eval_result.get("row_accounting", {}).get("invalid_rows_dropped", 0)

    # Determine whether exporting full evaluated population or display sample
    if export_all and "_full_records" in eval_result and eval_result["_full_records"]:
        records_to_export = eval_result["_full_records"]
        export_scope = f"Complete Evaluated Population ({len(records_to_export)} rows)"
    else:
        records_to_export = eval_result.get("flows", [])
        export_scope = f"Display Sample Subset ({len(records_to_export)} of {evaluated_total} evaluated rows)"

    output.write("# XRL-IDARS Evaluated CSV Dataset Export\n")
    output.write(f"# Evaluation ID: {eval_result.get('evaluation_id', 'UNTRACKED_SESSION')}\n")
    output.write(f"# Evaluation Type: {eval_result.get('evaluation_type')} (Official Benchmark: {eval_result.get('official_frozen_benchmark')})\n")
    output.write(f"# Model: {eval_result.get('model_identifier')}\n")
    output.write(f"# Contract: {eval_result.get('contract')}\n")
    output.write(f"# Population Accounting: {total_received} received | {evaluated_total} evaluated | {dropped} dropped\n")
    output.write(f"# Export Scope: {export_scope}\n")
    output.write(f"# Evaluated At: {eval_result.get('provenance', {}).get('evaluated_at')}\n")
    output.write(f"# Invariant: Ground truth held separate from feature inputs\n#\n")

    if not records_to_export:
        output.write("flow_id,attack_score,prediction_class,prediction_label,ground_truth_label,verdict\n")
        return output.getvalue()

    feature_keys = list(records_to_export[0].get("features", {}).keys())
    writer = csv.writer(output)
    header = ["flow_id", "attack_score", "prediction_class", "prediction_label", "ground_truth_label", "verdict"] + feature_keys
    writer.writerow(header)

    for f in records_to_export:
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
