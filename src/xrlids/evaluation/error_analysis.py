"""Deterministic Error Analysis Module (build spec section 26).

Provides rigorous, reproducible analysis of model errors:
- False Positives (FPs) and False Negatives (FNs)
- Confidence distributions broken down by outcome group (TP, TN, FP, FN)
- Difficult samples (highest-confidence false alarms, lowest-confidence missed attacks)
- Duplicate-subset evaluation (unique test flows vs. duplicate test flows)
- Model disagreement analysis between RF and LSTM (where each succeeds/fails)
- Fusion rescue vs. fusion degradation analysis
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from xrlids.evaluation.metrics import binary_metrics


def _summary_stats(values: np.ndarray) -> dict[str, float | None]:
    """Summary statistics for continuous confidence scores."""
    if len(values) == 0:
        return {
            "count": 0,
            "mean": None,
            "std": None,
            "median": None,
            "min": None,
            "max": None,
            "p25": None,
            "p75": None,
        }
    return {
        "count": int(len(values)),
        "mean": float(np.mean(values)),
        "std": float(np.std(values)),
        "median": float(np.median(values)),
        "min": float(np.min(values)),
        "max": float(np.max(values)),
        "p25": float(np.percentile(values, 25)),
        "p75": float(np.percentile(values, 75)),
    }


def compute_error_analysis(
    y_true: pd.Series | np.ndarray,
    y_score: pd.Series | np.ndarray,
    *,
    threshold: float = 0.5,
    features_df: pd.DataFrame | None = None,
    duplicate_mask: pd.Series | np.ndarray | None = None,
    n_difficult: int = 5,
) -> dict[str, Any]:
    """Compute error analysis metrics for a given model score series."""
    yt = np.asarray(y_true, dtype=int)
    ys = np.asarray(y_score, dtype=float)

    if len(yt) != len(ys):
        raise ValueError("y_true and y_score must have equal length")

    preds = (ys >= threshold).astype(int)
    metrics = binary_metrics(yt, preds)

    tp_mask = (yt == 1) & (preds == 1)
    tn_mask = (yt == 0) & (preds == 0)
    fp_mask = (yt == 0) & (preds == 1)
    fn_mask = (yt == 1) & (preds == 0)

    # Confidence distributions
    distributions = {
        "true_positives": _summary_stats(ys[tp_mask]),
        "true_negatives": _summary_stats(ys[tn_mask]),
        "false_positives": _summary_stats(ys[fp_mask]),
        "false_negatives": _summary_stats(ys[fn_mask]),
    }

    # Deterministic difficult samples
    # Worst false negatives: true attack, but predicted with lowest probability
    fn_indices = np.where(fn_mask)[0]
    if len(fn_indices) > 0:
        worst_fn_order = fn_indices[np.argsort(ys[fn_indices])[:n_difficult]]
        worst_fn = []
        for idx in worst_fn_order:
            item: dict[str, Any] = {
                "index": int(idx),
                "true_label": int(yt[idx]),
                "predicted_score": float(ys[idx]),
                "predicted_label": int(preds[idx]),
            }
            if features_df is not None and idx < len(features_df):
                item["features"] = features_df.iloc[idx].to_dict()
            worst_fn.append(item)
    else:
        worst_fn = []

    # Worst false positives: true benign, but predicted with highest probability
    fp_indices = np.where(fp_mask)[0]
    if len(fp_indices) > 0:
        worst_fp_order = fp_indices[np.argsort(-ys[fp_indices])[:n_difficult]]
        worst_fp = []
        for idx in worst_fp_order:
            item: dict[str, Any] = {
                "index": int(idx),
                "true_label": int(yt[idx]),
                "predicted_score": float(ys[idx]),
                "predicted_label": int(preds[idx]),
            }
            if features_df is not None and idx < len(features_df):
                item["features"] = features_df.iloc[idx].to_dict()
            worst_fp.append(item)
    else:
        worst_fp = []

    # Duplicate breakdown (Policy B support)
    duplicate_breakdown: dict[str, Any] | None = None
    if duplicate_mask is not None:
        dm = np.asarray(duplicate_mask, dtype=bool)
        if len(dm) == len(yt):
            uniq_mask = ~dm
            dupe_metrics = (
                binary_metrics(yt[dm], preds[dm]) if np.any(dm) else {"note": "no duplicate rows in subset"}
            )
            uniq_metrics = (
                binary_metrics(yt[uniq_mask], preds[uniq_mask])
                if np.any(uniq_mask)
                else {"note": "no unique rows in subset"}
            )
            duplicate_breakdown = {
                "evaluated": True,
                "total_rows": int(len(yt)),
                "duplicate_rows": int(np.sum(dm)),
                "unique_rows": int(np.sum(uniq_mask)),
                "duplicate_subset_metrics": dupe_metrics,
                "unique_subset_metrics": uniq_metrics,
            }

    return {
        "threshold": float(threshold),
        "total_evaluated": int(len(yt)),
        "confusion": metrics["confusion"],
        "rates": {
            "accuracy": metrics["accuracy"],
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "fpr": metrics["fpr"],
            "fnr": metrics["fnr"],
            "balanced_accuracy": metrics["balanced_accuracy"],
        },
        "confidence_distributions": distributions,
        "difficult_samples": {
            "worst_false_negatives": worst_fn,
            "worst_false_positives": worst_fp,
        },
        "duplicate_subset_analysis": duplicate_breakdown,
    }


def analyze_model_disagreements(
    y_true: pd.Series | np.ndarray,
    rf_score: pd.Series | np.ndarray,
    lstm_score: pd.Series | np.ndarray,
    *,
    fusion_score: pd.Series | np.ndarray | None = None,
    threshold: float = 0.5,
    n_examples: int = 5,
) -> dict[str, Any]:
    """Analyze predictions where RF and LSTM disagree on the aligned population."""
    yt = np.asarray(y_true, dtype=int)
    rf_s = np.asarray(rf_score, dtype=float)
    lstm_s = np.asarray(lstm_score, dtype=float)

    if not (len(yt) == len(rf_s) == len(lstm_s)):
        raise ValueError("y_true, rf_score, and lstm_score must have equal length")

    rf_p = (rf_s >= threshold).astype(int)
    lstm_p = (lstm_s >= threshold).astype(int)

    disagree_mask = rf_p != lstm_p
    disagree_count = int(np.sum(disagree_mask))
    disagree_fraction = float(disagree_count / max(1, len(yt)))

    # RF positive (1), LSTM negative (0)
    rf_pos_lstm_neg = (rf_p == 1) & (lstm_p == 0)
    rf_correct_when_lstm_wrong = int(np.sum(rf_pos_lstm_neg & (yt == 1)))
    rf_wrong_when_lstm_right = int(np.sum(rf_pos_lstm_neg & (yt == 0)))

    # RF negative (0), LSTM positive (1)
    rf_neg_lstm_pos = (rf_p == 0) & (lstm_p == 1)
    lstm_correct_when_rf_wrong = int(np.sum(rf_neg_lstm_pos & (yt == 1)))
    lstm_wrong_when_rf_right = int(np.sum(rf_neg_lstm_pos & (yt == 0)))

    # Fusion role analysis
    fusion_analysis: dict[str, Any] | None = None
    if fusion_score is not None:
        fus_s = np.asarray(fusion_score, dtype=float)
        fus_p = (fus_s >= threshold).astype(int)

        both_wrong = (rf_p != yt) & (lstm_p != yt)
        one_wrong = (rf_p != yt) ^ (lstm_p != yt)
        both_right = (rf_p == yt) & (lstm_p == yt)

        # Fusion rescues: at least one was wrong, but fusion got it right
        fusion_rescues = int(np.sum(one_wrong & (fus_p == yt)))
        fusion_rescues_from_both_wrong = int(np.sum(both_wrong & (fus_p == yt)))

        # Fusion degrades: both were right, but fusion was wrong
        fusion_degrades = int(np.sum(both_right & (fus_p != yt)))

        fusion_analysis = {
            "fusion_rescues_when_one_model_failed": fusion_rescues,
            "fusion_rescues_when_both_models_failed": fusion_rescues_from_both_wrong,
            "fusion_degradations_when_both_were_right": fusion_degrades,
            "fusion_accuracy_on_disagreements": (
                float(np.mean(fus_p[disagree_mask] == yt[disagree_mask])) if disagree_count > 0 else None
            ),
        }

    # Deterministic representative disagreement examples
    disagree_indices = np.where(disagree_mask)[0][:n_examples]
    examples = []
    for idx in disagree_indices:
        ex: dict[str, Any] = {
            "index": int(idx),
            "true_label": int(yt[idx]),
            "rf_score": float(rf_s[idx]),
            "rf_pred": int(rf_p[idx]),
            "lstm_score": float(lstm_s[idx]),
            "lstm_pred": int(lstm_p[idx]),
        }
        if fusion_score is not None:
            ex["fusion_score"] = float(fus_s[idx])
            ex["fusion_pred"] = int(fus_p[idx])
        examples.append(ex)

    return {
        "threshold": float(threshold),
        "aligned_population_size": int(len(yt)),
        "disagreement_count": disagree_count,
        "disagreement_fraction": disagree_fraction,
        "rf_pos_lstm_neg": {
            "count": int(np.sum(rf_pos_lstm_neg)),
            "true_attacks_rf_right": rf_correct_when_lstm_wrong,
            "true_benign_rf_false_alarm": rf_wrong_when_lstm_right,
        },
        "rf_neg_lstm_pos": {
            "count": int(np.sum(rf_neg_lstm_pos)),
            "true_attacks_lstm_right": lstm_correct_when_rf_wrong,
            "true_benign_lstm_false_alarm": lstm_wrong_when_rf_right,
        },
        "fusion_analysis": fusion_analysis,
        "representative_disagreement_examples": examples,
    }
