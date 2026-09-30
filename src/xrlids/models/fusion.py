"""Score-level RF/LSTM fusion (build spec section 18; Checkpoint 6).

    fusion_score = alpha * rf_score + (1 - alpha) * lstm_score

Mean fusion is ``alpha = 0.5``. Fusion is only meaningful if the two score vectors are
aligned on the *same population*: :func:`align_scores` makes that requirement explicit
and refuses to silently compare different populations.

Fusion is not assumed to help. If it does not beat its components, that is a valid
research result (RQ3) and is reported as such.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd

from xrlids.evaluation.metrics import evaluate


class FusionError(ValueError):
    """Raised when scores cannot be validly fused."""


@dataclass
class FusionResult:
    scores: np.ndarray
    alpha: float
    alignment: dict[str, Any]

    def as_series(self, index: pd.Index | None = None) -> pd.Series:
        return pd.Series(self.scores, index=index, name="fusion_score")


def align_scores(
    rf: pd.Series,
    lstm: pd.Series,
    *,
    how: str = "inner",
) -> tuple[pd.Series, pd.Series, dict[str, Any]]:
    """Align two score series on a common index.

    Reports the size of each input and the size of the intersection, so the evaluation
    population is never ambiguous. ``inner`` is the default; ``strict`` demands exact
    index equality and is used when the two models were scored on the very same rows.
    """
    if how == "strict":
        if not rf.index.equals(lstm.index):
            raise FusionError(
                "score indices differ; a strict comparison requires identical populations "
                f"(rf={len(rf)} rows, lstm={len(lstm)} rows)"
            )
        aligned_rf, aligned_lstm = rf, lstm
    elif how == "inner":
        common = rf.index.intersection(lstm.index)
        aligned_rf = rf.loc[common]
        aligned_lstm = lstm.loc[common]
    else:
        raise FusionError(f"unknown alignment 'how={how}'")

    report = {
        "how": how,
        "rf_rows": int(len(rf)),
        "lstm_rows": int(len(lstm)),
        "aligned_rows": int(len(aligned_rf)),
        "dropped_from_rf": int(len(rf) - len(aligned_rf)),
        "dropped_from_lstm": int(len(lstm) - len(aligned_lstm)),
        "population_warning": (
            "components evaluated on different populations; fusion comparison is only "
            "valid on the aligned intersection"
            if len(rf) != len(lstm)
            else None
        ),
    }
    return aligned_rf, aligned_lstm, report


def fuse_scores(
    rf: pd.Series,
    lstm: pd.Series,
    *,
    alpha: float = 0.5,
    how: str = "inner",
) -> FusionResult:
    """Weighted mean of aligned RF and LSTM scores."""
    if not 0.0 <= alpha <= 1.0:
        raise FusionError(f"alpha must be in [0,1], got {alpha}")
    aligned_rf, aligned_lstm, report = align_scores(rf, lstm, how=how)
    if len(aligned_rf) == 0:
        raise FusionError("no aligned rows; cannot fuse")
    scores = alpha * aligned_rf.to_numpy(dtype=float) + (1.0 - alpha) * aligned_lstm.to_numpy(dtype=float)
    return FusionResult(
        scores=scores,
        alpha=alpha,
        alignment={**report, "alpha": alpha, "formula": "alpha*rf + (1-alpha)*lstm"},
    )


def fuse(rf_scores: np.ndarray, lstm_scores: np.ndarray, alpha: float = 0.5) -> np.ndarray:
    """Array-level weighted mean (no alignment checks; use :func:`fuse_scores` in pipelines)."""
    if rf_scores.shape != lstm_scores.shape:
        raise FusionError(f"shape mismatch: {rf_scores.shape} vs {lstm_scores.shape}")
    return alpha * rf_scores + (1.0 - alpha) * lstm_scores


def compare_components(
    y_true: pd.Series,
    rf: pd.Series,
    lstm: pd.Series,
    *,
    alpha: float = 0.5,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Evaluate RF, LSTM and Fusion on the SAME aligned population (RQ2/RQ3)."""
    aligned_rf, aligned_lstm, report = align_scores(rf, lstm, how="inner")
    y = y_true.loc[aligned_rf.index]
    fusion = fuse_scores(aligned_rf, aligned_lstm, alpha=alpha, how="strict")
    return {
        "alignment": report,
        "threshold": threshold,
        "rf": evaluate(y, aligned_rf, threshold),
        "lstm": evaluate(y, aligned_lstm, threshold),
        "fusion": evaluate(y, fusion.scores, threshold),
        "alpha": alpha,
    }


def tune_fusion_alpha(
    val_rf: pd.Series,
    val_lstm: pd.Series,
    y_val: pd.Series,
    *,
    metric: str = "roc_auc",
    alpha_grid: Sequence[float] | None = None,
) -> dict[str, Any]:
    """Tune fusion weight alpha on VALIDATION data only (never test data).

    Sweeps candidate alphas across [0.0, 1.0] and chooses the alpha that maximizes
    the specified validation metric (default: roc_auc).
    """
    if alpha_grid is None:
        alpha_grid = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

    aligned_rf, aligned_lstm, report = align_scores(val_rf, val_lstm, how="inner")
    y_aligned = y_val.loc[aligned_rf.index]

    sweep_results = []
    best_alpha = 0.5
    best_metric_val = -float("inf")

    rf_arr = aligned_rf.to_numpy(dtype=float)
    lstm_arr = aligned_lstm.to_numpy(dtype=float)
    y_arr = y_aligned.to_numpy(dtype=int)

    for a in alpha_grid:
        scores = a * rf_arr + (1.0 - a) * lstm_arr
        m = evaluate(y_arr, scores, threshold=0.5)
        score_val = m.get(metric)
        if score_val is not None:
            # If strictly better, or tied and closer to 0.5 (balanced prior)
            is_better = score_val > best_metric_val + 1e-9
            is_tied = abs(score_val - best_metric_val) <= 1e-9 and abs(a - 0.5) < abs(best_alpha - 0.5)
            if is_better or is_tied:
                best_metric_val = score_val
                best_alpha = float(a)
        sweep_results.append({
            "alpha": float(a),
            "metric": metric,
            "metric_value": score_val,
            "f1": m.get("f1"),
            "roc_auc": m.get("roc_auc"),
            "pr_auc": m.get("pr_auc"),
        })

    return {
        "best_alpha": best_alpha,
        "target_metric": metric,
        "best_metric_value": best_metric_val,
        "sweep": sweep_results,
        "population": report,
        "note": "Alpha was tuned strictly on validation data. Test set was not used for weight selection.",
    }

