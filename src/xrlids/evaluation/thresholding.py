"""Threshold analysis (build spec sections 19, 31, 32).

Critical rule
-------------
The threshold objective is an OPEN research decision (**D-003**). This module therefore
implements the *infrastructure* and reports **candidate operating points** for several
objectives. It does NOT pick one. No selection happens on the test set under any
circumstances: candidate thresholds are computed on the validation population, and any
report states which population it used.

Explicitly blocked until D-003 is decided:
    freezing a single operating threshold
    reporting a headline precision/recall at "the" threshold
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np
import pandas as pd

from xrlids.evaluation.metrics import binary_metrics

DECISION_ID = "D-003"
DECISION_STATUS = "OPEN - USER DECISION REQUIRED"
RESEARCH_BASELINE_THRESHOLD: float = 0.50
OPERATIONAL_THRESHOLD: float = 0.40

OBJECTIVES: tuple[str, ...] = (
    "max_f1",
    "min_fpr_subject_to_recall_floor",
    "min_fnr_subject_to_fpr_ceiling",
    "cost_sensitive",
)


class ThresholdError(ValueError):
    """Raised when a threshold sweep is requested with invalid inputs."""


def threshold_sweep(
    y_true: pd.Series | np.ndarray,
    y_score: pd.Series | np.ndarray,
    *,
    thresholds: Sequence[float] | None = None,
) -> pd.DataFrame:
    """Metrics for every threshold in an explicit grid (default 0.00..1.00 step 0.01)."""
    yt = np.asarray(y_true, dtype=int)
    ys = np.asarray(y_score, dtype=float)
    if yt.shape != ys.shape:
        raise ThresholdError("y_true and y_score must have the same shape")
    if thresholds is None:
        thresholds = np.round(np.arange(0.0, 1.0001, 0.01), 4)

    rows = []
    for t in thresholds:
        pred = (ys >= t).astype(int)
        m = binary_metrics(yt, pred)
        rows.append(
            {
                "threshold": float(t),
                "tp": m["confusion"]["tp"],
                "tn": m["confusion"]["tn"],
                "fp": m["confusion"]["fp"],
                "fn": m["confusion"]["fn"],
                "precision": m["precision"],
                "recall": m["recall"],
                "f1": m["f1"],
                "macro_f1": m["macro_f1"],
                "accuracy": m["accuracy"],
                "fpr": m["fpr"],
                "fnr": m["fnr"],
                "balanced_accuracy": m["balanced_accuracy"],
            }
        )
    return pd.DataFrame(rows)


def candidate_operating_points(
    sweep: pd.DataFrame,
    *,
    recall_floor: float = 0.95,
    fpr_ceiling: float = 0.01,
    fp_cost: float = 1.0,
    fn_cost: float = 10.0,
) -> dict[str, Any]:
    """Compute the threshold each objective WOULD choose. Reports, does not decide.

    The cost-sensitive case exposes its cost assumptions explicitly, because a
    cost-sensitive objective is only meaningful once FP/FN costs are justified for the
    deployment — which the project has not yet done.
    """
    candidates: dict[str, Any] = {}

    best_f1 = sweep.loc[sweep["f1"].idxmax()]
    candidates["max_f1"] = {"threshold": float(best_f1["threshold"]), "f1": float(best_f1["f1"])}

    feasible = sweep[sweep["recall"] >= recall_floor]
    if len(feasible):
        pick = feasible.loc[feasible["fpr"].idxmin()]
        candidates["min_fpr_subject_to_recall_floor"] = {
            "threshold": float(pick["threshold"]),
            "recall": float(pick["recall"]),
            "fpr": float(pick["fpr"]),
            "constraint": {"recall_floor": recall_floor},
        }
    else:
        candidates["min_fpr_subject_to_recall_floor"] = {
            "threshold": None,
            "note": f"no threshold achieves recall >= {recall_floor}",
        }

    feasible2 = sweep[sweep["fpr"] <= fpr_ceiling]
    if len(feasible2):
        pick2 = feasible2.loc[feasible2["fnr"].idxmin()]
        candidates["min_fnr_subject_to_fpr_ceiling"] = {
            "threshold": float(pick2["threshold"]),
            "fnr": float(pick2["fnr"]),
            "fpr": float(pick2["fpr"]),
            "constraint": {"fpr_ceiling": fpr_ceiling},
        }
    else:
        candidates["min_fnr_subject_to_fpr_ceiling"] = {
            "threshold": None,
            "note": f"no threshold achieves FPR <= {fpr_ceiling}",
        }

    cost = fp_cost * sweep["fp"] + fn_cost * sweep["fn"]
    pick3 = sweep.loc[cost.idxmin()]
    candidates["cost_sensitive"] = {
        "threshold": float(pick3["threshold"]),
        "expected_cost": float(cost.min()),
        "assumptions": {"fp_cost": fp_cost, "fn_cost": fn_cost},
        "caveat": "costs are illustrative defaults, not project-justified values",
    }

    return {
        "decision_id": DECISION_ID,
        "decision_status": DECISION_STATUS,
        "note": (
            "These are candidate operating points for comparison only. No objective has "
            "been selected; a single operating threshold must not be frozen until D-003 "
            "is decided by the project owner."
        ),
        "objectives_available": list(OBJECTIVES),
        "candidates": candidates,
    }
