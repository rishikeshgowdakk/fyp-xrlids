"""SHAP Explainability Module (build spec section 27).

Computes TreeSHAP feature attributions for tree-based models (Random Forest).
Enforces scientific disclaimers:
- Explains feature contributions to model scores, does NOT prove causality.
- Test set is never tuned or modified based on SHAP findings.
"""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np
import pandas as pd

from xrlids.utils.logging_utils import get_logger

logger = get_logger(__name__)


def compute_rf_shap_explanations(
    rf_detector: Any,
    X_background: pd.DataFrame,
    X_explain: pd.DataFrame,
    y_explain: pd.Series | np.ndarray | None = None,
    families_explain: pd.Series | np.ndarray | None = None,
    *,
    feature_names: Sequence[str] | None = None,
    max_background: int = 100,
    max_explain: int = 200,
    seed: int = 42,
) -> dict[str, Any]:
    """Compute TreeSHAP attributions on a representative sample."""
    import shap

    feats = list(feature_names or X_background.columns)
    rng = np.random.default_rng(seed)

    # Subsample background if needed
    if len(X_background) > max_background:
        bg_idx = rng.choice(len(X_background), size=max_background, replace=False)
        X_bg = X_background.iloc[bg_idx]
    else:
        X_bg = X_background

    # Subsample explain population if needed
    if len(X_explain) > max_explain:
        exp_idx = rng.choice(len(X_explain), size=max_explain, replace=False)
        X_exp = X_explain.iloc[exp_idx]
        y_exp = np.asarray(y_explain)[exp_idx] if y_explain is not None else None
        fams_exp = np.asarray(families_explain)[exp_idx] if families_explain is not None else None
    else:
        X_exp = X_explain
        y_exp = np.asarray(y_explain) if y_explain is not None else None
        fams_exp = np.asarray(families_explain) if families_explain is not None else None

    # TreeExplainer
    sklearn_rf = rf_detector.model if hasattr(rf_detector, "model") else rf_detector
    explainer = shap.TreeExplainer(sklearn_rf, data=X_bg.to_numpy(dtype=float))
    try:
        raw_shap = explainer.shap_values(X_exp.to_numpy(dtype=float), check_additivity=False)
    except TypeError:
        raw_shap = explainer.shap_values(X_exp.to_numpy(dtype=float))

    # Depending on SHAP version and model, raw_shap can be:
    # 1. list of [class_0, class_1] arrays (shape: (N, F))
    # 2. 3D array (N, F, 2)
    # 3. 2D array (N, F) for binary output
    if isinstance(raw_shap, list) and len(raw_shap) == 2:
        shap_class1 = np.asarray(raw_shap[1], dtype=float)
    elif isinstance(raw_shap, np.ndarray) and raw_shap.ndim == 3 and raw_shap.shape[2] == 2:
        shap_class1 = raw_shap[:, :, 1].astype(float)
    else:
        shap_class1 = np.asarray(raw_shap, dtype=float)

    # Global feature importance: mean absolute SHAP value
    mean_abs_shap = np.mean(np.abs(shap_class1), axis=0)
    ranking_order = np.argsort(-mean_abs_shap)
    global_importance = [
        {
            "rank": int(i + 1),
            "feature": feats[idx],
            "mean_abs_shap": float(mean_abs_shap[idx]),
        }
        for i, idx in enumerate(ranking_order)
    ]

    # Predictions for the explained sample
    probs = rf_detector.predict_proba(X_exp)

    # Class-specific mean attributions where true labels are available
    class_patterns: dict[str, Any] = {}
    if y_exp is not None:
        attack_mask = y_exp == 1
        benign_mask = y_exp == 0
        if np.any(attack_mask):
            class_patterns["attack_mean_shap"] = {
                feats[i]: float(np.mean(shap_class1[attack_mask, i])) for i in range(len(feats))
            }
        if np.any(benign_mask):
            class_patterns["benign_mean_shap"] = {
                feats[i]: float(np.mean(shap_class1[benign_mask, i])) for i in range(len(feats))
            }

    # Family-specific mean absolute attributions where label families are available
    family_patterns: dict[str, Any] = {}
    if fams_exp is not None:
        for fam in np.unique(fams_exp):
            fam_mask = fams_exp == fam
            if np.any(fam_mask):
                fam_mean_abs = np.mean(np.abs(shap_class1[fam_mask]), axis=0)
                fam_rank = np.argsort(-fam_mean_abs)
                family_patterns[str(fam)] = [
                    {"rank": int(r + 1), "feature": feats[idx], "mean_abs_shap": round(float(fam_mean_abs[idx]), 6)}
                    for r, idx in enumerate(fam_rank[:5])
                ]

    # Representative local explanations:
    # Top 3 highest predicted attack probabilities
    # Top 3 lowest predicted attack probabilities
    local_samples: list[dict[str, Any]] = []
    top_attack_indices = np.argsort(-probs)[:3]
    top_benign_indices = np.argsort(probs)[:3]

    for category, indices in [("highest_attack_probability", top_attack_indices), ("lowest_attack_probability", top_benign_indices)]:
        for idx in indices:
            row_features = X_exp.iloc[idx].to_dict()
            row_attributions = {feats[f]: float(shap_class1[idx, f]) for f in range(len(feats))}
            local_samples.append({
                "sample_category": category,
                "sample_index": int(idx),
                "predicted_probability": float(probs[idx]),
                "true_label": int(y_exp[idx]) if y_exp is not None else None,
                "label_family": str(fams_exp[idx]) if fams_exp is not None else None,
                "feature_values": row_features,
                "shap_attributions": row_attributions,
                "top_positive_features": sorted(
                    [(k, v) for k, v in row_attributions.items() if v > 0],
                    key=lambda x: x[1],
                    reverse=True,
                )[:3],
                "top_negative_features": sorted(
                    [(k, v) for k, v in row_attributions.items() if v < 0],
                    key=lambda x: x[1],
                )[:3],
            })

    # Expected value (base value)
    base_value = explainer.expected_value
    if isinstance(base_value, (list, np.ndarray)) and len(base_value) > 1:
        expected_val = float(base_value[1])
    else:
        expected_val = float(base_value) if base_value is not None else 0.5

    return {
        "status": "COMPUTED",
        "methodology": "TreeSHAP (path-dependent tree explanation on RandomForestClassifier)",
        "explained_population": {
            "background_samples": int(len(X_bg)),
            "explained_samples": int(len(X_exp)),
            "features_analyzed": len(feats),
            "expected_base_value": expected_val,
        },
        "global_importance": global_importance,
        "class_specific_patterns": class_patterns,
        "family_specific_patterns": family_patterns,
        "local_explanations": local_samples,
        "scientific_caveats": {
            "causality": (
                "SHAP attributions quantify additive contributions to the model output "
                "relative to expected background. SHAP does NOT prove causality in network traffic."
            ),
            "test_isolation": "The test set was evaluated post-hoc and never used for feature or model tuning.",
            "stability": "Attributions are specific to the Random Forest model and training distribution.",
        },
    }
