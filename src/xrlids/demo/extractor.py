"""Feature parity verification and DataFrame conversion for demo flows."""

from __future__ import annotations

from typing import Any, Sequence

import numpy as np
import pandas as pd

from xrlids.demo.flow import Flow
from xrlids.features.definitions import R10_FEATURES


def flows_to_dataframe(flows: Sequence[Flow]) -> pd.DataFrame:
    """Convert a sequence of Flow objects into a DataFrame matching R10 contract."""
    rows = [f.to_features() for f in flows]
    df = pd.DataFrame(rows, columns=list(R10_FEATURES))
    return df.astype(np.float32)


def verify_feature_parity(
    offline_features: dict[str, float],
    live_features: dict[str, float],
    atol: float = 1e-4,
) -> dict[str, Any]:
    """Compare offline feature extraction vs live/replay feature extraction (Task 5.2).

    Parameters
    ----------
    offline_features : dict
        Features extracted by the offline tabular pipeline.
    live_features : dict
        Features extracted by the live/replay streaming flow accumulator.
    atol : float
        Absolute numerical tolerance for floating-point comparison.

    Returns
    -------
    dict with parity status, feature deltas, and boolean verdict.
    """
    deltas: dict[str, float] = {}
    mismatches: dict[str, dict[str, float]] = {}

    for feat in R10_FEATURES:
        v_off = float(offline_features.get(feat, 0.0))
        v_live = float(live_features.get(feat, 0.0))
        diff = abs(v_off - v_live)
        deltas[feat] = diff
        if diff > atol:
            mismatches[feat] = {"offline": v_off, "live": v_live, "abs_diff": diff}

    is_parity = len(mismatches) == 0
    return {
        "is_parity": is_parity,
        "features_checked": len(R10_FEATURES),
        "tolerance": atol,
        "max_delta": max(deltas.values()) if deltas else 0.0,
        "deltas": deltas,
        "mismatches": mismatches,
    }
