"""Integration tests for Phase 3C LiveFeatureParityHarness."""

import pandas as pd
import pytest

from xrlids.features.definitions import R10_FEATURES
from xrlids.live.parity import LiveFeatureParityHarness


def test_live_feature_parity_all_10_features_pass():
    """Verify that all 10 canonical R10 features achieve PASS under controlled topologies."""
    harness = LiveFeatureParityHarness()
    results = harness.evaluate_parity()

    assert len(results) == len(R10_FEATURES)

    for feat in R10_FEATURES:
        res = results[feat]
        assert res.passed is True, (
            f"Parity FAIL for '{feat}': max_abs_error={res.max_abs_error}, "
            f"tolerance={res.tolerance}"
        )
        assert res.max_abs_error <= res.tolerance
        assert res.sample_count >= 5


def test_parity_harness_dataframe_generation():
    """Verify that parity harness exports a complete and well-structured pandas DataFrame."""
    harness = LiveFeatureParityHarness()
    df = harness.to_dataframe()

    assert isinstance(df, pd.DataFrame)
    assert len(df) == 10
    assert set(df["feature_name"]) == set(R10_FEATURES)
    assert df["passed"].all() is True or df["passed"].all() == 1
    assert "max_abs_error" in df.columns
    assert "tolerance" in df.columns
