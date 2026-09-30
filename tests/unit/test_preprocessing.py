"""Preprocessing tests: train-only fitting, imputation, schema enforcement."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.preprocessing.pipeline import PreprocessingError, Preprocessor


def _frame(offset: float, n: int = 50) -> pd.DataFrame:
    rng = np.random.default_rng(0)
    return pd.DataFrame(
        {
            "a": rng.normal(offset, 1.0, n),
            "b": rng.normal(offset * 2, 3.0, n),
        }
    )


def test_fit_on_train_only_and_scaling_uses_train_statistics():
    train = _frame(0.0)
    different = _frame(1000.0)
    pre = Preprocessor(features=["a", "b"], dataset="x").fit(train)

    scaled_train = pre.transform(train)
    assert abs(scaled_train["a"].mean()) < 1e-9
    assert abs(scaled_train["a"].std(ddof=0) - 1.0) < 1e-9

    # transforming data with a different distribution must NOT re-fit
    scaled_other = pre.transform(different)
    assert scaled_other["a"].mean() > 100  # clearly off the training scale


def test_feature_order_is_frozen():
    train = _frame(0.0)
    pre = Preprocessor(features=["b", "a"], dataset="x").fit(train)
    out = pre.transform(train)
    assert list(out.columns) == ["b", "a"]


def test_missing_feature_raises():
    pre = Preprocessor(features=["a", "b"], dataset="x").fit(_frame(0.0))
    with pytest.raises(PreprocessingError, match="missing features"):
        pre.transform(pd.DataFrame({"a": [1.0]}))


def test_nan_imputed_with_train_median():
    train = _frame(0.0)
    train.loc[0, "a"] = np.nan
    pre = Preprocessor(features=["a", "b"], dataset="x").fit(train)
    assert pre.medians is not None
    out = pre.transform(train)
    assert not out.isna().any().any()


def test_unfitted_transform_raises():
    with pytest.raises(PreprocessingError):
        Preprocessor(features=["a"], dataset="x").transform(_frame(0.0))


def test_metadata_is_complete():
    pre = Preprocessor(features=["a", "b"], dataset="x").fit(_frame(0.0))
    meta = pre.metadata()
    for key in ("feature_list", "scaler_type", "n_train_rows", "feature_schema_hash", "preprocessor_hash"):
        assert key in meta
    assert meta["n_train_rows"] == 50
