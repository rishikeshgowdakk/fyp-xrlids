"""Splitting and leakage tests."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.splitting.leakage import audit_split_leakage
from xrlids.splitting.splitter import SplitConfig, SplitConfigurationError, build_splits


def _dataset(n: int = 400, seed: int = 0):
    rng = np.random.default_rng(seed)
    cols = ["f1", "f2", "f3"]
    X = pd.DataFrame(rng.normal(size=(n, 3)), columns=cols)
    y = pd.Series(rng.integers(0, 2, n))
    return X, y, cols


def test_ratios_and_shapes():
    X, y, cols = _dataset()
    res = build_splits(X, y, cols, SplitConfig(seed=1), dataset="d")
    n = res.manifest["counts"]
    assert n["train"] + n["validation"] + n["test"] == 400
    assert 0.55 < n["train"] / 400 < 0.65
    assert 0.15 < n["validation"] / 400 < 0.25


def test_deterministic_given_seed():
    X, y, cols = _dataset()
    a = build_splits(X, y, cols, SplitConfig(seed=7), dataset="d")
    b = build_splits(X, y, cols, SplitConfig(seed=7), dataset="d")
    assert a.assignment.equals(b.assignment)


def test_ratios_must_sum_to_one():
    with pytest.raises(SplitConfigurationError):
        SplitConfig(train=0.5, validation=0.2, test=0.2)


def test_leakage_detects_duplicate_rows_across_splits():
    row = pd.DataFrame({"f1": [1.0], "f2": [2.0]})
    splits = {"train": row, "test": row.copy()}
    report = audit_split_leakage(splits, ["f1", "f2"])
    assert report["status"] == "fail"
    assert "duplicate_overlap" in report["failed_checks"]


def test_leakage_passes_for_disjoint_rows():
    splits = {
        "train": pd.DataFrame({"f1": [1.0, 2.0], "f2": [1.0, 2.0]}),
        "test": pd.DataFrame({"f1": [3.0], "f2": [3.0]}),
    }
    report = audit_split_leakage(splits, ["f1", "f2"])
    assert report["status"] == "pass"


def test_leakage_reports_unperformed_checks_explicitly():
    splits = {
        "train": pd.DataFrame({"f1": [1.0]}),
        "test": pd.DataFrame({"f1": [2.0]}),
    }
    report = audit_split_leakage(splits, ["f1"])
    # no group / source-ip / timestamp columns exist, so those checks must be flagged
    assert "group_overlap" in report["not_performed"]
    assert "source_ip_overlap" in report["not_performed"]
    assert "temporal_overlap" in report["not_performed"]


def test_missing_group_column_fails_loudly():
    X, y, cols = _dataset(100)
    with pytest.raises(SplitConfigurationError):
        build_splits(X, y, cols, SplitConfig(group_column="nope"), dataset="d")


def test_row_hashes_handles_nan_gracefully():
    from xrlids.splitting.leakage import _row_hashes
    df = pd.DataFrame({"f1": [1.0, np.nan, 1.0], "f2": [np.nan, 2.0, np.nan]})
    hashes = _row_hashes(df, ["f1", "f2"])
    assert len(hashes) == 3
    assert hashes.iloc[0] == hashes.iloc[2]
    assert hashes.iloc[0] != hashes.iloc[1]


def test_policy_a_deduplicates_features_before_splitting():
    # Rows 0, 1, 2 have identical features but different indices
    X = pd.DataFrame({
        "f1": [1.0, 1.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0],
        "f2": [2.0, 2.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0],
    })
    y = pd.Series([0, 0, 0, 1, 1, 0, 1, 0, 1, 0])
    cfg = SplitConfig(seed=42, duplicate_policy="deduplicate_features", train=0.6, validation=0.2, test=0.2)
    res = build_splits(X, y, ["f1", "f2"], cfg, dataset="test_ds")

    # 10 rows initially, 2 duplicates dropped -> 8 unique rows
    assert res.manifest["duplicate_accounting"]["input_rows"] == 10
    assert res.manifest["duplicate_accounting"]["duplicate_rows_dropped"] == 2
    assert res.manifest["duplicate_accounting"]["unique_rows_retained"] == 8
    total_split_rows = sum(len(df) for df in res.splits.values())
    assert total_split_rows == 8
    assert res.leakage["status"] == "pass"


def test_policy_b_retains_duplicates_and_tags_test_subset():
    X = pd.DataFrame({
        "f1": [1.0, 1.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0],
        "f2": [2.0, 2.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0],
    })
    y = pd.Series([0, 0, 0, 1, 1, 0, 1, 0, 1, 0])
    cfg = SplitConfig(seed=42, duplicate_policy="retain_with_subset_evaluation", train=0.6, validation=0.2, test=0.2)
    res = build_splits(X, y, ["f1", "f2"], cfg, dataset="test_ds", run_leakage_audit=False)

    assert res.manifest["duplicate_accounting"]["input_rows"] == 10
    total_split_rows = sum(len(df) for df in res.splits.values())
    assert total_split_rows == 10
    assert res.test_duplicate_mask is not None
    assert len(res.test_duplicate_mask) == len(res.splits["test"])


def test_invalid_duplicate_policy_raises():
    with pytest.raises(SplitConfigurationError, match="invalid duplicate_policy"):
        SplitConfig(duplicate_policy="unknown_policy")

