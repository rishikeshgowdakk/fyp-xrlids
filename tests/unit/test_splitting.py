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
