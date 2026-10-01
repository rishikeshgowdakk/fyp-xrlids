"""End-to-end tests comparing in-memory vs chunked streaming pipeline (Task 22).

Proves that chunked streaming produces exact semantic, accounting, and predictive
equivalence to full in-memory processing.
"""

from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from xrlids.features.compute import build_feature_matrix
from xrlids.features.registry import load_feature_registry
from xrlids.labels.contract import load_label_contract
from xrlids.models.random_forest import RandomForestDetector
from xrlids.preprocessing.cleaning import clean_dataset_frame
from xrlids.preprocessing.pipeline import Preprocessor
from xrlids.preprocessing.streaming import stream_clean_and_extract
from xrlids.splitting.splitter import SplitConfig, build_splits


@pytest.fixture
def mock_fixture_csv(tmp_path: Path):
    """Create a representative small CSV fixture with duplicates, anomalies, and labels."""
    columns = [
        " Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Packet Length Mean", "Packet Length Std", "SYN Flag Count",
        "ACK Flag Count", "RST Flag Count", "FIN Flag Count",
        "Flow IAT Mean", "Flow IAT Std", "Fwd Packet Length Mean",
        "Bwd Packet Length Mean", "Active Mean", "Idle Mean",
        "Subflow Fwd Bytes", "Subflow Bwd Bytes", "Label"
    ]
    # Rows:
    # 0..19: benign flows
    # 20..39: attack flows
    # 40: duplicate of row 0
    # 41: negative duration flow (dropped)
    # 42: unknown label (dropped)
    # 43: repeated header row (dropped)
    rng = np.random.default_rng(42)
    rows = []
    for i in range(20):
        rows.append([
            1000 + i * 10, 2, 2, 100.0, 100.0, 50.0, 5.0, 1, 1, 0, 0,
            10.0, 2.0, 50.0, 50.0, 1.0, 1.0, 50, 50, "BENIGN"
        ])
    for i in range(20):
        rows.append([
            5000 + i * 50, 10, 1, 1000.0, 50.0, 200.0, 20.0, 1, 0, 1, 0,
            5.0, 1.0, 100.0, 50.0, 0.0, 0.0, 500, 25, "DoS Hulk"
        ])
    # Exact duplicate of row 0
    rows.append(list(rows[0]))
    # Negative duration
    rows.append([-100, 2, 2, 100.0, 100.0, 50.0, 5.0, 1, 1, 0, 0, 10.0, 2.0, 50.0, 50.0, 1.0, 1.0, 50, 50, "BENIGN"])
    # Unknown label
    rows.append([2000, 2, 2, 100.0, 100.0, 50.0, 5.0, 1, 1, 0, 0, 10.0, 2.0, 50.0, 50.0, 1.0, 1.0, 50, 50, "Weird_Trojan_999"])
    # Repeated header
    rows.append([1000, 2, 2, 100.0, 100.0, 50.0, 5.0, 1, 1, 0, 0, 10.0, 2.0, 50.0, 50.0, 1.0, 1.0, 50, 50, "Label"])

    df = pd.DataFrame(rows, columns=columns)
    csv_path = tmp_path / "test_fixture.csv"
    df.to_csv(csv_path, index=False)
    return csv_path


def test_in_memory_vs_streaming_equivalence(mock_fixture_csv):
    """Verify that in-memory and streaming pipelines yield identical rows, accounting, features, splits, and predictions."""
    contract = load_label_contract()
    registry = load_feature_registry()
    dataset_key = "cicids2017"
    rung = "R10"
    feature_names = registry.rung_features(rung)

    # 1. In-memory pipeline
    raw_df = pd.read_csv(mock_fixture_csv, low_memory=False)
    cleaned_mem = clean_dataset_frame(raw_df, dataset_key, contract)
    feat_mat_mem = build_feature_matrix(cleaned_mem.frame, dataset_key, rung, registry)
    X_mem = feat_mat_mem.frame.reset_index(drop=True).astype(np.float32)
    y_mem = cleaned_mem.labels.binary.reset_index(drop=True)
    accounting_mem = cleaned_mem.accounting

    # 2. Chunked streaming pipeline (small chunks of 5 rows to rigorously test boundaries)
    X_stream, y_stream, accounting_stream = stream_clean_and_extract(
        mock_fixture_csv,
        dataset=dataset_key,
        contract=contract,
        feature_names=feature_names,
        registry=registry,
        chunk_size=5,
    )

    # Verification 1: Exact same rows retained / dropped
    assert len(X_mem) == len(X_stream)
    assert len(y_mem) == len(y_stream)
    assert len(X_mem) == 40  # 44 total raw - 1 duplicate - 1 negative dur - 1 unknown - 1 repeated header = 40

    # Verification 2: Identical label accounting
    for k in ["raw_rows_at_start", "removed_duplicates", "removed_unknown_label", "removed_invalid", "final_accepted_rows"]:
        assert accounting_mem[k] == accounting_stream[k], f"Accounting mismatch on {k}"

    # Verification 3: Identical feature matrices (within float tolerance)
    assert list(X_mem.columns) == list(X_stream.columns)
    np.testing.assert_allclose(X_mem.to_numpy(), X_stream.to_numpy(), rtol=1e-5, atol=1e-5)
    np.testing.assert_array_equal(y_mem.to_numpy(), y_stream.to_numpy())

    # Verification 4: Identical split assignments
    split_cfg = SplitConfig(train=0.6, validation=0.2, test=0.2, seed=42, duplicate_policy="deduplicate_features")
    splits_mem = build_splits(X_mem, y_mem, feature_names, split_cfg, dataset=dataset_key)
    splits_stream = build_splits(X_stream, y_stream, feature_names, split_cfg, dataset=dataset_key)

    assert len(splits_mem.splits["train"]) == len(splits_stream.splits["train"])
    assert splits_mem.assignment.equals(splits_stream.assignment)
    np.testing.assert_array_equal(splits_mem.label_splits["train"].to_numpy(), splits_stream.label_splits["train"].to_numpy())
    np.testing.assert_array_equal(splits_mem.label_splits["test"].to_numpy(), splits_stream.label_splits["test"].to_numpy())

    # Verification 5: Identical model training and predictions
    prep_mem = Preprocessor(features=feature_names, dataset=dataset_key).fit(splits_mem.splits["train"])
    X_tr_mem = prep_mem.transform(splits_mem.splits["train"])
    X_te_mem = prep_mem.transform(splits_mem.splits["test"])

    prep_stream = Preprocessor(features=feature_names, dataset=dataset_key).fit(splits_stream.splits["train"])
    X_tr_stream = prep_stream.transform(splits_stream.splits["train"])
    X_te_stream = prep_stream.transform(splits_stream.splits["test"])

    rf_mem = RandomForestDetector(params={"n_estimators": 20, "random_state": 42}).fit(X_tr_mem, splits_mem.label_splits["train"])
    preds_mem = rf_mem.predict_proba(X_te_mem)

    rf_stream = RandomForestDetector(params={"n_estimators": 20, "random_state": 42}).fit(X_tr_stream, splits_stream.label_splits["train"])
    preds_stream = rf_stream.predict_proba(X_te_stream)

    np.testing.assert_allclose(preds_mem, preds_stream, rtol=1e-5, atol=1e-5)
