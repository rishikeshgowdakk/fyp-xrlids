"""Unit tests for complete per-file dataset audit (Task 5)."""

from __future__ import annotations

from pathlib import Path
import numpy as np
import pandas as pd
import pytest

from xrlids.datasets.audit import audit_file
from xrlids.features.registry import load_feature_registry
from xrlids.labels.contract import load_label_contract


def test_audit_file_contains_all_required_per_file_fields(tmp_path: Path):
    """Verify that audit_file produces all 25 required audit fields per Task 5."""
    df = pd.DataFrame(
        {
            " Flow Duration": [1000, -5, 1000, 2000],
            "Total Fwd Packets": [1, 2, 1, 3],
            "Total Backward Packets": [1, 1, 1, 1],
            "Total Length of Fwd Packets": [10.0, np.inf, 10.0, 50.0],
            "Total Length of Bwd Packets": [10.0, 10.0, 10.0, 10.0],
            "Packet Length Mean": [10.0, np.nan, 10.0, 20.0],
            "Packet Length Std": [1.0, 1.0, 1.0, 1.0],
            "SYN Flag Count": [1, 1, 1, 0],
            "ACK Flag Count": [1, 1, 1, 0],
            "RST Flag Count": [0, 0, 0, 0],
            "FIN Flag Count": [0, 0, 0, 0],
            "Const_Col": [42, 42, 42, 42],
            "Label": ["BENIGN", "DoS Hulk", "BENIGN", "Label"],  # includes a repeated header
        }
    )
    csv_file = tmp_path / "mock_cicids2017.csv"
    df.to_csv(csv_file, index=False)

    contract = load_label_contract()
    registry = load_feature_registry()

    res = audit_file(
        csv_file,
        dataset="cicids2017",
        contract=contract,
        registry=registry,
        chunk_size=2,  # test chunk boundary streaming
    )

    required_keys = [
        "dataset",
        "filename",
        "relative_path",
        "size_bytes",
        "sha256",
        "row_count",
        "column_count",
        "original_headers",
        "canonical_headers",
        "label_column",
        "distinct_raw_labels",
        "accepted_labels",
        "rejected_labels",
        "repeated_header_rows",
        "nan_counts",
        "inf_counts",
        "exact_duplicate_rows",
        "constant_columns",
        "duration_findings",
        "duration_anomalies",
        "invalid_numeric_rows",
        "feature_availability",
        "feature_extraction_status",
        "audit_timestamp",
        "git_commit",
        "source_provenance_classification",
    ]

    for k in required_keys:
        assert k in res, f"Missing required audit field: {k}"

    assert res["row_count"] == 4
    assert res["exact_duplicate_rows"] == 1
    assert res["repeated_header_rows"] == 1
    assert res["total_nan"] == 1
    assert res["total_inf"] == 1
    assert "Const_Col" in res["constant_columns"]
    assert res["accepted_labels"].get("BENIGN") == 2
    assert res["accepted_labels"].get("DoS Hulk") == 1
    assert res["rejected_labels"].get("Label") == 1
    assert res["duration_anomalies"]["negative"] == 1
