"""Dataset audit and manifest tests."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from xrlids.datasets.audit import audit_frame, summarize_audits
from xrlids.datasets.loading import (
    DatasetIntegrityError,
    dataset_availability,
    load_manifest,
    verify_files,
)


def test_audit_counts_nan_inf_and_duplicates(contract, registry):
    frame = pd.DataFrame(
        {
            "Flow Duration": [1_000_000, -5, 1_000_000],
            "Total Fwd Packets": [1, 2, 1],
            "Total Backward Packets": [1, 1, 1],
            "Total Length of Fwd Packets": [10.0, np.inf, 10.0],
            "Total Length of Bwd Packets": [10.0, 10.0, 10.0],
            "Packet Length Mean": [10.0, np.nan, 10.0],
            "Packet Length Std": [1.0, 1.0, 1.0],
            "SYN Flag Count": [1, 1, 1],
            "ACK Flag Count": [1, 1, 1],
            "RST Flag Count": [0, 0, 0],
            "FIN Flag Count": [0, 0, 0],
            "Flow IAT Mean": [1, 1, 1],
            "Flow IAT Std": [1, 1, 1],
            "Fwd Packet Length Mean": [10.0, 10.0, 10.0],
            "Bwd Packet Length Mean": [10.0, 10.0, 10.0],
            "Active Mean": [1, 1, 1],
            "Idle Mean": [1, 1, 1],
            "Subflow Fwd Bytes": [5, 5, 5],
            "Subflow Bwd Bytes": [5, 5, 5],
            "Label": ["BENIGN", "DoS Hulk", "BENIGN"],
        }
    )
    audit = audit_frame(frame, dataset="cicids2017", source_file="mem", contract=contract, registry=registry)
    assert audit["rows"] == 3
    assert audit["total_inf"] == 1
    assert audit["total_nan"] == 1
    assert audit["duplicate_rows"] == 1
    assert audit["duration_findings"]["Flow Duration"]["negative"] == 1
    assert audit["label_audit"]["rows_accepted"] == 3


def test_audit_reports_unknown_labels(contract, registry):
    frame = pd.DataFrame({"Label": ["BENIGN", "Bogus Attack"]})
    audit = audit_frame(frame, dataset="cicids2017", source_file="mem", contract=contract, registry=registry)
    assert audit["label_audit"]["rows_rejected_unknown_label"] == 1
    assert audit["unknown_label_rejections"]


def test_summarize_detects_schema_variation():
    audits = [
        {"dataset": "d", "source_file": "a.csv", "column_names": ["x", "y"], "rows": 10, "duplicate_rows": 0},
        {"dataset": "d", "source_file": "b.csv", "column_names": ["x", "z"], "rows": 20, "duplicate_rows": 1},
    ]
    summary = summarize_audits(audits)
    assert summary["schema_variation"]["d"]["schemas_identical"] is False
    assert summary["total_rows"] == 30


def test_dataset_unavailable_is_reported_not_faked(registry):
    manifest = load_manifest()
    avail = dataset_availability(manifest, "cicids2017")
    assert avail["status"] in {"DATA_NOT_AVAILABLE", "available"}
    if avail["status"] == "DATA_NOT_AVAILABLE":
        assert "reason" in avail


def test_checksum_mismatch_raises(tmp_path):
    f = tmp_path / "data.csv"
    f.write_text("a,b\n1,2\n")
    entry = {"key": "t", "files": [{"path": str(f), "sha256": "deadbeef"}]}
    with pytest.raises(DatasetIntegrityError):
        verify_files(entry, strict=True)


def test_unverifiable_file_is_not_reported_as_verified(tmp_path):
    f = tmp_path / "data.csv"
    f.write_text("a,b\n1,2\n")
    report = verify_files({"key": "t", "files": [{"path": str(f)}]}, strict=False)
    assert report["files"][0]["status"] == "unverifiable"
    assert report["overall"] == "unverifiable"
