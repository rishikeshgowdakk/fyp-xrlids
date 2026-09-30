"""Schema-validation tests: declared column maps vs real file headers."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from xrlids.datasets.schema import (
    SchemaValidationError,
    read_header,
    validate_dataset_schema,
    validate_file_schema,
)

CIC_COLS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Packet Length Mean", "Packet Length Std", "SYN Flag Count", "ACK Flag Count",
    "RST Flag Count", "FIN Flag Count", "Flow IAT Mean", "Flow IAT Std",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Active Mean", "Idle Mean",
    "Subflow Fwd Bytes", "Subflow Bwd Bytes", "Label",
]

UNSW_COLS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "Sbytes", "Dbytes",
    "Spkts", "Dpkts", "label", "attack_cat",
]


def _write_csv(path: Path, columns: list[str], rows: int = 2) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(columns=columns).to_csv(path, index=False)
    return path


def test_read_header_only_reads_columns(tmp_path):
    p = _write_csv(tmp_path / "f.csv", ["a", "b", "c"])
    assert read_header(p) == ["a", "b", "c"]


def test_cic_schema_validates_when_columns_present(registry, tmp_path):
    _write_csv(tmp_path / "day1.csv", CIC_COLS)
    report = validate_file_schema(
        tmp_path / "day1.csv", "cicids2017", registry, label_candidates=["Label"]
    )
    assert report.ok
    assert report.label_column_found == "Label"


def test_cic_schema_reports_missing_columns(registry, tmp_path):
    cols = [c for c in CIC_COLS if c not in ("SYN Flag Count", "ACK Flag Count")]
    _write_csv(tmp_path / "day1.csv", cols)
    report = validate_file_schema(tmp_path / "day1.csv", "cicids2017", registry)
    assert not report.ok
    assert "SYN Flag Count" in report.missing
    assert "ACK Flag Count" in report.missing


def test_unsw_map_matches_its_own_columns_but_r10_stays_unsupported(registry, tmp_path):
    """The UNSW column map declares only what UNSW genuinely has, so its own files
    validate cleanly - while the R10 *feature* contract remains 4/10 supported.
    Both halves of that statement are the honesty we need to protect."""
    _write_csv(tmp_path / "unsw.csv", UNSW_COLS)
    report = validate_file_schema(
        tmp_path / "unsw.csv", "unsw_nb15", registry, label_candidates=["label", "Label"]
    )
    assert report.ok  # the map over-promises nothing for UNSW
    assert report.label_column_found == "label"
    # ...but the R10 feature contract still cannot be satisfied:
    supported = registry.features_supported("unsw_nb15", "R10")
    assert len(supported) == 4
    assert "syn_count" in registry.unsupported_features("unsw_nb15", "R10")


def test_dataset_schema_detects_schema_variation_between_files(registry, tmp_path):
    _write_csv(tmp_path / "a.csv", CIC_COLS)
    _write_csv(tmp_path / "b.csv", CIC_COLS[:-1])  # one column fewer
    report = validate_dataset_schema(tmp_path, "cicids2017", registry)
    assert report.to_dict()["files_identical_schema"] is False


def test_missing_directory_raises(registry, tmp_path):
    with pytest.raises(SchemaValidationError, match="not acquired"):
        validate_dataset_schema(tmp_path / "nope", "cicids2017", registry)


def test_empty_directory_raises(registry, tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(SchemaValidationError, match=r"no \*\.csv files"):
        validate_dataset_schema(tmp_path / "empty", "cicids2017", registry)
