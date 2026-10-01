"""Real-file regression tests for the CIC-IDS2017 feature-extraction path (Task 2).

Historical defect: the ``cicids2017`` column map declared headers WITH leading spaces
(``" Flow Duration"``) while ``clean_dataset_frame`` stripped headers, so semantic
extraction raised ``FeatureValidationError`` and the primary benchmark could not run.

These tests exercise the acceptance chain on actual local CSVs, with no manual header
edits:

    raw schema validation -> label extraction -> semantic extraction -> R10 computation

They are skipped when the raw dataset is absent (raw data is never committed), but run
against real bytes whenever the repository is on a machine with the data present.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from xrlids.datasets.schema import validate_file_schema
from xrlids.features.compute import compute_features, extract_semantics
from xrlids.labels.contract import apply_label_contract
from xrlids.utils.columns import canonicalize_column

PREFIX_ROWS = 20_000


def _cic_files() -> list[Path]:
    return sorted(Path("data/raw/cicids2017").glob("*.csv"))


@pytest.fixture(scope="module")
def cic_files() -> list[Path]:
    files = _cic_files()
    if not files:
        pytest.skip("CIC-IDS2017 raw files not present on this machine")
    return files


@pytest.fixture(scope="module")
def cic_prefix(cic_files) -> pd.DataFrame:
    """First 20k rows of a real CIC-IDS2017 CSV with headers EXACTLY as published."""
    return pd.read_csv(cic_files[0], nrows=PREFIX_ROWS, low_memory=False)


def test_every_real_file_passes_raw_schema_validation(registry, contract, cic_files):
    """Header-only validation of all 8 real files against the declared column map."""
    candidates = contract.datasets["cicids2017"]["label_column_candidates"]
    for path in cic_files:
        report = validate_file_schema(
            path, "cicids2017", registry, label_candidates=candidates
        )
        assert report.ok, f"{path.name}: missing declared columns {report.missing}"
        assert report.label_column_found == "Label"
        # provenance: raw headers preserved verbatim, canonical is derived from them
        assert report.columns == list(pd.read_csv(path, nrows=0).columns)
        assert report.canonical_columns == [canonicalize_column(c) for c in report.columns]
        assert report.label_column_found in report.canonical_columns


def test_acceptance_chain_on_real_cic_file(registry, contract, cic_files, cic_prefix):
    """The exact Task-2 acceptance condition on a real CSV, without header edits."""
    # 1. raw schema validation (against the same real file)
    candidates = contract.datasets["cicids2017"]["label_column_candidates"]
    schema = validate_file_schema(
        cic_files[0], "cicids2017", registry, label_candidates=candidates
    )
    assert schema.ok

    # 2. label extraction from the RAW frame (headers keep their leading spaces)
    app = apply_label_contract(cic_prefix, "cicids2017", contract)
    assert app.stats["rows_accepted"] > 0
    # the resolved label column must be a RAW header actually present in the file
    assert app.stats["label_column"] in list(cic_prefix.columns)
    benign_rows = cic_prefix[app.native == "BENIGN"]
    if len(benign_rows):
        assert contract.normalize("BENIGN") == "BENIGN"
        assert app.canonical[benign_rows.index].eq("BENIGN").all()

    # 3. semantic extraction, strict (missing columns must raise, not substitute)
    semantics, report = extract_semantics(cic_prefix, "cicids2017", registry, strict=True)
    assert report["semantic_absent"] == []
    assert report["raw_columns_missing"] == []
    # raw provenance preserved alongside canonical headers
    assert report["raw_headers"] == list(cic_prefix.columns)

    # 4. R10 computation: 10/10 features, canonical vocabulary only
    rung = "R10"
    features = registry.rung_features(rung)
    matrix, available, unavailable = compute_features(
        semantics, features, dataset="cicids2017", strict=False
    )
    assert unavailable == [], f"R10 features unavailable on real CIC data: {unavailable}"
    assert available == features
    assert list(matrix.columns) == features
    finite = matrix[features].notna().all(axis=1).mean()
    assert finite > 0.9, f"only {finite:.1%} of real rows produced finite R10 features"

    # every semantic field must name the exact source column used
    for sem, prov in report["provenance"].items():
        assert prov["source_columns"], sem
        for col in prov["source_columns"]:
            assert col in schema.canonical_columns, (
                f"semantic '{sem}' used '{col}', which is not a canonical header of the file"
            )


@pytest.mark.parametrize("rung", ["R10", "R15", "R20"])
def test_real_file_supports_rung_where_columns_exist(registry, cic_files, cic_prefix, rung):
    """R10/R15/R20 must compute on real CIC-IDS2017 data (all rung columns exist)."""
    semantics, _ = extract_semantics(cic_prefix, "cicids2017", registry, strict=True)
    features = registry.rung_features(rung)
    matrix, available, unavailable = compute_features(
        semantics, features, dataset="cicids2017", strict=False
    )
    assert unavailable == [], f"{rung} unavailable on real CIC data: {unavailable}"
    assert available == features
    assert len(matrix) == len(cic_prefix)


def test_unavailable_features_are_reported_not_substituted(registry, cic_prefix):
    """If a column is genuinely absent the feature must be reported unavailable."""
    # Drop a single source column from a REAL frame: the dependent features must be
    # reported unavailable, never silently computed from a substitute column.
    drop_raw = " SYN Flag Count"
    if drop_raw not in cic_prefix.columns:
        pytest.skip("expected raw column layout not found")
    crippled = cic_prefix.drop(columns=[drop_raw])

    from xrlids.features.compute import FeatureValidationError

    # strict mode must RAISE on a missing source column, never guess a substitute
    with pytest.raises(FeatureValidationError):
        extract_semantics(crippled, "cicids2017", registry, strict=True)

    # non-strict mode must REPORT the dependent features as unavailable
    semantics, report = extract_semantics(crippled, "cicids2017", registry, strict=False)
    assert "syn_flags" in report["semantic_absent"]
    features = registry.rung_features("R10")
    _, available, unavailable = compute_features(
        semantics, features, dataset="cicids2017", strict=False
    )
    assert "syn_count" in unavailable
    assert "syn_count" not in available
