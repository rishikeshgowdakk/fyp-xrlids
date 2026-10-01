"""Column-contract tests across ALL THREE real datasets (Task 3).

One canonical header-normalization rule must be applied identically by schema
validation, cleaning and semantic extraction, for every dataset:

    raw input -> preserve original headers -> canonical header layer
              -> validated canonical frame -> label/feature resolution

These tests run against the real files when present (skipped otherwise), plus a
small always-runnable check that schema validation and cleaning derive the SAME
canonical representation from the same raw headers.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from xrlids.datasets.schema import validate_file_schema
from xrlids.features.compute import compute_features, extract_semantics
from xrlids.labels.contract import apply_label_contract
from xrlids.preprocessing.cleaning import clean_dataset_frame
from xrlids.utils.columns import canonicalize_column, canonicalize_frame

DATASETS = ["cicids2017", "cse_cic_ids2018", "unsw_nb15"]


def _files(dataset: str) -> list[Path]:
    return sorted(Path(f"data/raw/{dataset}").glob("*.csv"))


def _present_datasets() -> list[str]:
    return [d for d in DATASETS if _files(d)]


@pytest.fixture(scope="module")
def present() -> list[str]:
    found = _present_datasets()
    if not found:
        pytest.skip("no raw datasets present on this machine")
    return found


# ------------------------------------------------------------------ always-runnable
def test_schema_and_cleaning_derive_the_same_canonical_names(registry, contract):
    """Schema validation and cleaning must not disagree about header normalization."""
    raw = pd.DataFrame(
        {
            " Flow Duration": [1_000_000, 2_000_000],
            " Total Fwd Packets": [10, 20],
            " Total Backward Packets": [8, 12],
            " Total Length of Fwd Packets": [1000, 2000],
            " Total Length of Bwd Packets": [800, 1200],
            " Packet Length Mean": [100.0, 120.0],
            " Packet Length Std": [10.0, 20.0],
            " SYN Flag Count": [1, 2],
            " ACK Flag Count": [0, 5],
            " RST Flag Count": [0, 1],
            " FIN Flag Count": [0, 0],
            " Flow IAT Mean": [5000, 6000],
            " Flow IAT Std": [100, 200],
            " Fwd Packet Length Mean": [100.0, 120.0],
            " Bwd Packet Length Mean": [100.0, 120.0],
            " Active Mean": [1000, 2000],
            " Idle Mean": [2000, 3000],
            " Subflow Fwd Bytes": [600, 700],
            " Subflow Bwd Bytes": [400, 500],
            " Label": ["BENIGN", "DoS Hulk"],
        }
    )
    # cleaning's canonical layer
    cleaned = clean_dataset_frame(raw, "cicids2017", contract)
    canon_from_cleaning = list(cleaned.frame.columns)

    # schema side: canonicalize the same raw headers
    canon_from_headers = [canonicalize_column(c) for c in raw.columns]

    assert canon_from_cleaning == canon_from_headers
    # raw headers preserved for provenance
    assert cleaned.extra["raw_columns"] == [str(c) for c in raw.columns]
    assert cleaned.labels.stats["label_column"] == " Label"  # RAW name, traceable
    # extract_semantics sees the same canonical view as cleaning
    semantics, report = extract_semantics(cleaned.frame, "cicids2017", registry, strict=True)
    assert report["semantic_absent"] == []
    assert len(semantics) == 2


def test_canonicalize_frame_is_idempotent_and_keeps_raw():
    raw = pd.DataFrame({" Flow Duration": [1], "Label": ["BENIGN"]})
    once = canonicalize_frame(raw)
    twice = canonicalize_frame(once)
    assert list(once.columns) == ["Flow Duration", "Label"]
    assert list(twice.columns) == list(once.columns)
    assert twice.attrs["raw_columns"] == ["Flow Duration", "Label"]


# ------------------------------------------------------------------ real files
@pytest.mark.parametrize("dataset", DATASETS)
def test_all_real_files_pass_schema_and_keep_raw_provenance(registry, contract, dataset):
    files = _files(dataset)
    if not files:
        pytest.skip(f"{dataset} not present")
    candidates = contract.datasets[dataset]["label_column_candidates"]
    for path in files:
        report = validate_file_schema(
            path, dataset, registry, label_candidates=candidates
        )
        assert report.ok, f"{path.name}: missing {report.missing}"
        assert report.label_column_found is not None, f"{path.name}: no label column"
        raw = list(pd.read_csv(path, nrows=0).columns)
        assert report.columns == raw, "raw headers must be preserved verbatim"
        assert report.canonical_columns == [canonicalize_column(c) for c in raw]
        # canonicalization is idempotent: canonical of canonical == canonical
        assert [canonicalize_column(c) for c in report.canonical_columns] == (
            report.canonical_columns
        )


@pytest.mark.parametrize("dataset", DATASETS)
def test_real_prefix_cleans_and_extracts_with_one_contract(registry, contract, dataset):
    files = _files(dataset)
    if not files:
        pytest.skip(f"{dataset} not present")
    frame = pd.read_csv(files[0], nrows=5_000, low_memory=False)

    cleaned = clean_dataset_frame(frame, dataset, contract)
    assert cleaned.extra["raw_columns"] == [str(c) for c in frame.columns]
    assert cleaned.extra["canonical_columns"] == [
        canonicalize_column(c) for c in frame.columns
    ]
    # label resolution traces back to a real raw header
    resolved = cleaned.labels.stats["label_column"]
    assert resolved in [str(c) for c in frame.columns] or canonicalize_column(
        resolved
    ) in [canonicalize_column(c) for c in frame.columns]

    # semantic extraction on the SAME canonical representation
    strict = dataset != "unsw_nb15"  # UNSW legitimately lacks many CIC semantics
    semantics, report = extract_semantics(
        cleaned.frame, dataset, registry, strict=strict
    )
    if dataset == "unsw_nb15":
        # absent semantics must be REPORTED (no substitution)
        assert report["semantic_absent"], "UNSW must not silently fabricate semantics"
        _, available, unavailable = compute_features(
            semantics, registry.rung_features("R10"), dataset=dataset, strict=False
        )
        assert unavailable, "UNSW must report unavailable R10 features"
        assert not (set(unavailable) - set(registry.rung_features("R10")))
        # and strict mode must raise rather than substitute
        with pytest.raises(Exception):
            extract_semantics(cleaned.frame, dataset, registry, strict=True)
    else:
        assert report["semantic_absent"] == []
        _, available, unavailable = compute_features(
            semantics, registry.rung_features("R10"), dataset=dataset, strict=False
        )
        assert unavailable == [], f"{dataset}: unexpected unavailable {unavailable}"


def test_cse_repeated_header_rows_are_rejected_not_benign(contract):
    """Real repeated-header artifacts (value 'Label') must be UNKNOWN, never BENIGN."""
    path = Path(
        "data/raw/cse_cic_ids2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv"
    )
    if not path.is_file():
        pytest.skip("CSE file with known repeated-header rows not present")
    header = list(pd.read_csv(path, nrows=0).columns)
    label_col = next(c for c in header if canonicalize_column(c) == "Label")
    series = pd.read_csv(
        path, usecols=[label_col], nrows=100_000, low_memory=False
    )
    n_repeated = int(series[label_col].astype(str).str.strip().eq("Label").sum())
    if n_repeated == 0:
        pytest.skip("repeated-header rows not within the scanned prefix")

    app = apply_label_contract(series, "cse_cic_ids2018", contract)
    rejected_mask = ~app.accepted_mask
    assert int(rejected_mask.sum()) >= n_repeated
    # every rejected row normalized to LABEL (not BENIGN)
    assert app.canonical[rejected_mask].eq("UNKNOWN").all()
    assert app.binary[rejected_mask].eq(-1).all()
    assert not app.normalized[rejected_mask].eq("BENIGN").any()
    assert app.normalized[rejected_mask].eq("LABEL").all()
