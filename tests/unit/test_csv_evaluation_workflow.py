"""Unit tests for the CSV Dataset Evaluation and Export Workflow.

Verifies:
1. R10 and R4 contract enforcement.
2. Target leakage prevention: label columns are strictly isolated and dropped from model inputs.
3. Row accounting: invalid / infinite values are tracked and dropped with explicit reasons.
4. Centralized metrics: reproducible metrics computed via xrlids.evaluation.metrics.
5. REST APIs: POST /api/csv/evaluate, POST /api/csv/export, GET /api/csv/sample.
6. Provenance & Artifact Integrity: frozen experiment models and preprocessors remain untouched.
"""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.request
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import pandas as pd
import pytest

from dashboard.server import create_server
from xrlids.evaluation.csv_evaluator import (
    CSVValidationError,
    evaluate_csv_dataset,
    export_evaluated_csv_string,
    get_demo_sample_csv,
)
from xrlids.features.definitions import R4_FEATURES, R10_FEATURES

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def csv_server():
    server = create_server(port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_csv_evaluation_valid_r10_labelled():
    """Verify R10 evaluation produces metrics and confusion matrix when label is present."""
    data = {f: [1200.0, 500.0, 800.0, 1500.0] for f in R10_FEATURES}
    data["label"] = [0, 1, 0, 1]
    df = pd.DataFrame(data)

    res = evaluate_csv_dataset(df, contract="R10", benchmark="cicids2017")
    assert res["status"] == "success"
    assert res["contract"] == "R10"
    assert res["is_labelled"] is True
    assert res["label_column_detected"] == "label"
    assert res["row_accounting"]["total_rows_received"] == 4
    assert res["row_accounting"]["evaluated_rows"] == 4
    assert res["row_accounting"]["invalid_rows_dropped"] == 0

    assert res["metrics"] is not None
    assert "accuracy" in res["metrics"]
    assert "f1" in res["metrics"]
    assert res["confusion_matrix"] is not None
    assert set(res["confusion_matrix"].keys()) == {"tp", "fp", "tn", "fn"}

    # Disclaimer verification
    assert res["official_frozen_benchmark"] is False
    assert "Ad-hoc CSV evaluation" in res["disclaimer"]


def test_csv_evaluation_valid_r10_unlabelled():
    """Verify unlabelled CSVs run inference without error and report UNLABELLED status."""
    data = {f: [100.0, 250.0] for f in R10_FEATURES}
    df = pd.DataFrame(data)

    res = evaluate_csv_dataset(df, contract="R10", benchmark="cicids2017")
    assert res["status"] == "success"
    assert res["is_labelled"] is False
    assert res["metrics"] is None
    assert res["confusion_matrix"] is None
    assert len(res["flows"]) == 2
    for flow in res["flows"]:
        assert flow["ground_truth_label"] == "UNLABELLED"
        assert flow["verdict"] == "UNVERIFIED"
        assert 0.0 <= flow["attack_score"] <= 1.0


def test_csv_evaluation_r4_contract():
    """Verify R4 4-feature contract on UNSW-NB15 benchmark."""
    data = {f: [50.0, 150.0] for f in R4_FEATURES}
    data["Class"] = [0, 1]
    df = pd.DataFrame(data)

    res = evaluate_csv_dataset(df, contract="R4", benchmark="unswnb15")
    assert res["status"] == "success"
    assert res["contract"] == "R4"
    assert res["is_labelled"] is True
    assert res["label_column_detected"] == "Class"
    assert "UNSW-NB15" in res["model_identifier"]


def test_csv_evaluation_schema_rejection():
    """Missing required feature columns raises CSVValidationError with descriptive message."""
    data = {f: [10.0] for f in R10_FEATURES}
    del data["syn_count"]
    df = pd.DataFrame(data)

    with pytest.raises(CSVValidationError, match="Missing required R10 feature columns: \\['syn_count'\\]"):
        evaluate_csv_dataset(df, contract="R10")


def test_csv_evaluation_target_leakage_prevented():
    """Verify label candidate columns are stripped and cannot leak into model inputs."""
    data = {f: [100.0] for f in R10_FEATURES}
    data["true_label"] = [1]
    data["is_attack"] = [1]
    data["target"] = [1]
    df = pd.DataFrame(data)

    res = evaluate_csv_dataset(df, contract="R10")
    assert res["is_labelled"] is True
    # Features in output record must strictly be the 10 R10 features
    flow_features = res["flows"][0]["features"]
    assert set(flow_features.keys()) == set(R10_FEATURES)
    assert "true_label" not in flow_features
    assert "is_attack" not in flow_features


def test_csv_evaluation_row_accounting_drops_inf():
    """Rows with non-finite values (Infinity) are dropped and tracked in row accounting."""
    data = {f: [100.0, float("inf"), 200.0] for f in R10_FEATURES}
    df = pd.DataFrame(data)

    res = evaluate_csv_dataset(df, contract="R10")
    acct = res["row_accounting"]
    assert acct["total_rows_received"] == 3
    assert acct["invalid_rows_dropped"] == 1
    assert acct["evaluated_rows"] == 2
    assert "Non-finite numeric values" in acct["drop_reason"]


def test_csv_sample_endpoint(csv_server):
    """GET /api/csv/sample returns a valid CSV with R10 headers and real flow values."""
    url = f"{csv_server}/api/csv/sample"
    with urllib.request.urlopen(url, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))

    assert "csv_text" in data
    assert data["contract"] == "R10"
    csv_text = data["csv_text"]
    for feat in R10_FEATURES:
        assert feat in csv_text


def test_csv_evaluate_api_endpoint(csv_server):
    """POST /api/csv/evaluate processes raw CSV string and returns structured JSON report."""
    sample = get_demo_sample_csv(n_samples=4)
    payload = json.dumps({
        "csv_text": sample,
        "contract": "R10",
        "benchmark": "cicids2017",
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{csv_server}/api/csv/evaluate",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))

    assert data["status"] == "success"
    assert data["row_accounting"]["evaluated_rows"] >= 4
    assert len(data["flows"]) >= 4


def test_csv_export_api_endpoint(csv_server):
    """POST /api/csv/export generates downloadable CSV with provenance headers."""
    sample = get_demo_sample_csv(n_samples=2)
    eval_res = evaluate_csv_dataset(sample, contract="R10")

    payload = json.dumps({"eval_result": eval_res}).encode("utf-8")
    req = urllib.request.Request(
        f"{csv_server}/api/csv/export",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        assert "text/csv" in resp.headers.get("Content-Type")
        content = resp.read().decode("utf-8")

    assert "# XRL-IDARS Evaluated CSV Dataset Export" in content
    assert "flow_id,attack_score" in content


def test_csv_frozen_artifacts_untouched():
    """Verify evaluation does not modify frozen preprocessor or model artifact checksums."""
    prep_path = REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "preprocessor.joblib"
    model_path = REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "random_forest.joblib"

    def _file_hash(p):
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for b in iter(lambda: f.read(65536), b""):
                h.update(b)
        return h.hexdigest()

    h_prep_before = _file_hash(prep_path)
    h_model_before = _file_hash(model_path)

    # Run evaluation
    sample = get_demo_sample_csv(n_samples=6)
    evaluate_csv_dataset(sample, contract="R10")

    assert _file_hash(prep_path) == h_prep_before, "Preprocessor artifact was altered!"
    assert _file_hash(model_path) == h_model_before, "Model artifact was altered!"
