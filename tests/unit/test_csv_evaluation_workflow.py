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
    clear_cached_evaluations,
    evaluate_csv_dataset,
    export_evaluated_csv_string,
    get_cached_evaluation,
    get_demo_sample_csv,
    parse_strict_binary_label,
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


def test_csv_benchmark_contract_incompatibility_rejected():
    """Unsupported combinations of benchmark and contract are rejected before artifact loading."""
    dummy_data = {f: [100.0] for f in R10_FEATURES}
    df_r10 = pd.DataFrame(dummy_data)
    dummy_r4 = {f: [100.0] for f in R4_FEATURES}
    df_r4 = pd.DataFrame(dummy_r4)

    # UNSW-NB15 requires R4, rejecting R10
    with pytest.raises(CSVValidationError, match="Incompatible benchmark and feature contract.*unswnb15.*R4"):
        evaluate_csv_dataset(df_r10, contract="R10", benchmark="unswnb15")

    # CICIDS2017 requires R10, rejecting R4
    with pytest.raises(CSVValidationError, match="Incompatible benchmark and feature contract.*cicids2017.*R10"):
        evaluate_csv_dataset(df_r4, contract="R4", benchmark="cicids2017")

    # CSE-CIC-IDS2018 requires R10, rejecting R4
    with pytest.raises(CSVValidationError, match="Incompatible benchmark and feature contract.*cse2018.*R10"):
        evaluate_csv_dataset(df_r4, contract="R4", benchmark="cse2018")

    # Unknown benchmark
    with pytest.raises(CSVValidationError, match="Unknown benchmark 'unknown_bench'"):
        evaluate_csv_dataset(df_r10, contract="R10", benchmark="unknown_bench")


def test_strict_binary_label_parsing_valid():
    """Verify strict parsing for valid binary numeric and textual labels."""
    assert parse_strict_binary_label(0, 0) == 0
    assert parse_strict_binary_label(0.0, 1) == 0
    assert parse_strict_binary_label(1, 2) == 1
    assert parse_strict_binary_label(1.0, 3) == 1

    # String numeric
    assert parse_strict_binary_label("0", 4) == 0
    assert parse_strict_binary_label("0.0", 5) == 0
    assert parse_strict_binary_label("1", 6) == 1
    assert parse_strict_binary_label("1.0", 7) == 1

    # Textual benign
    assert parse_strict_binary_label("BENIGN", 8) == 0
    assert parse_strict_binary_label("benign", 9) == 0
    assert parse_strict_binary_label("NORMAL", 10) == 0
    assert parse_strict_binary_label("clean", 11) == 0

    # Textual attacks and families
    assert parse_strict_binary_label("ATTACK", 12) == 1
    assert parse_strict_binary_label("attack", 13) == 1
    assert parse_strict_binary_label("DDoS", 14) == 1
    assert parse_strict_binary_label("DoS Hulk", 15) == 1
    assert parse_strict_binary_label("PortScan", 16) == 1
    assert parse_strict_binary_label("FTP-Patator", 17) == 1
    assert parse_strict_binary_label("Exploits", 18) == 1
    assert parse_strict_binary_label("Fuzzers", 19) == 1


def test_strict_binary_label_parsing_invalid():
    """Non-binary, ambiguous, unrecognized, or missing labels raise CSVValidationError."""
    # Invalid numeric
    with pytest.raises(CSVValidationError, match="Invalid numeric ground-truth label '2'"):
        parse_strict_binary_label(2, 0)
    with pytest.raises(CSVValidationError, match="Invalid numeric ground-truth label '-1'"):
        parse_strict_binary_label(-1, 1)
    with pytest.raises(CSVValidationError, match="Invalid numeric ground-truth label '0.5'"):
        parse_strict_binary_label(0.5, 2)

    # Invalid numeric strings
    with pytest.raises(CSVValidationError, match="Invalid numeric ground-truth label string '2.0'"):
        parse_strict_binary_label("2.0", 3)
    with pytest.raises(CSVValidationError, match="Invalid numeric ground-truth label string '-1'"):
        parse_strict_binary_label("-1", 4)

    # Missing / Null
    with pytest.raises(CSVValidationError, match="missing or null"):
        parse_strict_binary_label(None, 5)
    with pytest.raises(CSVValidationError, match="missing or null"):
        parse_strict_binary_label(float("nan"), 6)
    with pytest.raises(CSVValidationError, match="label string is empty"):
        parse_strict_binary_label("   ", 7)

    # Unrecognized string
    with pytest.raises(CSVValidationError, match="Invalid or unrecognized ground-truth label 'random_malware'"):
        parse_strict_binary_label("random_malware", 8)


def test_csv_evaluation_row_accounting_reconciliation_mixed():
    """Verify exact total == evaluated + dropped accounting across mixed NaN, +Inf, -Inf, and string errors."""
    data = {f: [1200.0] * 8 for f in R10_FEATURES}
    data["label"] = [0, 1, 0, 1, 0, 1, 0, 1]

    # Row 0: valid
    # Row 1: valid
    # Row 2: valid
    # Row 3: valid
    # Row 4: +Inf in flow_duration_ms
    data["flow_duration_ms"][4] = float("inf")
    # Row 5: -Inf in flow_packets_per_s
    data["flow_packets_per_s"][5] = float("-inf")
    # Row 6: NaN in syn_count
    data["syn_count"][6] = float("nan")
    # Row 7: Unparseable non-numeric string in ack_count
    data["ack_count"][7] = "corrupt_text"

    df = pd.DataFrame(data)
    assert len(df) == 8

    res = evaluate_csv_dataset(df, contract="R10", benchmark="cicids2017")
    acct = res["row_accounting"]

    assert acct["total_rows_received"] == 8
    assert acct["evaluated_rows"] == 4
    assert acct["invalid_rows_dropped"] == 4
    assert acct["inf_rows_dropped"] == 2
    assert acct["nan_rows_dropped"] == 2
    assert acct["total_rows_received"] == acct["evaluated_rows"] + acct["invalid_rows_dropped"]
    assert "2 rows with Infinity/-Infinity" in acct["drop_reason"]
    assert "2 rows with NaN" in acct["drop_reason"]

    # Strict 1:1 index alignment check
    assert res["is_labelled"] is True
    assert res["metrics"]["population"] == 4
    assert len(res["flows"]) == 4
    # The valid rows correspond to original indices 0, 1, 2, 3
    valid_ids = [f["flow_id"] for f in res["flows"]]
    assert valid_ids == [0, 1, 2, 3]


def test_csv_evaluation_single_class_edge_cases():
    """Verify single-class benign and single-class attack datasets evaluate gracefully without uncaught errors."""
    # All benign
    data_benign = {f: [1200.0, 800.0, 950.0] for f in R10_FEATURES}
    data_benign["label"] = [0, 0, 0]
    df_benign = pd.DataFrame(data_benign)

    res_b = evaluate_csv_dataset(df_benign, contract="R10", benchmark="cicids2017")
    assert res_b["is_labelled"] is True
    assert res_b["metrics"]["accuracy"] is not None
    assert res_b["confusion_matrix"]["tp"] == 0
    assert res_b["confusion_matrix"]["fn"] == 0

    # All attack
    data_attack = {f: [1200.0, 800.0, 950.0] for f in R10_FEATURES}
    data_attack["label"] = [1, 1, 1]
    df_attack = pd.DataFrame(data_attack)

    res_a = evaluate_csv_dataset(df_attack, contract="R10", benchmark="cicids2017")
    assert res_a["is_labelled"] is True
    assert res_a["metrics"]["accuracy"] is not None
    assert res_a["confusion_matrix"]["tn"] == 0
    assert res_a["confusion_matrix"]["fp"] == 0


def test_csv_server_cache_and_export_authoritative(csv_server):
    """Verify server cache prevents tampering and exports full authoritative population."""
    sample = get_demo_sample_csv(n_samples=4)
    eval_req = urllib.request.Request(
        f"{csv_server}/api/csv/evaluate",
        data=json.dumps({
            "csv_text": sample,
            "contract": "R10",
            "benchmark": "cicids2017",
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(eval_req, timeout=5) as resp:
        assert resp.status == 200
        res_data = json.loads(resp.read().decode("utf-8"))

    eval_id = res_data["evaluation_id"]
    assert eval_id is not None
    # Client should not have _full_records
    assert "_full_records" not in res_data

    # Server cache MUST have it
    cached = get_cached_evaluation(eval_id)
    assert cached is not None
    assert "_full_records" in cached

    # Export using evaluation_id
    export_req = urllib.request.Request(
        f"{csv_server}/api/csv/export",
        data=json.dumps({"evaluation_id": eval_id}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(export_req, timeout=5) as resp:
        assert resp.status == 200
        csv_body = resp.read().decode("utf-8")

    assert f"# Evaluation ID: {eval_id}" in csv_body
    assert "Complete Evaluated Population" in csv_body
    assert "flow_id,attack_score" in csv_body

    # Attempt export with non-existent evaluation_id -> 404
    missing_req = urllib.request.Request(
        f"{csv_server}/api/csv/export",
        data=json.dumps({"evaluation_id": "00000000-0000-0000-0000-000000000000"}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(missing_req, timeout=5)
    assert exc_info.value.code == 404


def test_csv_api_incompatible_benchmark_contract_rejected(csv_server):
    """POST /api/csv/evaluate rejects incompatible benchmark/contract with HTTP 400."""
    sample = get_demo_sample_csv(n_samples=2)
    req = urllib.request.Request(
        f"{csv_server}/api/csv/evaluate",
        data=json.dumps({
            "csv_text": sample,
            "contract": "R10",
            "benchmark": "unswnb15",  # UNSW-NB15 requires R4
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=5)
    assert exc_info.value.code == 400
    err_body = json.loads(exc_info.value.read().decode("utf-8"))
    assert err_body["status"] == "validation_error"
    assert "Incompatible benchmark and feature contract" in err_body["error"]
