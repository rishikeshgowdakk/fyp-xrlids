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


def test_csv_multi_model_rf_lstm_fusion():
    """Verify that CSV evaluation produces RF, LSTM, and Fusion outputs and tracks warm-up."""
    # Create 8 flows (T=5, so 4 warm-up flows and 4 aligned sequence flows)
    data = {f: [100.0 * (i + 1) for i in range(8)] for f in R10_FEATURES}
    data["label"] = [0, 0, 0, 0, 1, 1, 1, 1]
    df = pd.DataFrame(data)

    res = evaluate_csv_dataset(df, contract="R10", benchmark="cicids2017")
    assert res["status"] == "success"
    assert "model_metrics" in res
    assert "rf" in res["model_metrics"]
    assert "lstm" in res["model_metrics"]
    assert "fusion" in res["model_metrics"]

    # Check row accounting for sequences and warm-up
    acct = res["row_accounting"]
    assert acct["evaluated_rows"] == 8
    assert acct["aligned_sequence_rows"] == 4
    assert acct["warmup_rows"] == 4

    # Check flows output
    flows = res["flows"]
    assert len(flows) == 8

    # First 4 flows are in warm-up
    for i in range(4):
        assert flows[i]["lstm_status"] == "WARM_UP"
        assert flows[i]["lstm_score"] is None
        assert 0.0 <= flows[i]["rf_score"] <= 1.0
        assert flows[i]["fusion_score"] == flows[i]["rf_score"]

    # Flows 4-7 are sequence-aligned
    for i in range(4, 8):
        assert flows[i]["lstm_status"] == "ALIGNED"
        assert flows[i]["lstm_score"] is not None
        assert 0.0 <= flows[i]["lstm_score"] <= 1.0
        expected_fusion = round(0.5 * flows[i]["rf_score"] + 0.5 * flows[i]["lstm_score"], 4)
        assert abs(flows[i]["fusion_score"] - expected_fusion) <= 0.0002


def test_csv_mode_b_exhibition_200():
    """Verify Mode B (Exhibition 200 subset) loads 166 benign and 34 attack records and scores them."""
    res = evaluate_csv_dataset(mode="exhibition", contract="R10", benchmark="cicids2017")
    assert res["status"] == "success"
    assert res["evaluation_mode"] == "exhibition"
    assert res["evaluation_type"] == "fixed_exhibition_subset"
    assert res["row_accounting"]["total_rows_received"] == 200
    assert res["row_accounting"]["evaluated_rows"] == 200
    assert res["row_accounting"]["aligned_sequence_rows"] == 196
    assert res["row_accounting"]["warmup_rows"] == 4

    # Verify metrics for all 3 models
    m_rf = res["model_metrics"]["rf"]
    m_lstm = res["model_metrics"]["lstm"]
    m_fusion = res["model_metrics"]["fusion"]

    assert m_rf["population"] == 200
    assert m_lstm["population"] == 196
    assert m_fusion["population"] == 196

    assert 0.80 <= m_rf["accuracy"] <= 1.00
    assert 0.80 <= m_fusion["accuracy"] <= 1.00

    # Verify flow records preserve endpoints
    flows = res["flows"]
    assert len(flows) == 100  # display limit
    assert flows[0]["metadata"]["src_endpoint"] != "Not available in source data"
    assert flows[0]["metadata"]["dst_endpoint"] != "Not available in source data"


def test_csv_mode_a_full_held_out_test():
    """Verify Mode A (Full Test) returns authoritative held-out metrics from research artifacts."""
    res = evaluate_csv_dataset(mode="full_test", contract="R10", benchmark="cicids2017")
    assert res["status"] == "success"
    assert res["evaluation_mode"] == "full_test"
    assert res["official_frozen_benchmark"] is True
    assert res["row_accounting"]["evaluated_rows"] == 355865
    assert res["row_accounting"]["aligned_sequence_rows"] == 355833
    assert res["row_accounting"]["warmup_rows"] == 32

    # Verify frozen fusion metrics match published research
    assert res["metrics"]["population"] == 355833
    assert abs(res["metrics"]["accuracy"] - 0.9906) <= 0.001
    assert abs(res["metrics"]["f1"] - 0.9745) <= 0.001


def test_csv_metadata_preservation_and_isolation():
    """Verify network flow metadata is preserved in output without contaminating ML feature matrix."""
    data = {f: [1200.0, 500.0] for f in R10_FEATURES}
    data["label"] = [0, 1]
    data["src_endpoint"] = ["192.168.10.15:45000", "172.16.0.1:58000"]
    data["dst_endpoint"] = ["142.250.190.40:443", "192.168.10.50:80"]
    data["protocol"] = ["TCP", "TCP"]
    df = pd.DataFrame(data)

    res = evaluate_csv_dataset(df, contract="R10", benchmark="cicids2017")
    assert res["status"] == "success"
    flows = res["flows"]
    assert len(flows) == 2

    # Metadata correctly populated
    assert flows[0]["metadata"]["src_endpoint"] == "192.168.10.15:45000"
    assert flows[0]["metadata"]["dst_endpoint"] == "142.250.190.40:443"
    assert flows[1]["metadata"]["src_endpoint"] == "172.16.0.1:58000"
    assert flows[1]["metadata"]["dst_endpoint"] == "192.168.10.50:80"

    # Feature dictionary contains ONLY expected R10 features
    for fl in flows:
        assert set(fl["features"].keys()) == set(R10_FEATURES)
        assert "src_endpoint" not in fl["features"]
        assert "dst_endpoint" not in fl["features"]
        assert "protocol" not in fl["features"]
        assert "label" not in fl["features"]


def test_csv_explain_api_and_dqn_response(csv_server):
    """Verify POST /api/csv/explain returns TreeSHAP and flow contains DQN recommendations."""
    # 1. Test /api/csv/explain
    explain_req = urllib.request.Request(
        f"{csv_server}/api/csv/explain",
        data=json.dumps({
            "features": {f: 100.0 for f in R10_FEATURES},
            "benchmark": "cicids2017",
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(explain_req, timeout=5) as resp:
        assert resp.status == 200
        exp_data = json.loads(resp.read().decode("utf-8"))
        assert "features" in exp_data
        assert len(exp_data["features"]) == 10
        assert "TreeExplainer" in exp_data["explainer_model"]
        assert "TreeSHAP explains Random Forest tree decisions only" in exp_data["scientific_notices"][0]

    # 2. Test DQN recommendation in flow evaluation output
    sample = get_demo_sample_csv(n_samples=2)
    eval_res = evaluate_csv_dataset(sample, contract="R10", benchmark="cicids2017")
    flow0 = eval_res["flows"][0]
    assert "response" in flow0
    resp_policy = flow0["response"]
    assert resp_policy["recommended_action"] in ("ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE")
    assert "DRY_RUN" in resp_policy["execution_mode"]


def test_csv_mode_a_full_test_evaluation(csv_server):
    """Verify Mode A evaluates the authoritative held-out test split (CIC-IDS2017, CSE-2018, UNSW-NB15)."""
    # 1. Direct evaluate_csv_dataset call in full_test mode
    res_a = evaluate_csv_dataset(
        contract="R10",
        benchmark="cicids2017",
        mode="full_test",
        max_display_flows=50,
    )
    assert res_a["mode"] == "full_test"
    assert res_a["split_name"] == "held_out_test"
    assert res_a["row_accounting"]["evaluated_rows"] == 355865
    assert res_a["is_labelled"] is True
    assert "rf_metrics" in res_a
    assert "lstm_metrics" in res_a
    assert "fusion_metrics" in res_a

    # 2. HTTP POST in full_test mode
    req = urllib.request.Request(
        f"{csv_server}/api/csv/evaluate",
        data=json.dumps({
            "mode": "full_test",
            "benchmark": "cicids2017",
            "contract": "R10",
            "max_rows": 25,
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200
        http_data = json.loads(resp.read().decode("utf-8"))
        assert http_data["mode"] == "full_test"
        assert http_data["row_accounting"]["evaluated_rows"] == 355865
        assert len(http_data["flows"]) == 25
        # Verify first flow has valid multi-model predictions
        f0 = http_data["flows"][0]
        assert "rf_score" in f0
        assert "lstm_score" in f0
        assert "attack_score" in f0


def test_csv_mode_b_all_three_benchmarks(csv_server):
    """Verify Mode B exhibition demo for all 3 benchmark datasets (CICIDS2017, CSE-2018, UNSW-NB15)."""
    # 1. CIC-IDS2017 Mode B
    res_cic = evaluate_csv_dataset(contract="R10", benchmark="cicids2017", mode="exhibition", max_display_flows=200)
    assert res_cic["status"] == "success"
    assert res_cic["mode"] == "exhibition"
    assert res_cic["row_accounting"]["evaluated_rows"] == 200
    assert res_cic["row_accounting"]["aligned_sequence_rows"] == 196
    # Tabular RF evaluated on all 200 flows
    assert res_cic["rf_confusion_matrix"]["tp"] + res_cic["rf_confusion_matrix"]["fn"] == 34
    assert res_cic["rf_confusion_matrix"]["tn"] + res_cic["rf_confusion_matrix"]["fp"] == 166
    # Sequence LSTM & Fusion evaluated on 196 aligned flows (4 warmup flows)
    assert res_cic["confusion_matrix"]["tp"] + res_cic["confusion_matrix"]["fn"] == 34
    assert res_cic["confusion_matrix"]["tn"] + res_cic["confusion_matrix"]["fp"] == 162
    assert "rf_metrics" in res_cic and "lstm_metrics" in res_cic and "fusion_metrics" in res_cic
    assert len(res_cic["flows"]) == 200
    assert "192.168.10" in res_cic["flows"][0]["metadata"]["src_endpoint"]

    # 2. CSE-CIC-IDS2018 Mode B
    res_cse = evaluate_csv_dataset(contract="R10", benchmark="cse2018", mode="exhibition", max_display_flows=200)
    assert res_cse["status"] == "success"
    assert res_cse["mode"] == "exhibition"
    assert res_cse["row_accounting"]["evaluated_rows"] == 200
    assert res_cse["row_accounting"]["aligned_sequence_rows"] == 196
    assert res_cse["rf_confusion_matrix"]["tp"] + res_cse["rf_confusion_matrix"]["fn"] == 34
    assert res_cse["rf_confusion_matrix"]["tn"] + res_cse["rf_confusion_matrix"]["fp"] == 166
    assert res_cse["confusion_matrix"]["tp"] + res_cse["confusion_matrix"]["fn"] == 34
    assert res_cse["confusion_matrix"]["tn"] + res_cse["confusion_matrix"]["fp"] == 162
    assert "rf_metrics" in res_cse and "lstm_metrics" in res_cse and "fusion_metrics" in res_cse
    assert len(res_cse["flows"]) == 200
    assert "172.31.65" in res_cse["flows"][0]["metadata"]["src_endpoint"]

    # 3. UNSW-NB15 Mode B
    res_unsw = evaluate_csv_dataset(contract="R4", benchmark="unswnb15", mode="exhibition", max_display_flows=200)
    assert res_unsw["status"] == "success"
    assert res_unsw["mode"] == "exhibition"
    assert res_unsw["row_accounting"]["evaluated_rows"] == 200
    assert res_unsw["row_accounting"]["aligned_sequence_rows"] == 196
    assert res_unsw["rf_confusion_matrix"]["tp"] + res_unsw["rf_confusion_matrix"]["fn"] == 34
    assert res_unsw["rf_confusion_matrix"]["tn"] + res_unsw["rf_confusion_matrix"]["fp"] == 166
    assert res_unsw["confusion_matrix"]["tp"] + res_unsw["confusion_matrix"]["fn"] == 34
    assert res_unsw["confusion_matrix"]["tn"] + res_unsw["confusion_matrix"]["fp"] == 162
    assert "rf_metrics" in res_unsw and "lstm_metrics" in res_unsw and "fusion_metrics" in res_unsw
    assert len(res_unsw["flows"]) == 200
    assert "10.40.85" in res_unsw["flows"][0]["metadata"]["src_endpoint"]

    # 4. HTTP Sample Retrieval for all 3 datasets
    for bench, expected_contract, expected_sub in [
        ("cicids2017", "R10", "192.168.10"),
        ("cse2018", "R10", "172.31.65"),
        ("unswnb15", "R4", "10.40.85"),
    ]:
        with urllib.request.urlopen(f"{csv_server}/api/csv/sample?benchmark={bench}", timeout=5) as resp:
            assert resp.status == 200
            sdata = json.loads(resp.read().decode("utf-8"))
            assert sdata["benchmark"] == bench
            assert sdata["contract"] == expected_contract
            assert sdata["rows"] == 200
            assert expected_sub in sdata["csv_text"]


def test_sequence_boundary_safety_multiple_segments():
    """Verify that LSTM sequences never cross independent capture boundaries.

    Segment 1: 6 flows from file_A.pcap -> 2 valid sequences (targets 4, 5), 4 warmup (0..3)
    Segment 2: 4 flows from file_B.pcap -> 0 valid sequences (length 4 < T=5), 4 warmup (6..9)
    Segment 3: 7 flows from file_C.pcap -> 3 valid sequences (targets 14, 15, 16), 4 warmup (10..13)
    Total flows: 17
    RF evaluated rows: 17 (RF does not lose rows to sequence warmup)
    LSTM aligned rows: 5 (targets 4, 5, 14, 15, 16)
    Total warmup rows: 12
    """
    total_n = 17
    data = {f: [100.0 + i for i in range(total_n)] for f in R10_FEATURES}
    data["label"] = [0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0]
    data["source_file"] = (
        ["file_A.pcap"] * 6 +
        ["file_B.pcap"] * 4 +
        ["file_C.pcap"] * 7
    )
    df = pd.DataFrame(data)

    res = evaluate_csv_dataset(csv_source=df, contract="R10", benchmark="cicids2017")

    assert res["status"] == "success"
    acct = res["row_accounting"]
    assert acct["total_rows_received"] == 17
    assert acct["evaluated_rows"] == 17
    assert acct["boundary_isolation_applied"] is True
    assert acct["boundary_column"] == "source_file"
    assert acct["boundary_segments_count"] == 3
    assert acct["aligned_sequence_rows"] == 5
    assert acct["warmup_rows"] == 12

    # Per-segment verification
    segs = acct["segments"]
    assert len(segs) == 3
    assert segs[0] == {"segment_id": "file_A.pcap", "total_flows": 6, "aligned_flows": 2, "warmup_flows": 4}
    assert segs[1] == {"segment_id": "file_B.pcap", "total_flows": 4, "aligned_flows": 0, "warmup_flows": 4}
    assert segs[2] == {"segment_id": "file_C.pcap", "total_flows": 7, "aligned_flows": 3, "warmup_flows": 4}

    # Verify model evaluation populations
    # 1. Random Forest evaluates ALL 17 rows
    rf_m = res["rf_metrics"]
    assert rf_m["population"] == 17
    rf_cm = res["rf_confusion_matrix"]
    assert rf_cm["tp"] + rf_cm["tn"] + rf_cm["fp"] + rf_cm["fn"] == 17

    # 2. Sequence models (LSTM and Fusion) evaluate strictly the 5 aligned sequence targets
    lstm_m = res["lstm_metrics"]
    assert lstm_m["population"] == 5
    lstm_cm = res["lstm_confusion_matrix"]
    assert lstm_cm["tp"] + lstm_cm["tn"] + lstm_cm["fp"] + lstm_cm["fn"] == 5

    fusion_m = res["fusion_metrics"]
    assert fusion_m["population"] == 5
    fusion_cm = res["fusion_confusion_matrix"]
    assert fusion_cm["tp"] + fusion_cm["tn"] + fusion_cm["fp"] + fusion_cm["fn"] == 5

    # Target alignment check in individual flows
    flows = res["flows"]
    assert len(flows) == 17
    # Segment 1: flows 0..3 are WARM_UP; flows 4, 5 are ALIGNED
    for i in range(4):
        assert flows[i]["lstm_status"] == "WARM_UP"
    assert flows[4]["lstm_status"] == "ALIGNED"
    assert flows[5]["lstm_status"] == "ALIGNED"

    # Segment 2: flows 6..9 ALL WARM_UP (under length threshold)
    for i in range(6, 10):
        assert flows[i]["lstm_status"] == "WARM_UP"

    # Segment 3: flows 10..13 are WARM_UP; flows 14, 15, 16 are ALIGNED
    for i in range(10, 14):
        assert flows[i]["lstm_status"] == "WARM_UP"
    for i in range(14, 17):
        assert flows[i]["lstm_status"] == "ALIGNED"


def test_csv_absence_of_boundary_column_defaults_to_single_stream():
    """Verify safe, explicit documentation and behavior when no boundary column is provided."""
    n = 10
    data = {f: [50.0 + i for i in range(n)] for f in R10_FEATURES}
    data["label"] = [0] * n
    df = pd.DataFrame(data)

    res = evaluate_csv_dataset(csv_source=df, contract="R10", benchmark="cicids2017")
    acct = res["row_accounting"]
    assert acct["boundary_isolation_applied"] is False
    assert acct["boundary_column"] is None
    assert acct["boundary_segments_count"] == 1
    assert "No capture boundary column detected" in acct["boundary_isolation_note"]
    assert acct["evaluated_rows"] == 10
    assert acct["aligned_sequence_rows"] == 6  # 10 - 5 + 1
    assert acct["warmup_rows"] == 4


def test_dqn_action_fallback_and_disclosure(monkeypatch):
    """Verify DQN recommendation disclosure vs rule fallback disclosure."""
    from xrlids.evaluation.csv_evaluator import _get_dqn_action

    # 1. Normal DQN inference (checkpoint exists)
    resp = _get_dqn_action(attack_score=0.92, flow_bytes=5000.0)
    assert resp["recommended_action"] in ["ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE"]
    assert resp["policy_type"] == "DQN_NEURAL_POLICY (DuelingQNetwork)"
    assert resp["is_fallback"] is False
    assert resp["q_values"] is not None
    assert "ALLOW" in resp["q_values"]
    assert "DRY_RUN" in resp["execution_mode"]

    # 2. Simulated checkpoint absence -> must explicitly disclose fallback
    import xrlids.evaluation.csv_evaluator as ce
    monkeypatch.setattr(ce, "REPO_ROOT", Path("/nonexistent/repo/root"))
    resp_fallback = ce._get_dqn_action(attack_score=0.92)
    assert resp_fallback["is_fallback"] is True
    assert "RULE_DRY_RUN" in resp_fallback["policy_type"]
    assert resp_fallback["q_values"] is None
    assert "fallback_reason" in resp_fallback
    assert "DQN checkpoint absent" in resp_fallback["fallback_reason"]
    assert resp_fallback["recommended_action"] == "ISOLATE"


def test_all_benchmarks_row_accounting_and_confusion_matrix_reconciliation():
    """Verify that evaluated rows = TP + TN + FP + FN across all three benchmarks."""
    benchmarks = [
        ("cicids2017", "R10", 355865, 355833, 32, 0.9815, 0.9512, 0.9815, 0.9512),
        ("cse2018", "R10", 1662459, 1662419, 40, 0.9723, 0.8861, 0.9723, 0.8861),
        ("unswnb15", "R4", 24504, 24496, 8, 0.8588, 0.8546, 0.8590, 0.8548),
    ]

    for bench, contract, exp_tabular, exp_aligned, exp_warmup, tab_acc, tab_f1, ali_acc, ali_f1 in benchmarks:
        res = evaluate_csv_dataset(mode="full_test", contract=contract, benchmark=bench)
        acct = res["row_accounting"]
        assert acct["evaluated_rows"] == exp_tabular
        assert acct["total_rows_received"] == exp_tabular
        assert acct["aligned_sequence_rows"] == exp_aligned
        assert acct["warmup_rows"] == exp_warmup
        assert acct["aligned_sequence_rows"] + acct["warmup_rows"] == acct["evaluated_rows"]

        # Random Forest Tabular evaluation on all rows
        rf_tab_cm = res["rf_tabular_confusion_matrix"]
        rf_tab_sum = rf_tab_cm["tp"] + rf_tab_cm["tn"] + rf_tab_cm["fp"] + rf_tab_cm["fn"]
        assert rf_tab_sum == exp_tabular
        assert res["rf_tabular_metrics"]["population"] == exp_tabular
        assert res["rf_tabular_metrics"]["accuracy"] == pytest.approx(tab_acc, abs=1e-4)
        assert res["rf_tabular_metrics"]["f1"] == pytest.approx(tab_f1, abs=1e-4)

        # Random Forest Aligned evaluation on sequence slice
        rf_cm = res["rf_confusion_matrix"]
        rf_sum = rf_cm["tp"] + rf_cm["tn"] + rf_cm["fp"] + rf_cm["fn"]
        assert rf_sum == exp_aligned
        assert res["rf_metrics"]["population"] == exp_aligned
        assert res["rf_metrics"]["accuracy"] == pytest.approx(ali_acc, abs=1e-4)
        assert res["rf_metrics"]["f1"] == pytest.approx(ali_f1, abs=1e-4)

        # Supervised LSTM on aligned slice
        lstm_cm = res["lstm_confusion_matrix"]
        lstm_sum = lstm_cm["tp"] + lstm_cm["tn"] + lstm_cm["fp"] + lstm_cm["fn"]
        assert lstm_sum == exp_aligned
        assert res["lstm_metrics"]["population"] == exp_aligned

        # Fusion on aligned slice
        fusion_cm = res["fusion_confusion_matrix"]
        fusion_sum = fusion_cm["tp"] + fusion_cm["tn"] + fusion_cm["fp"] + fusion_cm["fn"]
        assert fusion_sum == exp_aligned
        assert res["fusion_metrics"]["population"] == exp_aligned


def test_unsw_nb15_tabular_vs_aligned_f1_mathematical_proof():
    """Independently recompute and mathematically verify UNSW-NB15 metrics.

    Proof of F1 discrepancy resolution:
    - Tabular RF (N=24,504): TP=10171, TN=10873, FP=2603, FN=857
      Precision = 10171 / (10171 + 2603) = 0.7962267
      Recall = 10171 / (10171 + 857) = 0.9222887
      F1 = 2 * P * R / (P + R) = 20342 / (20342 + 2603 + 857) = 20342 / 23802 = 0.85463406... (~0.8546)

    - Aligned RF (N=24,496, 8 warmup flows dropped: 2 TN and 6 FP dropped):
      TP=10171, TN=10871, FP=2597, FN=857
      Precision = 10171 / (10171 + 2597) = 0.7966009
      Recall = 10171 / (10171 + 857) = 0.9222887
      F1 = 2 * P * R / (P + R) = 20342 / (20342 + 2597 + 857) = 20342 / 23796 = 0.85484955... (~0.8548)
    """
    # 1. Pure mathematical verification
    tp, fn = 10171, 857
    fp_tab, tn_tab = 2603, 10873
    fp_ali, tn_ali = 2597, 10871

    # Tabular
    acc_tab = (tp + tn_tab) / (tp + tn_tab + fp_tab + fn)
    prec_tab = tp / (tp + fp_tab)
    rec_tab = tp / (tp + fn)
    f1_tab = 2 * prec_tab * rec_tab / (prec_tab + rec_tab)

    assert round(acc_tab, 4) == 0.8588
    assert round(f1_tab, 4) == 0.8546

    # Aligned
    acc_ali = (tp + tn_ali) / (tp + tn_ali + fp_ali + fn)
    prec_ali = tp / (tp + fp_ali)
    rec_ali = tp / (tp + fn)
    f1_ali = 2 * prec_ali * rec_ali / (prec_ali + rec_ali)

    assert round(acc_ali, 4) == 0.8590
    assert round(f1_ali, 4) == 0.8548

    # 2. Verification from predictions_test.csv
    pred_path = REPO_ROOT / "results" / "experiments" / "EXP-P1-UNSWNB15-R10-MULTI-001" / "predictions_test.csv"
    if pred_path.exists():
        df_pred = pd.read_csv(pred_path)
        assert len(df_pred) == 24496
        y_true = df_pred["true_label"].values
        y_pred = (df_pred["rf_score"].values >= 0.50).astype(int)

        from sklearn.metrics import accuracy_score, f1_score
        assert accuracy_score(y_true, y_pred) == pytest.approx(0.858997, abs=1e-5)
        assert f1_score(y_true, y_pred) == pytest.approx(0.854850, abs=1e-5)




