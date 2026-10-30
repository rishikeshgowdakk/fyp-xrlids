"""Unit tests for Labelled Dataset Replay Lab Engine and Dashboard integration.

Tests:
1. Cache pool integrity and multi-dataset R10 schema.
2. Deterministic sampling and reproducibility with random seeds.
3. Stratified mixed sampling and single-family selection.
4. Honest unavailable family handling (e.g. PortScan on CSE-2018).
5. Provenance preservation: source_file, row_index, raw label, binary truth.
6. Multi-dataset model and preprocessor routing (CIC-17 vs CSE-18).
7. Sequential 6D causal state builder and DQN advisory response evaluation.
8. Interactive lifecycle controls: Start, Pause, Resume, Restart, Stop.
9. 10,000-record batch execution performance and metric integrity.
10. On-demand TreeSHAP explanation for individual flow records.
11. Full CSV export with all 27 audit and feature columns.
12. Dashboard HTTP API routes over localhost.
"""

from __future__ import annotations

import csv
import io
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
import sys

import numpy as np
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dashboard.server import create_server
from xrlids.demo.replay_lab import (
    CACHE_POOL_PATH,
    ReplayLabConfig,
    ReplayLabEngine,
    ReplayRecord,
)
from xrlids.features.definitions import R10_FEATURES

# Replay Lab's 10k-record corpus is generated from large raw CIC/CSE CSVs,
# intentionally excluded from Git. Do not manufacture an empty cache in CI.
REPO_ROOT = Path(__file__).resolve().parents[2]
RAW_DATA_AVAILABLE = any((REPO_ROOT / "data" / "raw" / "cicids2017").glob("*.csv")) and any(
    (REPO_ROOT / "data" / "raw" / "cse_cic_ids2018").glob("*.csv")
)
pytestmark = pytest.mark.skipif(
    not RAW_DATA_AVAILABLE,
    reason="Replay Lab integration corpus requires externally provisioned raw CIC-IDS2017 and CSE-CIC-IDS2018 CSVs.",
)


@pytest.fixture(scope="module")
def replay_engine():
    """Module-level singleton instance of ReplayLabEngine."""
    engine = ReplayLabEngine.get_instance()
    # Ensure any background thread is stopped before tests begin
    engine.stop()
    return engine


def test_replay_lab_cache_pool_integrity():
    """Verify that the cached replay pool exists, is non-empty, and adheres to R10 schema."""
    assert CACHE_POOL_PATH.exists(), f"Replay cache pool not found at {CACHE_POOL_PATH}"
    import joblib

    pool = joblib.load(CACHE_POOL_PATH)
    assert len(pool) >= 10000, f"Expected at least 10,000 pool records, got {len(pool)}"

    # Check both datasets are represented
    datasets = {r["dataset"] for r in pool}
    assert any("cicids2017" in d.lower() for d in datasets), "CIC-IDS2017 missing in pool"
    assert any("cse" in d.lower() for d in datasets), "CSE-CIC-IDS2018 missing in pool"

    # Sample and inspect items
    for rec in pool[:200]:
        assert "dataset" in rec
        assert "source_file" in rec and len(rec["source_file"]) > 0
        assert "source_row_index" in rec and isinstance(rec["source_row_index"], int)
        assert "original_label" in rec and len(rec["original_label"]) > 0
        assert "binary_label" in rec and rec["binary_label"] in (0, 1)
        assert "ground_truth_family" in rec and len(rec["ground_truth_family"]) > 0
        assert "is_attack" in rec and isinstance(rec["is_attack"], bool)
        assert "features" in rec
        feats = rec["features"]
        for f in R10_FEATURES:
            assert f in feats, f"Missing feature {f} in record"
            assert isinstance(feats[f], (int, float, np.floating)), f"Feature {f} not numeric"
            assert not np.isnan(feats[f]), f"Feature {f} is NaN"


def test_replay_lab_deterministic_sampling(replay_engine: ReplayLabEngine):
    """Verify that identical random seeds produce identical record sequences."""
    sample_a = replay_engine.sample_records(dataset="cicids2017", count=400, selection="mixed", seed=42)
    sample_b = replay_engine.sample_records(dataset="cicids2017", count=400, selection="mixed", seed=42)
    sample_diff = replay_engine.sample_records(dataset="cicids2017", count=400, selection="mixed", seed=999)

    assert len(sample_a) == 400
    assert len(sample_b) == 400

    # Identical seed -> identical records
    for ra, rb in zip(sample_a, sample_b):
        assert ra["source_file"] == rb["source_file"]
        assert ra["source_row_index"] == rb["source_row_index"]
        assert ra["original_label"] == rb["original_label"]
        assert ra["features"] == rb["features"]

    # Different seed -> different sample
    diff_count = sum(
        1 for ra, rd in zip(sample_a, sample_diff)
        if ra["source_file"] != rd["source_file"] or ra["source_row_index"] != rd["source_row_index"]
    )
    assert diff_count > 0, "Different seeds should produce different selections"


def test_replay_lab_stratified_mixed_sampling(replay_engine: ReplayLabEngine):
    """Verify mixed selection balances benign and attack records and samples multiple families."""
    records = replay_engine.sample_records(dataset="both", count=1000, selection="mixed", seed=42)
    assert len(records) == 1000

    benign_count = sum(1 for r in records if not r["is_attack"])
    attack_count = sum(1 for r in records if r["is_attack"])

    assert benign_count == 500
    assert attack_count == 500

    attack_families = {r["ground_truth_family"] for r in records if r["is_attack"]}
    assert len(attack_families) >= 4, f"Expected diverse attack families, got {attack_families}"


def test_replay_lab_single_family_selection(replay_engine: ReplayLabEngine):
    """Verify single-family selection strictly extracts records for that ground-truth family."""
    dos_records = replay_engine.sample_records(dataset="cicids2017", count=300, selection="DoS", seed=42)
    assert len(dos_records) == 300
    for r in dos_records:
        assert r["ground_truth_family"].lower() == "dos"
        assert r["is_attack"] is True
        assert r["binary_label"] == 1


def test_replay_lab_unavailable_family_handling(replay_engine: ReplayLabEngine):
    """Verify selecting unavailable families in CSE-2018 returns empty list without error."""
    # PortScan exists in CIC-IDS2017 (158k) but 0 in CSE-CIC-IDS2018
    ps_cse = replay_engine.sample_records(dataset="cse2018", count=400, selection="PortScan", seed=42)
    assert len(ps_cse) == 0

    # Heartbleed exists in CIC-IDS2017 (11) but 0 in CSE-CIC-IDS2018
    hb_cse = replay_engine.sample_records(dataset="cse2018", count=400, selection="Heartbleed", seed=42)
    assert len(hb_cse) == 0


def test_replay_lab_available_config_metadata(replay_engine: ReplayLabEngine):
    """Verify metadata endpoint returns correct datasets, speed options, and family presence."""
    cfg = replay_engine.get_available_config()
    assert "datasets" in cfg
    assert len(cfg["datasets"]) == 3
    dataset_ids = [d["id"] for d in cfg["datasets"]]
    assert "cicids2017" in dataset_ids
    assert "cse2018" in dataset_ids
    assert "both" in dataset_ids

    assert "record_counts" in cfg
    assert 400 in cfg["record_counts"]
    assert 1000 in cfg["record_counts"]
    assert 5000 in cfg["record_counts"]
    assert 10000 in cfg["record_counts"]

    # Verify family metadata
    families_map = {f["family"]: f for f in cfg["families"]}
    assert "DoS" in families_map
    assert "DDoS" in families_map
    assert "PortScan" in families_map
    assert families_map["PortScan"]["in_cicids2017"] is True
    assert families_map["PortScan"]["in_cse2018"] is False
    assert families_map["Heartbleed"]["in_cicids2017"] is True
    assert families_map["Heartbleed"]["in_cse2018"] is False


def test_replay_lab_execution_batch_mode(replay_engine: ReplayLabEngine):
    """Execute a 400-record mixed replay run in batch mode and verify pipeline semantics."""
    cfg = ReplayLabConfig(dataset="cicids2017", count=400, selection="mixed", speed="batch", seed=42)
    res = replay_engine.start(cfg)
    assert res["status"] == "RUNNING"
    assert res["requested_count"] == 400
    assert res["selected_count"] == 400

    # Wait for completion (batch mode completes in < 0.5s)
    deadline = time.time() + 10.0
    status = replay_engine.get_status()
    while status["status"] == "RUNNING" and time.time() < deadline:
        time.sleep(0.05)
        status = replay_engine.get_status()

    assert status["status"] == "COMPLETED"
    assert status["processed_count"] == 400
    assert status["progress_pct"] == 100.0

    metrics = status["metrics"]
    cm = metrics["confusion_matrix"]
    total_cm = cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"]
    assert total_cm == 400
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1"] <= 1.0

    # Per-family recall breakdown
    per_fam = metrics["per_family"]
    assert len(per_fam) >= 2
    for item in per_fam:
        assert "family" in item
        assert "support" in item and item["support"] > 0
        assert "recall_pct" in item
        assert 0.0 <= item["recall_pct"] <= 100.0

    # Recent flows
    recent = status["recent_flows"]
    assert len(recent) > 0
    sample_flow = recent[-1]
    assert sample_flow["response_mode"] == "advisory"
    assert sample_flow["safety_status"] in ("PERMITTED", "OVERRIDDEN") or "OVERRIDDEN" in sample_flow["safety_status"]
    assert sample_flow["dqn_action"] in ("ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE")
    assert 0.0 <= sample_flow["rf_attack_probability"] <= 1.0
    assert sample_flow["rf_binary_prediction"] in ("BENIGN", "ATTACK")


def test_replay_lab_execution_dual_model_routing(replay_engine: ReplayLabEngine):
    """Verify both datasets are routed to their respective models when dataset='both'."""
    cfg = ReplayLabConfig(dataset="both", count=400, selection="mixed", speed="batch", seed=777)
    replay_engine.start(cfg)

    deadline = time.time() + 10.0
    status = replay_engine.get_status()
    while status["status"] == "RUNNING" and time.time() < deadline:
        time.sleep(0.05)
        status = replay_engine.get_status()

    assert status["status"] == "COMPLETED"
    assert status["processed_count"] == 400

    datasets_evaluated = {r.dataset for r in replay_engine._evaluated_records}
    assert "CIC-IDS2017" in datasets_evaluated
    assert "CSE-CIC-IDS2018" in datasets_evaluated


def test_replay_lab_controls_lifecycle(replay_engine: ReplayLabEngine):
    """Verify pause, resume, and stop controls."""
    cfg = ReplayLabConfig(dataset="cicids2017", count=1000, selection="mixed", speed="slow", seed=42)
    replay_engine.start(cfg)
    time.sleep(0.1)

    # Pause
    p_res = replay_engine.pause()
    assert p_res["status"] == "PAUSED"
    p_status = replay_engine.get_status()
    assert p_status["status"] == "PAUSED"
    p_count = p_status["processed_count"]

    # Sleep while paused: count should not increase
    time.sleep(0.2)
    assert replay_engine.get_status()["processed_count"] == p_count

    # Resume
    r_res = replay_engine.resume()
    assert r_res["status"] == "RUNNING"
    time.sleep(0.3)
    assert replay_engine.get_status()["processed_count"] > p_count

    # Stop
    s_res = replay_engine.stop()
    assert s_res["status"] == "STOPPED"
    assert replay_engine.get_status()["status"] == "STOPPED"


def test_replay_lab_treeshap_explanation(replay_engine: ReplayLabEngine):
    """Verify on-demand TreeSHAP explanation for a specific replayed flow."""
    cfg = ReplayLabConfig(dataset="cicids2017", count=50, selection="mixed", speed="batch", seed=42)
    replay_engine.start(cfg)

    deadline = time.time() + 5.0
    while replay_engine.get_status()["status"] == "RUNNING" and time.time() < deadline:
        time.sleep(0.05)

    assert replay_engine.get_status()["status"] == "COMPLETED"

    # Explain flow #1
    exp = replay_engine.explain_flow(1)
    assert exp["flow_id"] == 1
    assert "features" in exp
    assert len(exp["features"]) == 10
    assert "base_value" in exp
    assert "explainer_model" in exp
    assert "Random Forest" in exp["explainer_model"]
    assert "ground_truth_family" in exp
    assert "dqn_action" in exp
    assert "safety_status" in exp


def test_replay_lab_csv_export(replay_engine: ReplayLabEngine):
    """Verify full CSV export string contains all provenance and R10 feature columns."""
    cfg = ReplayLabConfig(dataset="cicids2017", count=50, selection="mixed", speed="batch", seed=42)
    replay_engine.start(cfg)

    deadline = time.time() + 5.0
    while replay_engine.get_status()["status"] == "RUNNING" and time.time() < deadline:
        time.sleep(0.05)

    csv_text = replay_engine.export_csv_string()
    reader = csv.DictReader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 50

    expected_cols = [
        "flow_id",
        "dataset",
        "source_file",
        "source_row_index",
        "original_label",
        "ground_truth_family",
        "binary_ground_truth",
        "is_attack",
        "rf_attack_probability",
        "rf_binary_prediction",
        "is_correct",
        "rule_triggered",
        "rule_matches",
        "detection_source",
        "dqn_action",
        "safety_status",
        "response_mode",
        *R10_FEATURES,
    ]
    for col in expected_cols:
        assert col in reader.fieldnames, f"Expected column {col} missing in CSV export"

    first_row = rows[0]
    assert first_row["dataset"] == "CIC-IDS2017"
    assert first_row["response_mode"] == "advisory"
    assert float(first_row["flow_duration_ms"]) >= 0.0


def test_replay_lab_10000_record_benchmark(replay_engine: ReplayLabEngine):
    """Full scale verification: 10,000 genuine flow records evaluated in batch mode."""
    cfg = ReplayLabConfig(dataset="both", count=10000, selection="mixed", speed="batch", seed=42)
    t0 = time.time()
    replay_engine.start(cfg)

    deadline = time.time() + 15.0
    status = replay_engine.get_status()
    while status["status"] == "RUNNING" and time.time() < deadline:
        time.sleep(0.1)
        status = replay_engine.get_status()

    elapsed = time.time() - t0
    assert status["status"] == "COMPLETED"
    assert status["processed_count"] == 10000
    assert status["selected_count"] == 10000

    # Performance constraint: > 1,000 flows/s in batch mode
    throughput = 10000.0 / elapsed
    assert throughput >= 1000.0, f"Expected >= 1,000 flows/s, achieved {throughput:.1f} flows/s"

    # Metric integrity
    metrics = status["metrics"]
    cm = metrics["confusion_matrix"]
    assert cm["tp"] + cm["fp"] + cm["tn"] + cm["fn"] == 10000
    assert 0.0 < metrics["accuracy"] <= 1.0
    assert 0.0 < metrics["f1"] <= 1.0


def test_replay_lab_http_endpoints():
    """Verify HTTP API endpoints for Replay Lab using localhost test server."""
    server = create_server(port=0)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{port}"

        # 1. GET /api/replay-lab/config
        with urllib.request.urlopen(f"{base_url}/api/replay-lab/config", timeout=5) as resp:
            assert resp.status == 200
            cfg_data = json.loads(resp.read().decode("utf-8"))
            assert "datasets" in cfg_data
            assert "record_counts" in cfg_data
            assert "families" in cfg_data

        # 2. POST /api/replay-lab/start
        start_payload = {
            "dataset": "cicids2017",
            "count": 100,
            "selection": "mixed",
            "speed": "batch",
            "seed": 42,
        }
        req = urllib.request.Request(
            f"{base_url}/api/replay-lab/start",
            data=json.dumps(start_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            start_res = json.loads(resp.read().decode("utf-8"))
            assert start_res["status"] == "RUNNING"
            assert start_res["selected_count"] == 100

        # Wait for completion
        time.sleep(0.5)

        # 3. GET /api/replay-lab/status
        with urllib.request.urlopen(f"{base_url}/api/replay-lab/status", timeout=5) as resp:
            assert resp.status == 200
            status_data = json.loads(resp.read().decode("utf-8"))
            assert status_data["status"] == "COMPLETED"
            assert status_data["processed_count"] == 100
            assert "metrics" in status_data
            assert "recent_flows" in status_data

        # 4. POST /api/replay-lab/explain
        explain_payload = {"flow_id": 1}
        req_exp = urllib.request.Request(
            f"{base_url}/api/replay-lab/explain",
            data=json.dumps(explain_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req_exp, timeout=10) as resp:
            assert resp.status == 200
            exp_data = json.loads(resp.read().decode("utf-8"))
            assert exp_data["flow_id"] == 1
            assert "features" in exp_data

        # 5. GET /api/replay-lab/export
        with urllib.request.urlopen(f"{base_url}/api/replay-lab/export", timeout=5) as resp:
            assert resp.status == 200
            assert resp.headers.get_content_type() == "text/csv"
            csv_content = resp.read().decode("utf-8")
            assert "flow_id,dataset,source_file" in csv_content
            lines = [line for line in csv_content.splitlines() if line.strip()]
            assert len(lines) == 101  # Header + 100 rows

    finally:
        server.shutdown()
        server.server_close()
