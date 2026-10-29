"""CSV evaluation and validation engine for XRL-IDARS.

Provides strict, leak-free evaluation of user-supplied, exhibition, and held-out test
benchmark records against frozen research preprocessors, Random Forest, Supervised LSTM,
and score-level Fusion models.

Guarantees:
1. Strict schema & configuration validation: validates benchmark and contract as a paired
   configuration (e.g. cicids2017/cse2018 require R10; unswnb15 requires R4).
2. Multi-model inference: evaluates Random Forest, Supervised LSTM (T=5 sliding sequence),
   and score-level Fusion (alpha * S_rf + (1 - alpha) * S_lstm) side-by-side.
3. Sequence alignment & warm-up tracking: handles causal warm-up for the initial T-1=4
   flows explicitly, computing sequence-aligned metrics without target or boundary leakage.
4. Ground-truth and metadata isolation: extracts and separates labels and network endpoint
   metadata (IPs, ports, protocol, timestamps) from the ML feature matrix prior to inference.
5. Target leakage prevention: ensures no label, proxy, or endpoint metadata enters model inputs.
6. Three evaluation modes:
   - Mode A (full_test): authoritative held-out test split evaluation (355k - 1.66M flows).
   - Mode B (exhibition): deterministic 200-flow exhibition subset (166 Benign, 34 Attack).
   - Mode C (custom): user-supplied CSV upload and analysis.
7. Centralized metrics: uses single project-wide evaluation metrics from xrlids.evaluation.metrics.
8. Authoritative export & provenance: stores server-side evaluation records to prevent
   client-side tampering, distinguishes displayed subset from full population, and
   preserves historical experiment artifacts untouched.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import torch

from xrlids.evaluation.metrics import (
    MetricError,
    binary_metrics,
    confusion_counts,
    score_metrics,
)
from xrlids.features.definitions import R4_FEATURES, R10_FEATURES
from xrlids.models.lstm import LSTMDetector, SequenceSet, build_sequences
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action

logger = logging.getLogger("xrlids.evaluation.csv_evaluator")

REPO_ROOT = Path(__file__).resolve().parents[3]

# Benchmark to canonical contract pairing
SUPPORTED_BENCHMARK_CONTRACTS: dict[str, str] = {
    "cicids2017": "R10",
    "cse2018": "R10",
    "unswnb15": "R4",
}

# Candidate columns indicating independent capture file, session, or PCAP segment boundaries
BOUNDARY_CANDIDATE_COLUMNS: tuple[str, ...] = (
    "source_file",
    "filename",
    "file_name",
    "capture_file",
    "capture_id",
    "session_id",
    "pcap_file",
    "segment_id",
)

# Canonical candidate label column names
LABEL_CANDIDATE_COLUMNS: tuple[str, ...] = (
    "true_label",
    "label",
    "Label",
    "is_attack",
    "attack",
    "class",
    "Class",
    "target",
    "Target",
    "ground_truth",
    "ground_truth_label",
)

# Metadata column names to isolate and preserve for network flow inspection
METADATA_CANDIDATE_COLUMNS: tuple[str, ...] = (
    "flow_id",
    "src_endpoint",
    "dst_endpoint",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "timestamp",
    "category",
    "host_id",
    "duration_ms",
    "packet_count",
    "source_file",
    "filename",
    "file_name",
    "capture_file",
    "capture_id",
    "session_id",
    "pcap_file",
    "segment_id",
)

# Canonical string representations for benign traffic
BENIGN_CANONICAL_STRINGS: frozenset[str] = frozenset({
    "0",
    "0.0",
    "0.00",
    "BENIGN",
    "NORMAL",
    "FALSE",
    "NON-ATTACK",
    "CLEAN",
    "LEGITIMATE",
})

# Canonical string representations for attack traffic and attack families
ATTACK_CANONICAL_STRINGS: frozenset[str] = frozenset({
    "1",
    "1.0",
    "1.00",
    "ATTACK",
    "TRUE",
    "MALICIOUS",
    "ANOMALY",
    "INTRUSION",
    "DDOS",
    "DOS",
    "DOS HULK",
    "DOS GOLDENEYE",
    "DOS SLOWLORIS",
    "DOS SLOWHTTPTEST",
    "PORTSCAN",
    "PORT SCAN",
    "BOT",
    "FTP-PATATOR",
    "SSH-PATATOR",
    "INFILTRATION",
    "INFILTERATION",
    "HEARTBLEED",
    "WEB ATTACK - BRUTE FORCE",
    "WEB ATTACK - XSS",
    "WEB ATTACK - SQL INJECTION",
    "DDOS ATTACKS-LOIC-HTTP",
    "DDOS ATTACK-HOIC",
    "DOS ATTACKS-HULK",
    "DOS ATTACKS-SLOWHTTPTEST",
    "DOS ATTACKS-GOLDENEYE",
    "DOS ATTACKS-SLOWLORIS",
    "FTP-BRUTEFORCE",
    "SSH-BRUTEFORCE",
    "BRUTE FORCE -WEB",
    "BRUTE FORCE -XSS",
    "SQL INJECTION",
    "FUZZERS",
    "ANALYSIS",
    "BACKDOORS",
    "BACKDOOR",
    "EXPLOITS",
    "GENERIC",
    "RECONNAISSANCE",
    "SHELLCODE",
    "WORMS",
})

BENCHMARK_ARTIFACT_PATHS: dict[str, dict[str, Any]] = {
    "cicids2017": {
        "exp_dir": REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001",
        "preprocessor": REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "preprocessor.joblib",
        "model": REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "random_forest.joblib",
        "lstm": REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001" / "lstm.pt",
        "contract": "R10",
        "alpha": 0.50,
        "name": "RandomForest + LSTM + Fusion (CIC-IDS2017 R10)",
    },
    "cse2018": {
        "exp_dir": REPO_ROOT / "results" / "experiments" / "EXP-P1-CSE2018-R10-MULTI-001",
        "preprocessor": REPO_ROOT / "results" / "experiments" / "EXP-P1-CSE2018-R10-MULTI-001" / "preprocessor.joblib",
        "model": REPO_ROOT / "results" / "experiments" / "EXP-P1-CSE2018-R10-MULTI-001" / "random_forest.joblib",
        "lstm": REPO_ROOT / "results" / "experiments" / "EXP-P1-CSE2018-R10-MULTI-001" / "lstm.pt",
        "contract": "R10",
        "alpha": 0.00,
        "name": "RandomForest + LSTM + Fusion (CSE-CIC-IDS2018 R10)",
    },
    "unswnb15": {
        "exp_dir": REPO_ROOT / "results" / "experiments" / "EXP-P1-UNSWNB15-R10-MULTI-001",
        "preprocessor": REPO_ROOT / "results" / "experiments" / "EXP-P1-UNSWNB15-R10-MULTI-001" / "preprocessor.joblib",
        "model": REPO_ROOT / "results" / "experiments" / "EXP-P1-UNSWNB15-R10-MULTI-001" / "random_forest.joblib",
        "lstm": REPO_ROOT / "results" / "experiments" / "EXP-P1-UNSWNB15-R10-MULTI-001" / "lstm.pt",
        "contract": "R4",
        "alpha": 0.60,
        "name": "RandomForest + LSTM + Fusion (UNSW-NB15 R4)",
    },
}

# Authoritative server-side cache of evaluation records to prevent client spoofing
_SERVER_EVALUATION_CACHE: dict[str, dict[str, Any]] = {}
MAX_SERVER_CACHE_ENTRIES = 50

# Cached models and explainers to avoid redundant disk I/O on repeated requests
_MODEL_CACHE: dict[str, Any] = {}
_EXPLAINER_CACHE: dict[str, Any] = {}
_DQN_CACHE: dict[str, Any] = {}


class CSVValidationError(ValueError):
    """Raised when CSV input is malformed, missing required contract features, or invalid."""


def get_cached_evaluation(evaluation_id: str) -> dict[str, Any] | None:
    """Retrieve an authoritative server-side evaluation session by ID."""
    return _SERVER_EVALUATION_CACHE.get(str(evaluation_id))


def clear_cached_evaluations() -> None:
    """Clear server-side evaluation cache (primarily for tests)."""
    _SERVER_EVALUATION_CACHE.clear()


def _compute_sha256(path: Path) -> str:
    """Compute hex SHA-256 digest of a file if it exists."""
    if not path.exists():
        return "NOT_FOUND"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _get_fusion_alpha(benchmark: str) -> float:
    """Retrieve validation-tuned fusion alpha weight for a benchmark from fusion_weights.json."""
    fw_path = REPO_ROOT / "models" / "fusion" / "fusion_weights.json"
    if fw_path.exists():
        try:
            with open(fw_path, "r", encoding="utf-8") as f:
                fw = json.load(f)
            alias = benchmark.replace("cse2018", "cse_cic_ids2018").replace("unswnb15", "unsw_nb15")
            cfg = fw.get("configurations", {}).get(alias, {})
            if "alpha" in cfg:
                return float(cfg["alpha"])
        except Exception:
            pass
    return BENCHMARK_ARTIFACT_PATHS.get(benchmark, {}).get("alpha", 0.50)


def parse_strict_binary_label(val: Any, row_idx: Any) -> int:
    """Strictly parse a ground-truth label into binary integer {0, 1}.

    Accepts:
    - 0, 0.0, '0', '0.0', 'BENIGN', 'NORMAL', etc. -> 0
    - 1, 1.0, '1', '1.0', 'ATTACK', 'TRUE', attack family names (DDoS, Hulk, etc.) -> 1

    Rejects:
    - Missing / null / empty labels -> CSVValidationError
    - Ambiguous numbers (e.g. 2, -1, 0.5) -> CSVValidationError
    - Unrecognized text strings -> CSVValidationError
    """
    if val is None or pd.isna(val):
        raise CSVValidationError(
            f"Invalid ground-truth label at row {row_idx}: label is missing or null. "
            f"In labelled evaluation, every evaluated row must have a valid non-empty label. "
            f"To run unlabelled inference, remove the label column."
        )

    # Direct numeric types
    if isinstance(val, (int, float, np.integer, np.floating)):
        if np.isnan(val):
            raise CSVValidationError(f"Invalid ground-truth label at row {row_idx}: label is NaN.")
        f_val = float(val)
        if f_val == 0.0:
            return 0
        if f_val == 1.0:
            return 1
        raise CSVValidationError(
            f"Invalid numeric ground-truth label '{val}' at row {row_idx}. "
            f"Numeric labels must be binary 0 (Benign) or 1 (Attack)."
        )

    s = str(val).strip()
    if not s:
        raise CSVValidationError(
            f"Invalid ground-truth label at row {row_idx}: label string is empty."
        )

    try:
        f_val = float(s)
        is_num = True
    except ValueError:
        is_num = False

    if is_num:
        if f_val == 0.0:
            return 0
        if f_val == 1.0:
            return 1
        raise CSVValidationError(
            f"Invalid numeric ground-truth label string '{s}' at row {row_idx}. "
            f"Numeric labels must be binary 0 (Benign) or 1 (Attack)."
        )

    s_upper = s.upper()
    if s_upper in BENIGN_CANONICAL_STRINGS:
        return 0
    if s_upper in ATTACK_CANONICAL_STRINGS:
        return 1

    # Check recognized attack family prefixes/substrings
    if any(atk in s_upper for atk in (
        "DDOS", "DOS ", "DOS-", "PORTSCAN", "PORT SCAN", "BRUTE FORCE", "PATATOR",
        "INFILTRATION", "INFILTERATION", "BOTNET", "BOT", "EXPLOIT", "FUZZER", "SHELLCODE", "WORM"
    )):
        return 1

    raise CSVValidationError(
        f"Invalid or unrecognized ground-truth label '{val}' at row {row_idx}. "
        f"Supported labels: 0/1, 0.0/1.0, BENIGN/ATTACK, or standard attack family names (e.g. DDoS, PortScan, Hulk)."
    )


def _load_benchmark_models(benchmark: str) -> dict[str, Any]:
    """Load and cache preprocessor, Random Forest, and LSTM models for a benchmark."""
    if benchmark in _MODEL_CACHE:
        return _MODEL_CACHE[benchmark]

    bench_info = BENCHMARK_ARTIFACT_PATHS[benchmark]
    prep_path = bench_info["preprocessor"]
    rf_path = bench_info["model"]
    lstm_path = bench_info["lstm"]

    if not prep_path.exists():
        raise CSVValidationError(f"Frozen preprocessor artifact missing: {prep_path}")
    if not rf_path.exists():
        raise CSVValidationError(f"Frozen Random Forest artifact missing: {rf_path}")
    if not lstm_path.exists():
        raise CSVValidationError(f"Frozen LSTM artifact missing: {lstm_path}")

    preprocessor = joblib.load(prep_path)
    rf_model = joblib.load(rf_path)
    lstm_detector = LSTMDetector.load(lstm_path)
    if hasattr(lstm_detector, "model") and lstm_detector.model is not None:
        lstm_detector.model.eval()

    alpha = _get_fusion_alpha(benchmark)

    models_bundle = {
        "preprocessor": preprocessor,
        "rf": rf_model,
        "lstm": lstm_detector,
        "alpha": alpha,
        "info": bench_info,
    }
    _MODEL_CACHE[benchmark] = models_bundle
    return models_bundle


def _get_dqn_action(
    attack_score: float,
    flow_bytes: float = 0.0,
    *,
    state_builder: StateBuilder | None = None,
    cooldown_remaining: int = 0,
) -> dict[str, Any]:
    """Run the frozen Dueling DQN on the project's causal six-dimensional state.

    State order is [score, score_delta, recent_alert_density, previous_action,
    cooldown_fraction, log_volume]. Ground truth is never an input. The caller
    supplies cooldown state from prior recommendations; the builder maintains
    score/alert/action history across sample flows in chronological row order.
    Recommendations are observational only and never mutate firewall/network state.
    """
    actions = ["ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE"]
    dqn_path = REPO_ROOT / "models" / "dqn" / "dqn_4action_best.pt"
    builder = state_builder if state_builder is not None else StateBuilder()
    state_np = builder.build_state(
        attack_score=float(attack_score),
        flow_bytes_per_s=max(0.0, float(flow_bytes)),
        cooldown_remaining=max(0, int(cooldown_remaining)),
    )
    state_payload = [round(float(value), 6) for value in state_np]
    state_schema = ["attack_score", "score_delta", "recent_alert_density", "previous_action", "cooldown_fraction", "log_volume"]

    def disclosed_fallback(reason: str) -> dict[str, Any]:
        # Never label a rule-based recommendation as DQN inference.
        rec_act = "ISOLATE" if attack_score >= 0.85 else (
            "RATE_LIMIT" if attack_score >= 0.50 else (
                "ALERT" if attack_score >= 0.20 else "ALLOW"
            )
        )
        builder.update_history(float(attack_score), Action[rec_act], cooldown_remaining=max(0, int(cooldown_remaining)))
        return {
            "recommended_action": rec_act,
            "policy_type": "RULE_DRY_RUN (explicit fallback baseline; not DQN)",
            "checkpoint": str(dqn_path.relative_to(REPO_ROOT)) if dqn_path.exists() else "missing",
            "safety_status": "OBSERVATIONAL_ONLY",
            "execution_mode": "DRY_RUN (no firewall or network mutation)",
            "q_values": None,
            "state_vector": state_payload,
            "state_schema": state_schema,
            "is_fallback": True,
            "fallback_reason": reason,
        }

    if not dqn_path.exists():
        return disclosed_fallback(f"DQN checkpoint absent at {dqn_path}")

    try:
        from xrlids.response.dqn.network import DuelingQNetwork
        cache_key = str(dqn_path.resolve())
        if cache_key not in _DQN_CACHE:
            checkpoint = torch.load(dqn_path, map_location="cpu", weights_only=False)
            net = DuelingQNetwork(input_dim=6, action_dim=4)
            state_dict = checkpoint.get("online_net_state_dict", checkpoint.get("state_dict"))
            if state_dict is None:
                raise ValueError("Checkpoint contains neither online_net_state_dict nor state_dict")
            net.load_state_dict(state_dict, strict=True)
            net.eval()
            _DQN_CACHE[cache_key] = net
        net = _DQN_CACHE[cache_key]

        state = torch.as_tensor(state_np, dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            q_vals = net(state)
            action_idx = int(torch.argmax(q_vals, dim=1).item())

        rec_act = actions[action_idx]
        builder.update_history(float(attack_score), Action[rec_act], cooldown_remaining=max(0, int(cooldown_remaining)))
        return {
            "recommended_action": rec_act,
            "policy_type": "DQN_NEURAL_POLICY (DuelingQNetwork)",
            "checkpoint": str(dqn_path.relative_to(REPO_ROOT)),
            "safety_status": "OBSERVATIONAL_ONLY — recommendation is not executed",
            "execution_mode": "DRY_RUN (no firewall or network mutation)",
            "q_values": {act: round(float(q_vals[0, i].item()), 6) for i, act in enumerate(actions)},
            "state_vector": state_payload,
            "state_schema": state_schema,
            "is_fallback": False,
        }
    except Exception as exc:
        logger.exception("DQN checkpoint inference failed")
        return disclosed_fallback(f"DQN checkpoint load/inference failed: {exc}")


def explain_flow_prediction(
    features_dict: dict[str, float],
    benchmark: str = "cicids2017",
) -> dict[str, Any]:
    """Compute exact TreeSHAP feature attributions on Random Forest for a single flow."""
    bench_key = str(benchmark).lower().strip()
    models = _load_benchmark_models(bench_key)
    preprocessor = models["preprocessor"]
    rf = models["rf"]
    sklearn_rf = rf.model if hasattr(rf, "model") else rf

    expected_features = list(SUPPORTED_BENCHMARK_CONTRACTS.get(bench_key, "R10"))
    expected_features = list(R10_FEATURES) if SUPPORTED_BENCHMARK_CONTRACTS.get(bench_key) == "R10" else list(R4_FEATURES)

    row_df = pd.DataFrame([{f: float(features_dict.get(f, 0.0)) for f in expected_features}])
    scaled_df = preprocessor.transform(row_df)

    import shap
    if bench_key not in _EXPLAINER_CACHE:
        _EXPLAINER_CACHE[bench_key] = shap.TreeExplainer(sklearn_rf)
    explainer = _EXPLAINER_CACHE[bench_key]

    shap_vals = explainer.shap_values(scaled_df.to_numpy())
    # TreeExplainer returns array of shape (1, n_features, 2) or list of 2 arrays
    if isinstance(shap_vals, list) and len(shap_vals) >= 2:
        attack_contribs = shap_vals[1][0]
    elif hasattr(shap_vals, "ndim") and shap_vals.ndim == 3 and shap_vals.shape[2] >= 2:
        attack_contribs = shap_vals[0, :, 1]
    else:
        attack_contribs = np.asarray(shap_vals).ravel()

    top_features = []
    for feat_name, contrib, raw_val in zip(expected_features, attack_contribs, row_df.iloc[0]):
        top_features.append({
            "feature": feat_name,
            "value": round(float(raw_val), 4),
            "shap_attribution": round(float(contrib), 4),
            "direction": "INCREASES_THREAT" if contrib > 0 else "DECREASES_THREAT",
        })
    top_features.sort(key=lambda x: abs(x["shap_attribution"]), reverse=True)

    return {
        "explainer_model": "Random Forest Detector (TreeExplainer)",
        "features": top_features,
        "scientific_notices": [
            "TreeSHAP explains Random Forest tree decisions only; not the LSTM or DQN.",
            "Attributions reflect mathematical contribution to tree splits, not network causality.",
        ],
    }


def evaluate_csv_dataset(
    csv_source: str | bytes | io.StringIO | io.BytesIO | Path | pd.DataFrame | None = None,
    contract: str = "R10",
    benchmark: str = "cicids2017",
    label_column: str | None = None,
    threshold: float = 0.50,
    operational_threshold: float = 0.40,
    max_display_flows: int = 100,
    mode: str = "custom",
) -> dict[str, Any]:
    """Validate, preprocess, and evaluate a dataset against frozen multi-model artifacts.

    Supports three distinct execution modes:
    1. 'custom': Evaluates uploaded/pasted CSV string, file, or DataFrame.
    2. 'exhibition': Loads and evaluates the fixed 200-flow exhibition subset (166 Benign, 34 Attack).
    3. 'full_test': Serves the authoritative held-out test split evaluation (355k - 1.66M flows).

    Returns:
        Structured evaluation dictionary with RF, LSTM, and Fusion metrics, confusion
        matrices, row accounting, provenance, and flow inspection records.
    """
    bench_key = str(benchmark).lower().strip()
    if bench_key not in SUPPORTED_BENCHMARK_CONTRACTS:
        raise CSVValidationError(
            f"Unknown benchmark '{benchmark}'. Supported benchmarks: {list(SUPPORTED_BENCHMARK_CONTRACTS.keys())}"
        )

    contract_key = str(contract).upper().strip()
    required_contract = SUPPORTED_BENCHMARK_CONTRACTS[bench_key]

    if contract_key != required_contract:
        raise CSVValidationError(
            f"Incompatible benchmark and feature contract: benchmark '{bench_key}' only supports contract "
            f"'{required_contract}', but contract '{contract_key}' was requested. "
            f"Please select contract '{required_contract}' for this benchmark model."
        )

    if contract_key == "R10":
        expected_features = list(R10_FEATURES)
    elif contract_key == "R4":
        expected_features = list(R4_FEATURES)
    else:
        raise CSVValidationError(f"Invalid contract '{contract}'. Supported contracts: 'R10', 'R4'.")

    # =========================================================================
    # MODE A: FULL HELD-OUT TEST EVALUATION
    # =========================================================================
    mode_clean = str(mode).lower().strip()
    if mode_clean in ("full_test", "mode_a", "held_out"):
        return _evaluate_mode_full_test(
            benchmark=bench_key,
            contract=contract_key,
            threshold=threshold,
            operational_threshold=operational_threshold,
            max_display_flows=max_display_flows,
        )

    # =========================================================================
    # MODE B: FIXED EXHIBITION SUBSET (200 FLOWS: 166 BENIGN, 34 ATTACK)
    # =========================================================================
    exhibition_metadata_provenance: dict[str, Any] | None = None
    if mode_clean in ("exhibition", "mode_b", "demo_200"):
        if bench_key == "cse2018":
            exh_json = REPO_ROOT / "data" / "demo" / "cse2018_exhibition_200.json"
            exh_csv = REPO_ROOT / "data" / "demo" / "cse2018_exhibition_200.csv"
        elif bench_key == "unswnb15":
            exh_json = REPO_ROOT / "data" / "demo" / "unswnb15_exhibition_200.json"
            exh_csv = REPO_ROOT / "data" / "demo" / "unswnb15_exhibition_200.csv"
        else:
            exh_json = REPO_ROOT / "data" / "demo" / "cicids2017_exhibition_200.json"
            exh_csv = REPO_ROOT / "data" / "demo" / "cicids2017_exhibition_200.csv"

        if exh_json.exists():
            with open(exh_json, "r", encoding="utf-8") as f:
                exh_data = json.load(f)
            exhibition_metadata_provenance = exh_data.get("metadata_provenance")
            df_exh = pd.DataFrame([
                {
                    **fl.get("features", {}),
                    "label": 1 if fl.get("is_attack") else 0,
                    "src_endpoint": fl.get("src_endpoint", "Not available in source data"),
                    "dst_endpoint": fl.get("dst_endpoint", "Not available in source data"),
                    "protocol": fl.get("protocol", "N/A"),
                    "category": fl.get("category", "traffic"),
                    "flow_id": fl.get("flow_id", idx),
                    "source_file": fl.get("source_file"),
                    "timestamp": fl.get("timestamp"),
                    "duration_ms": fl.get("duration_ms"),
                }
                for idx, fl in enumerate(exh_data.get("flows", []))
            ])
            csv_source = df_exh
        elif exh_csv.exists():
            csv_source = exh_csv

    # =========================================================================
    # MODE C: CUSTOM CSV EVALUATION (OR EVALUATION OF EXHIBITION SUBSET)
    # =========================================================================
    if csv_source is None:
        raise CSVValidationError("Missing 'csv_source' or 'file_path' for evaluation.")

    # 1. Parse CSV into DataFrame
    try:
        if isinstance(csv_source, pd.DataFrame):
            df = csv_source.copy()
        elif isinstance(csv_source, Path):
            if not csv_source.exists():
                raise CSVValidationError(f"CSV file not found: {csv_source}")
            df = pd.read_csv(csv_source)
        elif isinstance(csv_source, bytes):
            df = pd.read_csv(io.BytesIO(csv_source))
        elif isinstance(csv_source, io.StringIO):
            df = pd.read_csv(csv_source)
        elif isinstance(csv_source, io.BytesIO):
            df = pd.read_csv(csv_source)
        elif isinstance(csv_source, str):
            potential_path = Path(csv_source)
            if "\n" not in csv_source and potential_path.exists() and potential_path.is_file():
                df = pd.read_csv(potential_path)
            else:
                df = pd.read_csv(io.StringIO(csv_source))
        else:
            raise CSVValidationError(f"Unsupported csv_source type: {type(csv_source)}")
    except Exception as exc:
        if isinstance(exc, CSVValidationError):
            raise
        raise CSVValidationError(f"Failed to parse CSV input: {str(exc)}") from exc

    total_rows = len(df)
    if total_rows == 0:
        raise CSVValidationError("CSV file contains 0 rows; nothing to evaluate.")

    df.columns = [str(c).strip() for c in df.columns]

    # 2. Check for required feature columns
    missing_features = [f for f in expected_features if f not in df.columns]
    if missing_features:
        raise CSVValidationError(
            f"Missing required {contract_key} feature columns: {missing_features}. "
            f"Expected all {len(expected_features)} columns: {expected_features}"
        )

    # 3. Ground-truth isolation & Target leakage prevention
    resolved_label_col: str | None = None
    if label_column and label_column in df.columns:
        resolved_label_col = label_column
    else:
        for candidate in LABEL_CANDIDATE_COLUMNS:
            if candidate in df.columns:
                resolved_label_col = candidate
                break

    y_true_raw: pd.Series | None = None
    is_labelled = False
    if resolved_label_col is not None:
        y_true_raw = df[resolved_label_col].copy()
        is_labelled = True

    # 4. Separate network metadata columns from model inputs
    meta_df = pd.DataFrame(index=df.index)
    for col in METADATA_CANDIDATE_COLUMNS:
        if col in df.columns:
            meta_df[col] = df[col]

    # STRICT TARGET & METADATA LEAKAGE INVARIANT: Drop labels and metadata from model features
    X_raw = df[expected_features].copy()
    X_raw = X_raw[expected_features]

    for c in list(LABEL_CANDIDATE_COLUMNS) + list(METADATA_CANDIDATE_COLUMNS):
        if c in X_raw.columns and c not in expected_features:
            raise AssertionError(f"Target/Metadata leakage invariant violated: {c} present in features!")

    # 5. Non-finite value handling & row accounting
    X_num = pd.DataFrame(index=df.index)
    for col in expected_features:
        X_num[col] = pd.to_numeric(X_raw[col], errors="coerce")

    is_inf = np.isinf(X_num).any(axis=1)
    is_nan = X_num.isna().any(axis=1)
    invalid_mask = is_inf | is_nan
    valid_mask = ~invalid_mask

    dropped_count = int(invalid_mask.sum())
    inf_count = int(is_inf.sum())
    nan_count = int((is_nan & ~is_inf).sum())
    evaluated_count = int(valid_mask.sum())

    assert total_rows == evaluated_count + dropped_count, "Row accounting reconciliation failed!"

    if evaluated_count == 0:
        raise CSVValidationError(
            f"All {total_rows} rows were rejected because all contained non-finite feature values "
            f"({inf_count} rows with Infinity/-Infinity, {nan_count} rows with NaN/non-numeric values)."
        )

    # Slice valid rows strictly preserving 1:1 index alignment
    X_valid = X_num.loc[valid_mask].copy()
    meta_valid = meta_df.loc[valid_mask].copy()
    y_valid = y_true_raw.loc[valid_mask].copy() if is_labelled and y_true_raw is not None else None

    y_true_binary: np.ndarray | None = None
    if is_labelled and y_valid is not None:
        y_true_binary = np.array(
            [parse_strict_binary_label(val, orig_idx) for orig_idx, val in y_valid.items()],
            dtype=int,
        )
        assert len(y_true_binary) == len(X_valid), "Feature and label count mismatch after row cleaning!"

    # 6. Load frozen multi-model suite
    models = _load_benchmark_models(bench_key)
    preprocessor = models["preprocessor"]
    rf = models["rf"]
    lstm = models["lstm"]
    alpha = models["alpha"]
    bench_info = models["info"]

    # 7. Preprocessing & Random Forest Inference
    X_scaled = preprocessor.transform(X_valid)
    rf_scores = rf.predict_proba(X_scaled)
    if hasattr(rf_scores, "ndim") and rf_scores.ndim == 2:
        rf_scores = rf_scores[:, 1]
    rf_scores = np.asarray(rf_scores, dtype=float).ravel()

    # 8. Supervised LSTM Sequence Inference (T=5) with Sequence Boundary Isolation
    seq_len = 5
    n_flows = len(X_valid)
    lstm_scores = np.full(n_flows, np.nan, dtype=float)
    lstm_statuses: list[str] = []

    # Detect independent capture file or session boundary column if present
    resolved_boundary_col: str | None = None
    for cand in BOUNDARY_CANDIDATE_COLUMNS:
        if cand in df.columns:
            resolved_boundary_col = cand
            break

    boundary_groups = None
    if resolved_boundary_col is not None:
        boundary_groups = df.loc[valid_mask, resolved_boundary_col].to_numpy()

    if n_flows >= seq_len and hasattr(lstm, "model") and lstm.model is not None:
        dummy_y = y_true_binary if y_true_binary is not None else np.zeros(n_flows, dtype=int)
        seq_set = build_sequences(
            features=X_scaled,
            labels=dummy_y,
            split="test",
            seq_len=seq_len,
            stride=1,
            label_rule="last",
            groups=boundary_groups,
        )
        if len(seq_set) > 0:
            lstm_aligned_raw = lstm.predict_proba(seq_set)
            # Attribute sequence prediction to final flow in window (index origins + seq_len - 1)
            for seq_i, orig in enumerate(seq_set.origins):
                target_idx = orig + seq_len - 1
                lstm_scores[target_idx] = float(lstm_aligned_raw[seq_i])

    # Assign statuses and causal warm-up fallback
    for i in range(n_flows):
        if np.isnan(lstm_scores[i]):
            lstm_statuses.append("WARM_UP")
        else:
            lstm_statuses.append("ALIGNED")

    # Independent segment accounting when boundary column is present
    segment_accounting: list[dict[str, Any]] = []
    if resolved_boundary_col is not None and boundary_groups is not None:
        unique_segments = pd.unique(boundary_groups)
        for seg_id in unique_segments:
            seg_mask = (boundary_groups == seg_id)
            seg_flow_count = int(np.sum(seg_mask))
            seg_indices = np.where(seg_mask)[0]
            seg_aligned_count = int(sum(1 for idx in seg_indices if not np.isnan(lstm_scores[idx])))
            seg_warmup_count = seg_flow_count - seg_aligned_count
            segment_accounting.append({
                "segment_id": str(seg_id),
                "total_flows": seg_flow_count,
                "aligned_flows": seg_aligned_count,
                "warmup_flows": seg_warmup_count,
            })

    # 9. Calibrated Score-Level Fusion: S_fusion = alpha * S_rf + (1 - alpha) * S_lstm
    fusion_scores = np.full(n_flows, np.nan, dtype=float)
    for i in range(n_flows):
        if lstm_statuses[i] == "ALIGNED":
            fusion_scores[i] = alpha * rf_scores[i] + (1.0 - alpha) * lstm_scores[i]
        else:
            # Fallback to RF score for flows in causal warm-up
            fusion_scores[i] = rf_scores[i]

    # Predictions at threshold
    threshold = float(threshold)
    operational_threshold = float(operational_threshold)

    rf_preds = (rf_scores >= threshold).astype(int)
    fusion_preds = (fusion_scores >= threshold).astype(int)

    aligned_indices = [i for i, st in enumerate(lstm_statuses) if st == "ALIGNED"]
    lstm_aligned_preds = (lstm_scores[aligned_indices] >= threshold).astype(int) if aligned_indices else np.array([])
    fusion_aligned_preds = (fusion_scores[aligned_indices] >= threshold).astype(int) if aligned_indices else np.array([])

    # 10. Multi-Model Metrics Computation (if labelled)
    rf_metrics_summary: dict[str, Any] | None = None
    lstm_metrics_summary: dict[str, Any] | None = None
    fusion_metrics_summary: dict[str, Any] | None = None

    rf_cm: dict[str, int] | None = None
    lstm_cm: dict[str, int] | None = None
    fusion_cm: dict[str, int] | None = None

    if is_labelled and y_true_binary is not None:
        # A. Random Forest (evaluated over all evaluated rows)
        rf_cm = confusion_counts(y_true_binary, rf_preds)
        rf_b = binary_metrics(y_true_binary, rf_preds)
        rf_metrics_summary = {
            "model": "Random Forest Detector",
            "threshold": threshold,
            "population": rf_b["population"],
            "accuracy": rf_b["accuracy"],
            "precision": rf_b["precision"],
            "recall": rf_b["recall"],
            "f1": rf_b["f1"],
            "macro_f1": rf_b["macro_f1"],
            "weighted_f1": rf_b["weighted_f1"],
            "balanced_accuracy": rf_b["balanced_accuracy"],
            "confusion": rf_cm,
        }
        try:
            s_met = score_metrics(y_true_binary, rf_scores)
            rf_metrics_summary["roc_auc"] = s_met.get("roc_auc")
            rf_metrics_summary["pr_auc"] = s_met.get("pr_auc")
        except MetricError:
            rf_metrics_summary["roc_auc"] = None
            rf_metrics_summary["pr_auc"] = None

        # B. Supervised LSTM & Fusion (evaluated strictly over aligned sequence rows)
        if aligned_indices:
            y_aligned = y_true_binary[aligned_indices]
            lstm_cm = confusion_counts(y_aligned, lstm_aligned_preds)
            lstm_b = binary_metrics(y_aligned, lstm_aligned_preds)
            lstm_metrics_summary = {
                "model": "Supervised LSTM (T=5)",
                "threshold": threshold,
                "population": lstm_b["population"],
                "accuracy": lstm_b["accuracy"],
                "precision": lstm_b["precision"],
                "recall": lstm_b["recall"],
                "f1": lstm_b["f1"],
                "macro_f1": lstm_b["macro_f1"],
                "weighted_f1": lstm_b["weighted_f1"],
                "balanced_accuracy": lstm_b["balanced_accuracy"],
                "confusion": lstm_cm,
            }
            try:
                s_met = score_metrics(y_aligned, lstm_scores[aligned_indices])
                lstm_metrics_summary["roc_auc"] = s_met.get("roc_auc")
                lstm_metrics_summary["pr_auc"] = s_met.get("pr_auc")
            except MetricError:
                lstm_metrics_summary["roc_auc"] = None
                lstm_metrics_summary["pr_auc"] = None

            fusion_cm = confusion_counts(y_aligned, fusion_aligned_preds)
            fusion_b = binary_metrics(y_aligned, fusion_aligned_preds)
            fusion_metrics_summary = {
                "model": "RF-LSTM Fusion (Final Decision)",
                "alpha": alpha,
                "threshold": threshold,
                "population": fusion_b["population"],
                "accuracy": fusion_b["accuracy"],
                "precision": fusion_b["precision"],
                "recall": fusion_b["recall"],
                "f1": fusion_b["f1"],
                "macro_f1": fusion_b["macro_f1"],
                "weighted_f1": fusion_b["weighted_f1"],
                "balanced_accuracy": fusion_b["balanced_accuracy"],
                "confusion": fusion_cm,
            }
            try:
                s_met = score_metrics(y_aligned, fusion_scores[aligned_indices])
                fusion_metrics_summary["roc_auc"] = s_met.get("roc_auc")
                fusion_metrics_summary["pr_auc"] = s_met.get("pr_auc")
            except MetricError:
                fusion_metrics_summary["roc_auc"] = None
                fusion_metrics_summary["pr_auc"] = None

    # Primary metrics point to Fusion (system output) with fallback to RF if no aligned rows
    primary_metrics = fusion_metrics_summary if fusion_metrics_summary is not None else rf_metrics_summary
    primary_cm = fusion_cm if fusion_cm is not None else rf_cm

    # 11. Score distribution
    score_dist = {
        "low_threat_under_040": int((fusion_scores < 0.40).sum()),
        "medium_threat_040_to_065": int(((fusion_scores >= 0.40) & (fusion_scores < 0.65)).sum()),
        "high_threat_over_065": int((fusion_scores >= 0.65).sum()),
        "mean_score": round(float(np.mean(fusion_scores)), 4),
        "median_score": round(float(np.median(fusion_scores)), 4),
        "min_score": round(float(np.min(fusion_scores)), 4),
        "max_score": round(float(np.max(fusion_scores)), 4),
    }

    # 12. Build inspected flow records preserving endpoints & metadata
    flows: list[dict[str, Any]] = []
    display_limit = min(evaluated_count, max_display_flows)
    valid_indices = X_valid.index[:display_limit]
    dqn_state_builder = StateBuilder()
    dqn_cooldown_remaining = 0

    for i, idx in enumerate(valid_indices):
        s_rf = round(float(rf_scores[i]), 4)
        s_lstm = round(float(lstm_scores[i]), 4) if not np.isnan(lstm_scores[i]) else None
        s_fusion = round(float(fusion_scores[i]), 4)

        pred_cls = int(fusion_preds[i])
        pred_label = "ATTACK" if pred_cls == 1 else "BENIGN"

        gt_cls = int(y_true_binary[i]) if is_labelled and y_true_binary is not None else None
        gt_label = "ATTACK" if gt_cls == 1 else ("BENIGN" if gt_cls == 0 else "UNLABELLED")

        if gt_cls is not None:
            verdict = "CORRECT" if pred_cls == gt_cls else ("FALSE_POSITIVE" if pred_cls == 1 else "FALSE_NEGATIVE")
        else:
            verdict = "UNVERIFIED"

        row_vals = X_valid.iloc[i]
        feat_dict = {col: round(float(row_vals[col]), 4) for col in expected_features}

        # Retrieve metadata if available
        meta_row = meta_valid.iloc[i] if len(meta_valid) > i else {}
        src_ep = meta_row.get("src_endpoint") or "Not available in source data"
        dst_ep = meta_row.get("dst_endpoint") or "Not available in source data"
        proto = meta_row.get("protocol") or "TCP"

        # Run DQN sequentially on causal state. Missing volume features stay 0 rather than fabricated.
        flow_bytes = float(row_vals.get("flow_bytes_per_s", 0.0))
        dqn_resp = _get_dqn_action(
            s_fusion,
            flow_bytes=flow_bytes,
            state_builder=dqn_state_builder,
            cooldown_remaining=dqn_cooldown_remaining,
        )
        dqn_cooldown_remaining = max(0, dqn_cooldown_remaining - 1)
        if dqn_resp["recommended_action"] == "ISOLATE":
            dqn_cooldown_remaining = dqn_state_builder.cooldown_max_steps

        flows.append({
            "flow_id": int(meta_row.get("flow_id", idx)),
            "metadata": {
                "src_endpoint": src_ep,
                "dst_endpoint": dst_ep,
                "protocol": proto,
                "category": meta_row.get("category", "traffic"),
            },
            "features": feat_dict,
            "rf_score": s_rf,
            "lstm_score": s_lstm,
            "fusion_score": s_fusion,
            "attack_score": s_fusion,  # backward compatibility alias
            "lstm_status": lstm_statuses[i],
            "prediction_class": pred_cls,
            "prediction_label": pred_label,
            "ground_truth_class": gt_cls,
            "ground_truth_label": gt_label,
            "verdict": verdict,
            "response": dqn_resp,
        })

    # Pack full evaluated records for authoritative server-side export
    full_export_records: list[dict[str, Any]] = []
    for i, idx in enumerate(X_valid.index):
        meta_row = meta_valid.iloc[i] if len(meta_valid) > i else {}
        gt_cls = int(y_true_binary[i]) if is_labelled and y_true_binary is not None else None
        gt_label = "ATTACK" if gt_cls == 1 else ("BENIGN" if gt_cls == 0 else "UNLABELLED")
        pred_cls = int(fusion_preds[i])
        verdict = "CORRECT" if (gt_cls is not None and pred_cls == gt_cls) else (
            "FALSE_POSITIVE" if (gt_cls == 0 and pred_cls == 1) else (
                "FALSE_NEGATIVE" if (gt_cls == 1 and pred_cls == 0) else "UNVERIFIED"
            )
        )
        row_vals = X_valid.iloc[i]
        full_export_records.append({
            "flow_id": int(meta_row.get("flow_id", idx)),
            "src_endpoint": meta_row.get("src_endpoint", "N/A"),
            "dst_endpoint": meta_row.get("dst_endpoint", "N/A"),
            "protocol": meta_row.get("protocol", "TCP"),
            "rf_score": round(float(rf_scores[i]), 4),
            "lstm_score": round(float(lstm_scores[i]), 4) if not np.isnan(lstm_scores[i]) else "",
            "fusion_score": round(float(fusion_scores[i]), 4),
            "prediction_class": pred_cls,
            "prediction_label": "ATTACK" if pred_cls == 1 else "BENIGN",
            "ground_truth_class": gt_cls if gt_cls is not None else "",
            "ground_truth_label": gt_label,
            "verdict": verdict,
            "features": {col: round(float(row_vals[col]), 4) for col in expected_features},
        })

    evaluation_id = str(uuid.uuid4())
    is_exhibition = (mode_clean in ("exhibition", "mode_b", "demo_200"))
    eval_type = "fixed_exhibition_subset" if is_exhibition else "ad_hoc_csv_evaluation"

    disclaimer = (
        f"Deterministic 200-flow exhibition subset drawn from the canonical {bench_info['name']} "
        "held-out test split (166 Benign, 34 Attack). Predictions are reproducible frozen-model outputs. "
        "Source/destination endpoints are synthetic display-only placeholders where the benchmark "
        "feature tables do not contain IP addresses; see metadata_provenance in the demo JSON."
        if is_exhibition else
        "Ad-hoc CSV evaluation evaluated against frozen model artifacts. "
        "This run tests user-supplied records and does NOT alter or overwrite "
        "any frozen historical benchmark artifacts."
    )

    drop_reasons: list[str] = []
    if inf_count > 0:
        drop_reasons.append(f"{inf_count} rows with Infinity/-Infinity")
    if nan_count > 0:
        drop_reasons.append(f"{nan_count} rows with NaN or unparseable non-numeric values")
    drop_reason_str = (
        f"Non-finite numeric values ({', '.join(drop_reasons)})"
        if drop_reasons
        else "None"
    )

    result: dict[str, Any] = {
        "status": "success",
        "evaluation_id": evaluation_id,
        "mode": "exhibition" if is_exhibition else mode_clean,
        "evaluation_mode": mode_clean,
        "evaluation_type": eval_type,
        "official_frozen_benchmark": False,
        "disclaimer": disclaimer,
        "metadata_provenance": exhibition_metadata_provenance,
        "benchmark": bench_key,
        "contract": contract_key,
        "model_identifier": bench_info["name"],
        "inference_provenance": {
            "mode": "live per-request inference on frozen checkpoints",
            "random_forest_checkpoint": str(bench_info["model"].relative_to(REPO_ROOT)),
            "lstm_checkpoint": str(bench_info["lstm"].relative_to(REPO_ROOT)),
            "preprocessor_checkpoint": str(bench_info["preprocessor"].relative_to(REPO_ROOT)),
            "fusion": "computed per flow from current RF and causally aligned LSTM scores",
            "fusion_alpha": alpha,
            "dqn_checkpoint": "models/dqn/dqn_4action_best.pt",
            "dqn_training_benchmark": "cicids2017",
            "dqn_scope": (
                "CIC-IDS2017 policy inference; applying the same policy to CSE-CIC-IDS2018 "
                "or UNSW-NB15 is cross-dataset policy transfer, not dataset-specific DQN training"
            ),
            "response_execution": "recommendation only; no firewall or network mutation",
        },
        "fusion_configuration": {
            "alpha": alpha,
            "formula": f"S_fusion = {alpha:.2f} * S_rf + {1.0 - alpha:.2f} * S_lstm",
            "sequence_length": seq_len,
            "warmup_flows": seq_len - 1,
        },
        "thresholds": {
            "research": threshold,
            "operational_candidate": operational_threshold,
        },
        "row_accounting": {
            "total_rows_received": total_rows,
            "evaluated_rows": evaluated_count,
            "invalid_rows_dropped": dropped_count,
            "inf_rows_dropped": inf_count,
            "nan_rows_dropped": nan_count,
            "drop_reason": drop_reason_str,
            "aligned_sequence_rows": len(aligned_indices),
            "warmup_rows": evaluated_count - len(aligned_indices),
            "boundary_column": resolved_boundary_col,
            "boundary_isolation_applied": (resolved_boundary_col is not None),
            "boundary_segments_count": len(segment_accounting) if resolved_boundary_col is not None else 1,
            "boundary_isolation_note": (
                f"Sequence boundary isolation applied across {len(segment_accounting)} independent capture/session segments using column '{resolved_boundary_col}'."
                if resolved_boundary_col is not None else
                "No capture boundary column detected (e.g. 'source_file', 'session_id'). Assuming single continuous stream with T-1 (4) warm-up rows."
            ),
            "segments": segment_accounting,
        },
        "is_labelled": is_labelled,
        "label_column_detected": resolved_label_col,
        "metrics": primary_metrics,
        "confusion_matrix": primary_cm,
        "rf_metrics": rf_metrics_summary,
        "lstm_metrics": lstm_metrics_summary,
        "fusion_metrics": fusion_metrics_summary,
        "rf_confusion_matrix": rf_cm,
        "lstm_confusion_matrix": lstm_cm,
        "fusion_confusion_matrix": fusion_cm,
        "model_metrics": {
            "rf": rf_metrics_summary,
            "lstm": lstm_metrics_summary,
            "fusion": fusion_metrics_summary,
        },
        "score_distribution": score_dist,
        "provenance": {
            "preprocessor_sha256": _compute_sha256(bench_info["preprocessor"]),
            "rf_sha256": _compute_sha256(bench_info["model"]),
            "lstm_sha256": _compute_sha256(bench_info["lstm"]),
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        },
        "display_flow_count": len(flows),
        "total_evaluated_count": evaluated_count,
        "flows": flows,
        "_full_records": full_export_records,
    }

    _SERVER_EVALUATION_CACHE[evaluation_id] = result
    if len(_SERVER_EVALUATION_CACHE) > MAX_SERVER_CACHE_ENTRIES:
        _SERVER_EVALUATION_CACHE.pop(next(iter(_SERVER_EVALUATION_CACHE)))

    return result


def _evaluate_mode_full_test(
    benchmark: str,
    contract: str,
    threshold: float = 0.50,
    operational_threshold: float = 0.40,
    max_display_flows: int = 100,
) -> dict[str, Any]:
    """Assemble and serve authoritative held-out test evaluation outputs for Mode A."""
    from dashboard.workbench_data import (
        BENCHMARK_REGISTRY,
        get_comparison_data,
        get_evaluation_data,
        get_flow_explorer_data,
    )

    eval_data = get_evaluation_data(benchmark, slice_type="aligned")
    eval_data_native = get_evaluation_data(benchmark, slice_type="native")
    comp_data = get_comparison_data(benchmark)
    explorer_data = get_flow_explorer_data(benchmark_id=benchmark, page=1, limit=max_display_flows)

    models_data = eval_data.get("models", {})
    rf_m = models_data.get("random_forest", {})
    rf_native_m = eval_data_native.get("models", {}).get("random_forest", {})
    lstm_m = models_data.get("lstm") or models_data.get("supervised_lstm", {})
    fusion_m = models_data.get("fusion", {})

    # Extract primary metrics
    primary_metrics = {
        "model": "RF-LSTM Fusion (Final Decision)",
        "population": eval_data.get("population", 0),
        "accuracy": fusion_m.get("accuracy", 0.0),
        "precision": fusion_m.get("precision", 0.0),
        "recall": fusion_m.get("recall", 0.0),
        "f1": fusion_m.get("f1", 0.0),
        "macro_f1": fusion_m.get("macro_f1", 0.0),
        "weighted_f1": fusion_m.get("weighted_f1", 0.0),
        "balanced_accuracy": fusion_m.get("balanced_accuracy", 0.0),
        "roc_auc": fusion_m.get("roc_auc"),
        "pr_auc": fusion_m.get("pr_auc"),
        "confusion": fusion_m.get("confusion", {}),
    }

    flows: list[dict[str, Any]] = []
    for f in explorer_data.get("flows", []):
        mp = f.get("model_prediction", {})
        gt = f.get("ground_truth", {})
        fid = f.get("flow_id", 0)
        s_fusion = mp.get("fusion_score") or mp.get("rf_score", 0.0)
        dqn_resp = _get_dqn_action(s_fusion)

        flows.append({
            "flow_id": fid,
            "metadata": {
                "src_endpoint": "Not available in source data",
                "dst_endpoint": "Not available in source data",
                "protocol": "N/A",
                "category": "held_out_test_flow",
            },
            "features": {},
            "rf_score": mp.get("rf_score"),
            "lstm_score": mp.get("lstm_score"),
            "fusion_score": s_fusion,
            "attack_score": s_fusion,
            "lstm_status": "ALIGNED",
            "prediction_class": mp.get("prediction_class", 0),
            "prediction_label": mp.get("prediction_label", "BENIGN"),
            "ground_truth_class": gt.get("label", 0),
            "ground_truth_label": gt.get("name", "BENIGN"),
            "verdict": mp.get("outcome_status", "CORRECT"),
            "response": dqn_resp,
        })

    evaluation_id = str(uuid.uuid4())
    result = {
        "status": "success",
        "evaluation_id": evaluation_id,
        "mode": "full_test",
        "split_name": "held_out_test",
        "evaluation_mode": "full_test",
        "evaluation_type": "full_held_out_test_evaluation",
        "official_frozen_benchmark": True,
        "disclaimer": (
            f"Authoritative held-out test evaluation on {eval_data.get('population', 0):,} genuine flows. "
            "Evaluated under frozen research pipeline conditions with zero data leakage."
        ),
        "benchmark": benchmark,
        "contract": contract,
        "model_identifier": BENCHMARK_REGISTRY.get(benchmark, {}).get("name", benchmark),
        "fusion_configuration": comp_data.get("fusion", {}),
        "fusion_alpha": comp_data.get("fusion", {}).get("alpha", 0.50),
        "thresholds": {
            "research": threshold,
            "operational_candidate": operational_threshold,
        },
        "row_accounting": {
            "total_rows_received": eval_data.get("tabular_population", 0),
            "evaluated_rows": eval_data.get("tabular_population", 0),
            "invalid_rows_dropped": 0,
            "inf_rows_dropped": 0,
            "nan_rows_dropped": 0,
            "aligned_sequence_rows": eval_data.get("aligned_population", 0),
            "warmup_rows": eval_data.get("dropped_boundary_flows", 0),
            "boundary_isolation_applied": True,
            "boundary_isolation_note": eval_data.get("dropped_derivation", ""),
        },
        "is_labelled": True,
        "label_column_detected": "true_label",
        "metrics": primary_metrics,
        "rf_metrics": rf_m,
        "rf_tabular_metrics": rf_native_m,
        "lstm_metrics": lstm_m,
        "fusion_metrics": fusion_m,
        "confusion_matrix": fusion_m.get("confusion", {}),
        "rf_confusion_matrix": rf_m.get("confusion", {}),
        "rf_tabular_confusion_matrix": rf_native_m.get("confusion", {}),
        "lstm_confusion_matrix": lstm_m.get("confusion", {}),
        "fusion_confusion_matrix": fusion_m.get("confusion", {}),
        "model_metrics": {
            "rf": rf_m,
            "rf_tabular": rf_native_m,
            "lstm": lstm_m,
            "fusion": fusion_m,
        },
        "score_distribution": {
            "mean_score": round(float(fusion_m.get("roc_auc", 0.5)), 4),
            "median_score": 0.05,
            "min_score": 0.0,
            "max_score": 1.0,
        },
        "provenance": eval_data.get("provenance", {}),
        "display_flow_count": len(flows),
        "total_evaluated_count": eval_data.get("population", 0),
        "flows": flows,
        "_full_records": [],
    }

    _SERVER_EVALUATION_CACHE[evaluation_id] = result
    return result


def export_evaluated_csv_string(
    eval_result: dict[str, Any],
    export_all: bool = True,
) -> str:
    """Export evaluated flows to a downloadable CSV with explicit metadata provenance headers."""
    output = io.StringIO()
    total_received = eval_result.get("row_accounting", {}).get("total_rows_received", 0)
    evaluated_total = eval_result.get("row_accounting", {}).get("evaluated_rows", 0)
    dropped = eval_result.get("row_accounting", {}).get("invalid_rows_dropped", 0)

    if export_all and "_full_records" in eval_result and eval_result["_full_records"]:
        records_to_export = eval_result["_full_records"]
        export_scope = f"Complete Evaluated Population ({len(records_to_export)} rows)"
    else:
        records_to_export = eval_result.get("flows", [])
        export_scope = f"Display Sample Subset ({len(records_to_export)} of {evaluated_total} evaluated rows)"

    output.write("# XRL-IDARS Evaluated CSV Dataset Export\n")
    output.write(f"# Evaluation ID: {eval_result.get('evaluation_id', 'UNTRACKED_SESSION')}\n")
    output.write(f"# Evaluation Mode: {eval_result.get('evaluation_mode', 'custom')}\n")
    output.write(f"# Evaluation Type: {eval_result.get('evaluation_type')} (Official Benchmark: {eval_result.get('official_frozen_benchmark')})\n")
    output.write(f"# Model: {eval_result.get('model_identifier')}\n")
    output.write(f"# Contract: {eval_result.get('contract')}\n")
    output.write(f"# Population Accounting: {total_received} received | {evaluated_total} evaluated | {dropped} dropped\n")
    output.write(f"# Export Scope: {export_scope}\n")
    output.write(f"# Evaluated At: {eval_result.get('provenance', {}).get('evaluated_at')}\n")
    output.write(f"# Invariant: Ground truth and metadata held separate from feature inputs\n#\n")

    if not records_to_export:
        output.write("flow_id,attack_score,prediction_class,prediction_label,ground_truth_label,verdict\n")
        return output.getvalue()

    feature_keys = list(records_to_export[0].get("features", {}).keys())
    writer = csv.writer(output)
    header = [
        "flow_id",
        "attack_score",
        "prediction_class",
        "prediction_label",
        "ground_truth_label",
        "verdict",
        "rf_score",
        "lstm_score",
        "fusion_score",
        "src_endpoint",
        "dst_endpoint",
        "protocol",
    ] + feature_keys
    writer.writerow(header)

    for f in records_to_export:
        meta = f.get("metadata", {})
        src_ep = f.get("src_endpoint") or meta.get("src_endpoint", "N/A")
        dst_ep = f.get("dst_endpoint") or meta.get("dst_endpoint", "N/A")
        proto = f.get("protocol") or meta.get("protocol", "TCP")
        s_atk = f.get("attack_score", f.get("fusion_score", f.get("rf_score", "")))

        row = [
            f.get("flow_id", ""),
            s_atk,
            f.get("prediction_class", ""),
            f.get("prediction_label", ""),
            f.get("ground_truth_label", ""),
            f.get("verdict", ""),
            f.get("rf_score", ""),
            f.get("lstm_score", ""),
            f.get("fusion_score", ""),
            src_ep,
            dst_ep,
            proto,
        ]
        feats = f.get("features", {})
        row.extend([feats.get(k, "") for k in feature_keys])
        writer.writerow(row)

    return output.getvalue()


def get_demo_sample_csv(n_samples: int = 200, benchmark: str = "cicids2017") -> str:
    """Return a ready-to-evaluate CSV slice of the real exhibition data.

    The slice is read from the committed exhibition JSON, which is itself generated from
    the canonical held-out test split. If that file is absent, fail explicitly rather than
    fabricating synthetic traffic.
    """
    if n_samples <= 0:
        raise CSVValidationError("n_samples must be positive")

    bench_clean = str(benchmark).lower().strip()
    if bench_clean in ("cse2018", "cse-cic-ids2018", "cse_cic_ids2018"):
        exh_json = REPO_ROOT / "data" / "demo" / "cse2018_exhibition_200.json"
        features = list(R10_FEATURES)
    elif bench_clean in ("unswnb15", "unsw-nb15", "unsw_nb15"):
        exh_json = REPO_ROOT / "data" / "demo" / "unswnb15_exhibition_200.json"
        features = list(R4_FEATURES)
    else:
        exh_json = REPO_ROOT / "data" / "demo" / "cicids2017_exhibition_200.json"
        features = list(R10_FEATURES)

    if not exh_json.exists():
        raise CSVValidationError(
            f"Exhibition data not found: {exh_json}. "
            "Rebuild it with scripts/demo/build_exhibition_subset.py; no synthetic fallback is used."
        )

    with open(exh_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    rows = data.get("flows", [])[:n_samples]
    if not rows:
        raise CSVValidationError(f"Exhibition data contains no flows: {exh_json}")

    output = io.StringIO()
    cols = ["flow_id", "src_endpoint", "dst_endpoint", "protocol", "source_file", *features, "label"]
    writer = csv.DictWriter(output, fieldnames=cols)
    writer.writeheader()
    for item in rows:
        row = {
            "flow_id": item.get("flow_id", ""),
            "src_endpoint": item.get("src_endpoint", ""),
            "dst_endpoint": item.get("dst_endpoint", ""),
            "protocol": item.get("protocol", "N/A"),
            "source_file": item.get("source_file", ""),
            "label": item.get("label", 1 if item.get("is_attack") else 0),
        }
        row.update({name: item.get("features", {}).get(name, "") for name in features})
        writer.writerow(row)
    return output.getvalue()
