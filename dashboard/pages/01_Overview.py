"""Page 1: System Overview & Architecture."""

from __future__ import annotations

from pathlib import Path
import sys
import pandas as pd
import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from dashboard.session_init import ensure_session_state
from xrlids.events.manager import EventManager
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline

st.set_page_config(page_title="Overview - XRL-IDARS", page_icon="🏛️", layout="wide")

event_mgr, pipeline, live_mgr = ensure_session_state()

st.title("🏛️ System Overview & Architecture")
st.markdown("Architectural breakdown of the XRL-IDARS network intrusion detection and explainable autonomous response system.")

st.divider()

col_pipe, col_models = st.columns([3, 2])

with col_pipe:
    st.subheader("Operational Pipeline Workflow")
    st.markdown("""
    The system processes network traffic through decoupled, latency-optimized stages:

    1. **Packet Capture & Stream Replay:** Ingests live wire frames via Scapy raw sockets or replays PCAP streams.
    2. **Canonical Bidirectional Flow Engine:** Assembles packets into bidirectional flows keyed by sorted 5-tuple `(min(IP), max(IP), ...)`. Emits completed flows on TCP `FIN`/`RST` or 120s sliding timeout.
    3. **R10 Feature Extraction & Scaling:** Extracts 10 standardized statistical moments and applies the train-fitted `StandardScaler`.
    4. **Operational ML Detector (Random Forest):** Evaluates completed flows in **< 0.80 ms** CPU latency ($F_1 = 0.9512$). In parallel, the Rule Engine checks RFC 793/1122 protocol invariants.
    5. **TreeSHAP Explainability:** Calculates exact local Shapley feature attributions in **< 2.5 ms** for flagged threats.
    6. **Causal 6D StateBuilder & Dueling DQN:** Constructs the causal Markov state vector $\\mathbf{s}_t = [S_t, \\Delta S_t, N_{\\text{alert}}, a_{t-1}, c_t, v_t]$ and selects cost-optimal mitigation across 4 actions.
    7. **Deterministic Safety Gate & Advisory Actuator:** Enforces critical host allowlists, 30s cooldowns, and 5% blast-radius circuit breakers under advisory (dry-run) execution.
    """)

with col_models:
    st.subheader("Model Artifact Provenance")
    st.markdown("""
    - **Operational Champion:**
      - Model: Random Forest (`models/rf/random_forest_cicids2017.joblib`)
      - Contract: $R_{10}$ Canonical (10 Features)
      - Status: **SOLE OPERATIONAL ML DETECTOR**
    - **Autonomous Response Policy:**
      - Model: Dueling Deep Q-Network (`models/dqn/dqn_4action_best.pt`)
      - State Space: 6D Causal Vector
      - Action Space: 4 Actions (`ALLOW`, `ALERT`, `RATE_LIMIT`, `ISOLATE`)
    - **Offline Research Baselines (Independent Track):**
      - PyTorch LSTM FlowSeq (`models/lstm/`, $F_1 = 0.9996$)
      - Convex RF–LSTM Score Fusion (`models/fusion/`)
      - XGBoost Candidate Benchmark (`models/xgboost/`)
      - Status: **STRICTLY OFFLINE — NEVER INVOKED LIVE**
    """)

st.divider()

st.subheader("Subsystem Telemetry Matrix")
subsystems = [
    {"Subsystem": "Perception Tier", "Technology": "Random Forest (Sole Live ML)", "Empirical Latency": "0.78 ms", "Contract": "R10 Features", "Status": "ONLINE"},
    {"Subsystem": "Explainability Tier", "Technology": "TreeSHAP (Lundberg & Lee)", "Empirical Latency": "1.82 ms", "Contract": "Exact Local Shapley", "Status": "ONLINE"},
    {"Subsystem": "Rule Engine", "Technology": "Deterministic Protocol Rules", "Empirical Latency": "0.004 ms", "Contract": "RFC 793/1122", "Status": "ONLINE"},
    {"Subsystem": "Source Tracker", "Technology": "Sliding Window Buffer", "Empirical Latency": "0.003 ms", "Contract": "5 flows / 60s", "Status": "ONLINE"},
    {"Subsystem": "Response Policy", "Technology": "Dueling Deep Q-Network", "Empirical Latency": "0.18 ms", "Contract": "6D Causal State", "Status": "ONLINE"},
    {"Subsystem": "Safety Gate", "Technology": "Deterministic Invariants", "Empirical Latency": "0.001 ms", "Contract": "Allowlist / 5% Blast", "Status": "ONLINE"},
    {"Subsystem": "Actuator", "Technology": "Advisory / Dry-Run Backend", "Empirical Latency": "0.015 ms", "Contract": "Zero Kernel Mutations", "Status": "ONLINE (ADVISORY)"},
]
st.dataframe(pd.DataFrame(subsystems), use_container_width=True)
