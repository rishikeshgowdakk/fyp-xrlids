"""Page 1: System Overview and Architecture."""

from __future__ import annotations

from pathlib import Path
import sys
import streamlit as st
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

st.set_page_config(page_title="Overview & Architecture - XRL-IDARS", page_icon="🏛️", layout="wide")

st.title("🏛️ System Overview & Architecture")
st.markdown("Detailed breakdown of the XRL-IDARS end-to-end intrusion detection and response architecture.")

st.divider()

col1, col2 = st.columns([3, 2])

with col1:
    st.subheader("System Pipeline Workflow")
    st.markdown("""
    The system processes incoming traffic through four coordinated stages:

    1. **Ingestion & Flow Construction:** Packets captured via Scapy or PCAP replay are mapped into bidirectional 5-tuple flows. Upon connection termination (TCP FIN/RST) or 120s timeout, canonical $R_{10}$ features are extracted and validated against strict schema contracts.
    2. **Perception & Parallel Detection:** The primary operational machine learning detector (Random Forest) computes continuous threat posterior $P(\\text{ATTACK}) \\in [0, 1]$. In parallel, the deterministic Rule Engine evaluates protocol invariants (RFC 793/1122).
    3. **Hybrid Arbitration & Source Tracking:** The Hybrid Decision Engine reconciles statistical model predictions and protocol rule violations. The Source Activity Tracker aggregates threat history across a 60s sliding window.
    4. **Local Explainability & Autonomous Response:** TreeSHAP calculates local feature contributions for significant threats. The Dueling DQN policy maps a 6D causal state to optimal response actions, validated by the Deterministic Safety Gate.
    """)

with col2:
    st.subheader("Model Artifact Provenance")
    st.markdown("""
    - **Random Forest (Operational Classifier):**
      - `cicids2017` ($F_1 = 0.9512$, $N = 355\\text{k}$)
      - `cse2018` ($F_1 = 0.8861$, $N = 1.66\\text{M}$)
      - `unswnb15` ($F_1 = 0.8546$, $N = 24.5\\text{k}$)
      - `cse2018_tuesday_flood` ($F_1 = 0.9977$, $N = 8,726$)
    - **Offline Research Sequence Model:**
      - PyTorch LSTM (`EXP-P2-LSTM-VALID-001`, $F_1 = 0.9996$, $N = 8,726$)
      - Retained strictly as offline research baseline
    - **DQN Response Policy:**
      - Checkpoint: `models/dqn/dqn_4action_best.pt`
      - Backbone: 2-layer MLP (64, 64) with LayerNorm
    """)

st.divider()
st.subheader("Subsystem Matrix")
subsystems = [
    {"Subsystem": "Perception Tier", "Technology": "Random Forest (Sole Operational Detector)", "Latency": "< 0.8 ms", "Contract": "R10 / R4", "Status": "ONLINE"},
    {"Subsystem": "Explainability Tier", "Technology": "TreeSHAP (Lundberg & Lee)", "Latency": "~ 27 ms", "Contract": "Exact Shapley", "Status": "ONLINE"},
    {"Subsystem": "Rule Engine", "Technology": "Deterministic Protocol Rules", "Latency": "< 0.01 ms", "Contract": "RFC 793/1122", "Status": "ONLINE"},
    {"Subsystem": "Source Tracker", "Technology": "Sliding Window Buffer", "Latency": "< 0.05 ms", "Contract": "5 flows / 60s", "Status": "ONLINE"},
    {"Subsystem": "Response Policy", "Technology": "Dueling Deep Q-Network", "Latency": "~ 0.5 ms", "Contract": "6D Causal State", "Status": "ONLINE"},
    {"Subsystem": "Safety Gate", "Technology": "Deterministic Invariants", "Latency": "< 0.01 ms", "Contract": "Exemptions / Radius", "Status": "ONLINE"},
]
st.dataframe(pd.DataFrame(subsystems), use_container_width=True)
