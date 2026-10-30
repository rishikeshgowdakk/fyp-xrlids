"""Page 9: Research Benchmarks (Offline Only)."""

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

st.set_page_config(page_title="Research Benchmarks - XRL-IDARS", page_icon="🔬", layout="wide")

st.title("🔬 Offline Research Benchmarks")
st.markdown("Comparative evaluations preserving pretrained LSTM sequence models, RF–LSTM convex score fusion, and candidate model benchmarks.")

# Prominent Invariant Notice
st.warning("""
⚠️ **INDEPENDENT OFFLINE RESEARCH BENCHMARK TRACK**  
Pretrained PyTorch LSTM sequence models (`models/lstm/`, `EXP-P2-LSTM-VALID-001`), convex score fusion weights (`models/fusion/`), and XGBoost candidate models (`models/xgboost/`) are preserved strictly for offline comparative research, empirical validation, and reproducibility.

**THEY ARE NEVER INVOKED BY THE OPERATIONAL LIVE DETECTION PIPELINE.**  
Random Forest is the sole operational ML detector for wire packet sniffing and streaming PCAP replay.
""")

st.divider()

# Head-to-Head Architecture Comparison Table
st.subheader("1. Head-to-Head Comparative Architecture Benchmark")
comp_data = [
    {
        "Architecture / Model": "Random Forest (Operational Champion)",
        "Pipeline Role": "Operational Detector (Live / Replay)",
        "Accuracy": "99.06%",
        "F1-Score": "0.9512",
        "Inference Latency": "0.78 ms",
        "Line-Rate Wire Viability": "YES (< 1.0 ms)",
    },
    {
        "Architecture / Model": "PyTorch LSTM FlowSeq (5 Flows)",
        "Pipeline Role": "Offline Research Benchmark Only",
        "Accuracy": "99.96%",
        "F1-Score": "0.9996",
        "Inference Latency": "12.45 ms",
        "Line-Rate Wire Viability": "NO (Buffer Overflows under Bursts)",
    },
    {
        "Architecture / Model": "Convex RF–LSTM Score Fusion (α=0.7)",
        "Pipeline Role": "Offline Research Benchmark Only",
        "Accuracy": "99.97%",
        "F1-Score": "0.9997",
        "Inference Latency": "13.25 ms",
        "Line-Rate Wire Viability": "NO (Requires Recurrent Context)",
    },
    {
        "Architecture / Model": "XGBoost Candidate Benchmark",
        "Pipeline Role": "Offline Candidate Benchmark Only",
        "Accuracy": "99.08%",
        "F1-Score": "0.9521",
        "Inference Latency": "0.22 ms",
        "Line-Rate Wire Viability": "High-Throughput Candidate",
    },
]
st.dataframe(pd.DataFrame(comp_data), use_container_width=True)

st.divider()

col_latency, col_criteria = st.columns([1, 1])

with col_latency:
    st.subheader("Inference Latency Comparison (ms)")
    lat_df = pd.DataFrame([
        {"Model": "XGBoost (Offline)", "Latency (ms)": 0.22},
        {"Model": "Random Forest (Live Champion)", "Latency (ms)": 0.78},
        {"Model": "TreeSHAP Explainer", "Latency (ms)": 1.82},
        {"Model": "LSTM FlowSeq (Offline)", "Latency (ms)": 12.45},
        {"Model": "RF-LSTM Fusion (Offline)", "Latency (ms)": 13.25},
    ])
    st.bar_chart(lat_df.set_index("Model")["Latency (ms)"])
    st.caption("Random Forest executes in 0.78 ms CPU time, whereas LSTM incurs 12.45 ms, exceeding the line-rate packet burst deadline.")

with col_criteria:
    st.subheader("2. Pre-Registered Response Criteria")
    criteria = [
        {"Criterion": "RQ7: Cost Reduction vs Best Baseline", "Target": "≥ 15.0% (p < 0.01)", "Observed": "+28.31% vs B1 (p<0.001), +0.18% vs B2 (p=0.7600)", "Finding": "H1 Supported vs B1; Target NOT MET vs B2"},
        {"Criterion": "RQ7.1: Action Chattering Index (ACI)", "Target": "ACI < 0.01", "Observed": "ACI = 0.0214 (4-Action) / 0.0019 (3-Action)", "Finding": "FAIL (4-Action) / PASS (3-Action)"},
        {"Criterion": "RQ7.2: False Quarantine Rate (FQR)", "Target": "FQR < 2.0%", "Observed": "0.20% test population (1.00% - 1.58%)", "Finding": "PASS (Zero Outages)"},
        {"Criterion": "RQ7.3: Safety Gate Compliance", "Target": "100% adherence", "Observed": "100% compliance (375/375 critical checks)", "Finding": "PASS (Inviolable)"},
    ]
    st.dataframe(pd.DataFrame(criteria), use_container_width=True)

st.divider()

st.subheader("Honest Scientific Transparency Disclosure")
st.markdown("""
> **Scientific Finding:** While Dueling DQN achieves statistically significant cost reductions over standard practice (+64.3% vs Always-ALLOW, +28.3% vs Single-Threshold, $p < 0.001$), it matches rather than exceeds a calibrated two-tier threshold baseline (+0.18%, $p = 0.7600$), missing the pre-registered 15% practical target. In 4-action mode, rapid switching between RATE_LIMIT and ISOLATE also exceeds the chattering threshold ($\text{ACI} = 0.0214$); this is eliminated in 3-action mode ($\text{ACI} = 0.0019$).
""")
