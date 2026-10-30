"""Page 4: TreeSHAP Local Explainability (Phase 12).

Provides interactive local feature attributions using TreeSHAP (Lundberg & Lee):
- Pre-configured flow archetypes (Normal browsing, SYN flood, Port scan, Slowloris)
- Manual feature parameter sliders for the full R10 contract
- Real-time computation of exact Shapley additive values
- Waterfall/attribution visualizations with threat-increasing vs threat-decreasing indicators
"""

from __future__ import annotations

from pathlib import Path
import sys

import numpy as np
import pandas as pd
import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.explainability.explainer import TreeSHAPExplainer
from xrlids.models.manager import ModelManager

st.set_page_config(page_title="TreeSHAP Explainability - XRL-IDARS", page_icon="🔍", layout="wide")

st.title("🔍 TreeSHAP Local Feature Explainability")
st.markdown("""
Inspect local additive feature attributions calculated using **TreeSHAP** (Lundberg & Lee, Nature MI 2020).
TreeSHAP explains why the perception model classified a specific network flow as benign or anomalous by computing
the exact marginal contribution of each feature:

$$\\sum_{i=1}^M \\phi_i(x) = f(x) - E[f(x)]$$
""")

st.divider()

# Preset flow profiles
PRESETS = {
    "SYN Flood Attack (High Packets, Zero ACK)": {
        "flow_duration_ms": 450.0,
        "flow_packets_per_s": 22000.0,
        "flow_bytes_per_s": 1320000.0,
        "packet_length_mean": 60.0,
        "packet_length_std": 0.0,
        "syn_count": 95.0,
        "ack_count": 0.0,
        "rst_count": 0.0,
        "fin_count": 0.0,
        "syn_ack_ratio": 95.0,
    },
    "Port Scan / Sweep (Low Bytes, High Rate)": {
        "flow_duration_ms": 12.0,
        "flow_packets_per_s": 8500.0,
        "flow_bytes_per_s": 420000.0,
        "packet_length_mean": 48.0,
        "packet_length_std": 0.0,
        "syn_count": 1.0,
        "ack_count": 0.0,
        "rst_count": 1.0,
        "fin_count": 0.0,
        "syn_ack_ratio": 1.0,
    },
    "Normal HTTPS Web Browsing (Benign)": {
        "flow_duration_ms": 4200.0,
        "flow_packets_per_s": 28.5,
        "flow_bytes_per_s": 32000.0,
        "packet_length_mean": 1120.0,
        "packet_length_std": 450.0,
        "syn_count": 1.0,
        "ack_count": 35.0,
        "rst_count": 0.0,
        "fin_count": 1.0,
        "syn_ack_ratio": 0.028,
    },
    "Slowloris DoS (Low Rate, Long Duration)": {
        "flow_duration_ms": 85000.0,
        "flow_packets_per_s": 0.35,
        "flow_bytes_per_s": 22.0,
        "packet_length_mean": 54.0,
        "packet_length_std": 12.0,
        "syn_count": 1.0,
        "ack_count": 15.0,
        "rst_count": 0.0,
        "fin_count": 0.0,
        "syn_ack_ratio": 0.067,
    },
}

selected_preset = st.selectbox("Load Predefined Flow Archetype", list(PRESETS.keys()))
preset_data = PRESETS[selected_preset]

st.subheader("⚙️ $R_{10}$ Canonical Flow Parameters")

c1, c2, c3 = st.columns(3)

with c1:
    flow_duration_ms = st.number_input("Flow Duration (ms)", value=float(preset_data["flow_duration_ms"]), min_value=0.0, step=100.0)
    flow_packets_per_s = st.number_input("Flow Packets / sec", value=float(preset_data["flow_packets_per_s"]), min_value=0.0, step=100.0)
    flow_bytes_per_s = st.number_input("Flow Bytes / sec", value=float(preset_data["flow_bytes_per_s"]), min_value=0.0, step=1000.0)
    packet_length_mean = st.number_input("Mean Packet Length (bytes)", value=float(preset_data["packet_length_mean"]), min_value=0.0, step=10.0)

with c2:
    packet_length_std = st.number_input("Packet Length Std Dev", value=float(preset_data["packet_length_std"]), min_value=0.0, step=10.0)
    syn_count = st.number_input("SYN Flag Count", value=float(preset_data["syn_count"]), min_value=0.0, step=1.0)
    ack_count = st.number_input("ACK Flag Count", value=float(preset_data["ack_count"]), min_value=0.0, step=1.0)

with c3:
    rst_count = st.number_input("RST Flag Count", value=float(preset_data["rst_count"]), min_value=0.0, step=1.0)
    fin_count = st.number_input("FIN Flag Count", value=float(preset_data["fin_count"]), min_value=0.0, step=1.0)
    syn_ack_ratio = st.number_input("SYN/ACK Ratio", value=float(preset_data["syn_ack_ratio"]), min_value=0.0, step=0.1)

flow_input = {
    "flow_duration_ms": flow_duration_ms,
    "flow_packets_per_s": flow_packets_per_s,
    "flow_bytes_per_s": flow_bytes_per_s,
    "packet_length_mean": packet_length_mean,
    "packet_length_std": packet_length_std,
    "syn_count": syn_count,
    "ack_count": ack_count,
    "rst_count": rst_count,
    "fin_count": fin_count,
    "syn_ack_ratio": syn_ack_ratio,
}

if st.button("🚀 Calculate Exact TreeSHAP Attributions", type="primary"):
    with st.spinner("Executing TreeSHAP tree traversal and calculating Shapley values..."):
        try:
            mgr = ModelManager()
            pred = mgr.predict_flow(flow_input)
            
            explainer = TreeSHAPExplainer(
                model=mgr.model,
                feature_names=mgr.features,
                preprocessor=mgr.preprocessor,
            )
            explanation = explainer.explain_flow(flow_input)
            
            st.divider()
            
            res_c1, res_c2, res_c3 = st.columns(3)
            res_c1.metric("Predicted Model Score", f"{pred.attack_score:.4f}", "P(ATTACK)")
            res_c2.metric("Base Value E[f(x)]", f"{explanation.base_value:.4f}", "Prior Expectation")
            res_c3.metric("Classification Verdict", pred.prediction_label, mgr.model_name)

            st.subheader("📊 Feature Attribution Ranking (Shapley Values $\\phi_i$)")
            
            attribs = explanation.attributions
            sorted_attribs = sorted(attribs, key=lambda a: abs(a["shap_attribution"]), reverse=True)
            
            df_shap = pd.DataFrame([
                {
                    "Feature": a["feature"],
                    "Value": a["value"],
                    "SHAP Attribution": round(a["shap_attribution"], 4),
                    "Direction": "🚨 " + a["direction"] if "INCREASE" in a["direction"] else ("🛡️ " + a["direction"] if "DECREASE" in a["direction"] else "⚪ " + a["direction"]),
                }
                for a in sorted_attribs
            ])
            
            st.dataframe(df_shap, use_container_width=True)
            
            # Simple bar chart
            chart_data = pd.DataFrame({
                "Feature": [a["feature"] for a in sorted_attribs],
                "SHAP Value": [a["shap_attribution"] for a in sorted_attribs],
            }).set_index("Feature")
            st.bar_chart(chart_data)

            if explanation.top_features:
                top_str = ", ".join(f"{tf['feature']} ({tf['shap_attribution']:+.3f})" for tf in explanation.top_features[:3])
                st.info(f"**Top Driving Features:** {top_str}")

        except Exception as ex:
            st.error(f"Error computing TreeSHAP explanation: {ex}")
