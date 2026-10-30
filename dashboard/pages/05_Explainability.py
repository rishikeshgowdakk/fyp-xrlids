"""Page 5: TreeSHAP Explainability."""

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

st.set_page_config(page_title="Explainability - XRL-IDARS", page_icon="🔍", layout="wide")

event_mgr, pipeline, live_mgr = ensure_session_state()
events = event_mgr.get_recent_events(limit=50)

st.title("🔍 TreeSHAP Explainability")
st.markdown("Exact local Shapley feature attributions computed via the Lundberg & Lee TreeSHAP algorithm for Random Forest threat predictions.")

st.divider()

# Filter events that have explanations
explained_events = [ev for ev in reversed(events) if ev.explanation is not None]

if not explained_events:
    st.info("No explained security events in memory. By default, TreeSHAP runs on flows exceeding the threat threshold ($P(\\text{ATTACK}) \\ge 0.40$) or protocol rule hits. Inject a sample attack flow or replay an attack PCAP to generate explanations.")

    if st.button("🚀 Generate Sample Attack with TreeSHAP", type="primary"):
        sample_attack = {
            "flow_duration_ms": 300.0,
            "flow_packets_per_s": 12000.0,
            "flow_bytes_per_s": 720000.0,
            "packet_length_mean": 60.0,
            "packet_length_std": 0.0,
            "syn_count": 75.0,
            "ack_count": 0.0,
            "rst_count": 0.0,
            "fin_count": 0.0,
            "syn_ack_ratio": 75.0,
        }
        st.session_state.pipeline.process_flow(
            sample_attack,
            source_ip="10.200.1.66",
            dest_ip="192.168.10.80",
            flow_id="sample-shap-eval",
            explain=True,
            source_mode="SAMPLE",
        )
        st.rerun()
else:
    selected_idx = st.selectbox(
        "Select Event for Shapley Attribution",
        range(len(explained_events)),
        format_func=lambda i: f"[{explained_events[i].timestamp[:19]}] {explained_events[i].source_ip} (RF Score: {explained_events[i].detection.get('attack_score', 0.0):.4f}, {explained_events[i].severity})",
    )
    ev = explained_events[selected_idx]
    exp = ev.explanation

    col_meta, col_summary = st.columns([1, 1])
    with col_meta:
        st.subheader("Attribution Context")
        st.markdown(f"**Flow ID:** `{ev.flow_id}`")
        st.markdown(f"**Random Forest Score:** `{ev.detection.get('attack_score', 0.0):.4f}`")
        st.markdown(f"**Base Expected Value $E[f(x)]$:** `{exp.get('base_value', 0.0):.4f}`")
        st.markdown(f"**Attribution Latency:** `{exp.get('latency_ms', 1.8):.2f} ms`")

    with col_summary:
        st.subheader("Shapley Additivity")
        st.markdown("""
        By Shapley efficiency, the sum of all local feature attributions exactly equals the deviation of the prediction from the background dataset expectation:
        $$f(x) - E[f(x)] = \\sum_{i=1}^{M} \\phi_i$$
        """)

    st.divider()

    # Waterfall Feature Importance Chart
    st.subheader("Local Feature Attributions (Waterfall)")
    top_features = exp.get("top_features", [])
    if top_features:
        chart_data = []
        for tf in top_features:
            val = tf["shap_value"]
            chart_data.append({
                "Feature": tf["feature"],
                "Shapley Value": val,
                "Impact": "Threat Increasing (+)" if val >= 0 else "Threat Decreasing (-)",
            })

        df_chart = pd.DataFrame(chart_data)
        st.bar_chart(df_chart.set_index("Feature")["Shapley Value"])

        st.subheader("Exact Numerical Shapley Table")
        detail_rows = []
        for tf in top_features:
            detail_rows.append({
                "Feature Name": tf["feature"],
                "Observed Value": tf["feature_value"],
                "Shapley Attribution (ϕ)": round(tf["shap_value"], 6),
                "Direction": "Threat Increasing (+)" if tf["shap_value"] >= 0 else "Threat Decreasing (-)",
            })
        st.dataframe(pd.DataFrame(detail_rows), use_container_width=True)
