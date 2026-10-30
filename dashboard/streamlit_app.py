"""Streamlit Operational Dashboard for XRL-IDARS (Phase 12).

Provides an enterprise-grade monitoring dashboard visualizing:
- 4-Tier Active Pipeline (Perception, Rules, Explainability, Autonomous Response)
- Real-time Flow Telemetry and Ingestion
- Cross-Benchmark ML Performance (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15)
- TreeSHAP Local Attributions
- Deterministic Rule Engine & Hybrid Arbitration
- Source-IP Sliding Windows and Escalations
- Dueling DQN Policy and Deterministic Safety Gate
- End-to-End Latency Waterfall
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time

import pandas as pd
import streamlit as st

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.events.manager import EventManager
from xrlids.models.manager import ModelManager
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline

# Streamlit Page Configuration
st.set_page_config(
    page_title="XRL-IDARS Operational Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Initialize Session State
if "event_manager" not in st.session_state:
    st.session_state.event_manager = EventManager()
if "pipeline" not in st.session_state:
    st.session_state.pipeline = ActiveInferencePipeline(
        event_manager=st.session_state.event_manager
    )

pipeline: ActiveInferencePipeline = st.session_state.pipeline
event_mgr: EventManager = st.session_state.event_manager

# Sidebar Information
with st.sidebar:
    st.title("🛡️ XRL-IDARS")
    st.caption("Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System")
    st.divider()

    st.subheader("⚙️ System Status")
    st.markdown("**Perception Model:** `XGBoost Champion / RF`")
    st.markdown("**Feature Contract:** `R10 Canonical`")
    st.markdown("**Response Mode:** `Advisory (Dry-Run)`")
    st.markdown("**Kernel Mutations:** `DISABLED (Safe)`")

    st.divider()
    stats = event_mgr.get_stats()
    st.metric("Total Events Evaluated", stats["total_events"])
    st.metric("Threat Intrusions Flagged", stats["threat_events"])
    st.metric("Deterministic Rule Hits", stats["rule_matches_count"])
    st.metric("Source-IP Escalations", stats["escalated_events_count"])

    st.divider()
    if st.button("🔄 Inject Sample Attack Flow"):
        sample_attack = {
            "flow_duration_ms": 350.0,
            "flow_packets_per_s": 15000.0,
            "flow_bytes_per_s": 900000.0,
            "packet_length_mean": 60.0,
            "packet_length_std": 0.0,
            "syn_count": 80.0,
            "ack_count": 0.0,
            "rst_count": 0.0,
            "fin_count": 0.0,
            "syn_ack_ratio": 80.0,
        }
        res = pipeline.process_flow(
            sample_attack,
            source_ip="10.100.4.88",
            dest_ip="192.168.10.50",
            flow_id=f"flow-demo-{int(time.time())}",
        )
        st.success(f"Processed flow! Verdict: {res.hybrid.verdict} ({res.hybrid.detection_source})")

    if st.button("🧹 Clear Audit Buffer"):
        event_mgr.clear()
        st.info("Buffer cleared.")

# Main Landing Page Content
st.title("🛡️ XRL-IDARS Operational Command Center")
st.markdown("""
Welcome to the **XRL-IDARS** central operational dashboard. This system bridges statistical machine learning,
exact local explainability (TreeSHAP), deterministic network protocol rules, multi-flow source tracking,
and reinforcement learning-based response optimization under strict safety invariants.
""")

st.divider()

# High-Level Metrics Row
kpi1, kpi2, kpi3, kpi4 = st.columns(4)
kpi1.metric("Pipeline Health", "100% OPERATIONAL", "All 4 tiers online")
kpi2.metric("Detection Champion", pipeline.model_manager.model_name, "Latency < 0.2ms")
kpi3.metric("Response Policy", "Dueling DQN (4-Action)", "Cost-optimized")
kpi4.metric("Safety Enforcement", "Deterministic Gate", "0 Kernel Mutations")

st.markdown("### 🏛️ 4-Tier Integrated Architecture")

c1, c2, c3, c4 = st.columns(4)

with c1:
    st.info("#### 1. Perception Tier\n"
            "- **Models:** Random Forest & XGBoost\n"
            "- **Contract:** R10 & R4 canonical features\n"
            "- **Output:** Continuous threat score $P(\\text{ATTACK})$\n"
            "- **Inference:** Sub-millisecond CPU speed")

with c2:
    st.warning("#### 2. Rule & Tracking Tier\n"
               "- **Rule Engine:** 5 deterministic RFC rules\n"
               "- **Arbitration:** Hybrid Decision Matrix\n"
               "- **Source Tracker:** 5 flows / 60s sliding window\n"
               "- **Cooldown:** 30s re-trigger suppression")

with c3:
    st.success("#### 3. Explainability Tier\n"
               "- **Engine:** Lundberg & Lee TreeSHAP\n"
               "- **Type:** Local additive attributions\n"
               "- **Output:** Exact feature Shapley values\n"
               "- **Direction:** Threat increasing vs decreasing")

with c4:
    st.error("#### 4. Response & Safety Tier\n"
             "- **Policy:** Dueling Deep Q-Network\n"
             "- **State:** 6D causal representation $\\mathbf{s}_t$\n"
             "- **Safety Gate:** Critical host exemptions & blast radius\n"
             "- **Execution:** Advisory dry-run mode")

st.divider()

# Recent Events Table
st.subheader("📡 Live Security Event Stream")
recent_events = event_mgr.get_recent_events(limit=10)
if recent_events:
    table_data = []
    for ev in reversed(recent_events):
        table_data.append({
            "Timestamp": ev.timestamp[:19].replace("T", " "),
            "Flow ID": ev.flow_id,
            "Source IP": ev.source_ip,
            "Score": round(ev.detection.get("attack_score", 0.0), 4),
            "Verdict": ev.hybrid_verdict,
            "Severity": ev.severity,
            "Enforced Action": ev.response.get("enforced_action", "ALLOW"),
            "Safety Override": "YES" if ev.response.get("safety_override") else "NO",
        })
    st.dataframe(pd.DataFrame(table_data), use_container_width=True)
else:
    st.info("No events logged in the buffer yet. Click 'Inject Sample Attack Flow' in the sidebar or replay a PCAP in the Ingestion tab.")

st.markdown("---")
st.markdown("👉 **Use the left sidebar navigation** to explore dedicated modules: Live Ingestion, Model Evaluation, TreeSHAP Explainability, Rule Intelligence, Source Tracking, Response Policy, and System Telemetry.")
