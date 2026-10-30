"""Streamlit Operational Dashboard for XRL-IDARS.

Main entrypoint providing:
- Global session state initialization (EventManager, ActiveInferencePipeline, LiveCaptureManager)
- Unified left-sidebar navigation across 10 operational modules
- Real-time event statistics and pipeline controls
- Clean, minimal, neutral typography and restrained status colors
"""

from __future__ import annotations

import os
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

from dashboard.session_init import ensure_session_state
from xrlids.capture.live_manager import LiveCaptureManager
from xrlids.events.manager import EventManager
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline

# Page configuration
st.set_page_config(
    page_title="XRL-IDARS Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom minimal neutral CSS styling
st.markdown("""
<style>
  /* Clean neutral typography */
  .main .block-container {
    padding-top: 1.5rem;
    padding-bottom: 2rem;
    max-width: 1200px;
  }
  h1, h2, h3, h4 {
    font-weight: 700;
    color: #0f172a;
    letter-spacing: -0.01em;
  }
  /* Restrained status badges */
  .badge-neutral {
    background-color: #f1f5f9;
    color: #334155;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 600;
    font-size: 0.8rem;
    display: inline-block;
  }
  .badge-op {
    background-color: #dbeafe;
    color: #1e40af;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.8rem;
    display: inline-block;
  }
  .badge-research {
    background-color: #fef3c7;
    color: #92400e;
    padding: 2px 8px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.8rem;
    display: inline-block;
  }
</style>
""", unsafe_allow_html=True)

# Ensure global session state
event_mgr, pipeline, live_mgr = ensure_session_state()

event_mgr: EventManager = st.session_state.event_manager
pipeline: ActiveInferencePipeline = st.session_state.pipeline
live_mgr: LiveCaptureManager = st.session_state.live_manager

# Sidebar Global Telemetry
with st.sidebar:
    st.markdown("### 🛡️ XRL-IDARS")
    st.caption("Explainable Reinforcement Learning-Based Intrusion Detection & Autonomous Response")
    st.divider()

    st.markdown("**Operational Architecture**")
    st.markdown("- **ML Detector:** `Random Forest (Sole Live ML)`")
    st.markdown("- **Feature Contract:** `R10 Canonical (10 Features)`")
    st.markdown("- **Response Policy:** `Dueling DQN (4 Actions)`")
    st.markdown("- **Safety Gate:** `Deterministic Invariants`")
    st.markdown("- **Actuator Mode:** `ADVISORY (Zero Mutations)`")

    st.divider()
    stats = event_mgr.get_stats()
    c_s1, c_s2 = st.columns(2)
    c_s1.metric("Total Events", stats["total_events"])
    c_s2.metric("Threats", stats["threat_events"])

    c_s3, c_s4 = st.columns(2)
    c_s3.metric("Rule Matches", stats["rule_matches_count"])
    c_s4.metric("Escalations", stats["escalated_events_count"])

    st.divider()
    # Quick Simulation / Buffer Action
    if st.button("Inject Sample Test Flow", use_container_width=True):
        sample_flow = {
            "flow_duration_ms": 250.0,
            "flow_packets_per_s": 8000.0,
            "flow_bytes_per_s": 480000.0,
            "packet_length_mean": 60.0,
            "packet_length_std": 0.0,
            "syn_count": 50.0,
            "ack_count": 0.0,
            "rst_count": 0.0,
            "fin_count": 0.0,
            "syn_ack_ratio": 50.0,
        }
        res = pipeline.process_flow(
            sample_flow,
            source_ip="10.200.1.88",
            dest_ip="192.168.10.50",
            flow_id=f"flow-sample-{int(time.time()*1000)}",
            source_mode="SAMPLE",
        )
        st.success(f"Sample evaluated: {res.hybrid.verdict} ({res.hybrid.severity})")

    if st.button("Clear Event Audit Buffer", use_container_width=True):
        event_mgr.clear()
        st.info("Buffer cleared.")

# Main Page Header
st.title("🛡️ XRL-IDARS Operational Command Center")
st.markdown("""
Autonomous network defense system coupling sub-millisecond Random Forest classification on 10 deterministic flow statistics ($R_{10}$) with exact local TreeSHAP attribution and a causal 6-dimensional Dueling Deep Q-Network (DQN) response policy under an inviolable deterministic safety gate.
""")

st.divider()

# Core Status Cards Row
col1, col2, col3, col4 = st.columns(4)
live_stats = live_mgr.get_stats()

with col1:
    st.markdown("**Capture Daemon**")
    status_label = live_stats["status"]
    if status_label == "RUNNING":
        st.markdown("<span class='badge-op'>● CAPTURE ACTIVE</span>", unsafe_allow_html=True)
    elif status_label == "BLOCKED":
        st.markdown("<span class='badge-research'>⚠ BLOCKED (UNPRIVILEGED)</span>", unsafe_allow_html=True)
    else:
        st.markdown(f"<span class='badge-neutral'>○ {status_label}</span>", unsafe_allow_html=True)
    st.caption(f"Interface: `{live_stats['interface']}` | PPS: {live_stats['packets_per_sec']}")

with col2:
    st.markdown("**Operational ML Detector**")
    st.markdown("<span class='badge-op'>RANDOM FOREST</span>", unsafe_allow_html=True)
    st.caption("F1 = 0.9512 | Latency < 0.80 ms (CPU)")

with col3:
    st.markdown("**Autonomous Policy**")
    st.markdown("<span class='badge-op'>DUELING DQN</span>", unsafe_allow_html=True)
    st.caption("4 Actions: ALLOW, ALERT, RATE_LIMIT, ISOLATE")

with col4:
    st.markdown("**Execution Guardrail**")
    st.markdown("<span class='badge-neutral'>ADVISORY / DRY-RUN</span>", unsafe_allow_html=True)
    st.caption("Zero kernel mutations | Inviolable allowlists")

st.divider()

# System Pipeline & Architecture Summary
st.subheader("Operational Pipeline")
st.markdown("""
`Scapy / PCAP Replay` → `Canonical FlowEngine (Min<Max 5-Tuple)` → `R10 Feature Contract` → `StandardScaler` → **`Random Forest (Sole Operational ML)`** → `Security Event` → **`TreeSHAP Explainer`** → `6D StateBuilder` → **`Dueling DQN Policy`** → **`Deterministic Safety Gate`** → `Advisory Actuator` → `Streamlit SOC Dashboard (:8501)`
""")

st.info("ℹ️ **Scientific Integrity Invariant:** Random Forest performs intrusion classification. Dueling DQN performs multi-tier response selection. Pretrained PyTorch LSTM FlowSeq sequence models and RF–LSTM convex fusion are preserved strictly for offline research benchmarking and are never invoked in live operational packet processing.")

st.divider()

# Recent Event Stream Table
st.subheader("Recent Security Events")
recent_events = event_mgr.get_recent_events(limit=10)
if recent_events:
    table_rows = []
    for ev in reversed(recent_events):
        table_rows.append({
            "Timestamp": ev.timestamp[:19].replace("T", " "),
            "Flow ID": ev.flow_id,
            "Source IP": ev.source_ip,
            "Dest IP": ev.dest_ip,
            "Attack Score": round(ev.detection.get("attack_score", 0.0), 4),
            "Verdict": ev.hybrid_verdict,
            "Severity": ev.severity,
            "Proposed Action": ev.response.get("proposed_action", "ALLOW"),
            "Enforced Action": ev.response.get("enforced_action", "ALLOW"),
            "Safety Override": "YES" if ev.response.get("safety_override") else "NO",
        })
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True)
else:
    st.markdown("_No events recorded in buffer yet. Use Packet & Flow Ingestion to stream packets or inject a sample flow from the sidebar._")
