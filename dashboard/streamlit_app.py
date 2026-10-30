"""Streamlit Operational Dashboard for XRL-IDARS.

Main application entrypoint configuring exactly three primary sections:
1. Overview (Architecture, how XRL-IDARS works, animated flowchart)
2. Live Demo (Operational command center, Scapy simulation, live/pcap, TreeSHAP, DQN, safety, PostgreSQL)
3. Benchmarks (Offline research evaluation, 10,000-record benchmark, RF vs LSTM vs Fusion comparison)
"""

from __future__ import annotations

import os
from pathlib import Path
import sys

import streamlit as st

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from dashboard.session_init import ensure_session_state
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

# Sidebar Brand & Global Telemetry
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

# Configure exactly 3 primary navigation sections
overview_page = st.Page("pages/01_Overview.py", title="Overview", icon="🛡️", default=True)
live_demo_page = st.Page("pages/02_Live_Demo.py", title="Live Demo", icon="🚨")
benchmarks_page = st.Page("pages/03_Benchmarks.py", title="Benchmarks", icon="📊")

pg = st.navigation({
    "XRL-IDARS": [overview_page, live_demo_page, benchmarks_page]
})
pg.run()
