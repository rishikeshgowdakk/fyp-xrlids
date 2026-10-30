"""Page 6: Multi-Flow Source Activity Tracking (Phase 12).

Visualizes and tests the sliding-window source-IP tracker:
- 60-second sliding window per host
- 5-flow suspicious escalation threshold
- 30-second cooldown suppression to prevent alert fatigue
- Interactive flow simulator demonstrating multi-flow escalation
"""

from __future__ import annotations

from pathlib import Path
import sys
import time

import pandas as pd
import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.tracking.source_tracker import SourceActivityTracker

st.set_page_config(page_title="Source Tracking - XRL-IDARS", page_icon="🎯", layout="wide")

# Persistent tracker in session state
if "tracker" not in st.session_state:
    st.session_state.tracker = SourceActivityTracker(
        window_seconds=60.0,
        escalation_threshold=5,
        cooldown_seconds=30.0,
    )

tracker: SourceActivityTracker = st.session_state.tracker

st.title("🎯 Multi-Flow Source Activity Tracking")
st.markdown("""
Monitor and test the **Source Activity Tracking Tier**. While single-flow ML models and protocol rules evaluate
individual flows independently, distributed attackers often intentionally spread malicious activity across
multiple low-rate connections to evade threshold triggers.

The Source Activity Tracker aggregates suspicious flows per source IP across a **60-second sliding window**,
triggering an **escalation alert** upon $\\ge 5$ suspicious flows, backed by a **30-second cooldown suppression timer**.
""")

st.divider()

col_cfg, col_sim = st.columns([1, 1])

with col_cfg:
    st.subheader("⚙️ Tracker Invariants")
    st.markdown("""
    - **Sliding Window:** 60.0 seconds
    - **Escalation Threshold:** 5 suspicious flows
    - **Cooldown Suppression:** 30.0 seconds
    - **Multi-flow Escalation:** Forces causal state elevation in DQN response policy
    """)
    if st.button("🧹 Reset All Host Tracking States"):
        tracker.reset()
        st.success("Tracker reset to initial clean state.")

with col_sim:
    st.subheader("🧪 Interactive Host Activity Simulator")
    test_ip = st.text_input("Source IP Address", value="192.168.1.150")
    num_flows = st.slider("Inject Suspicious Flows", min_value=1, max_value=10, value=3)
    
    if st.button("🚀 Record Suspicious Flow(s)", type="primary"):
        now = time.time()
        escalated_any = False
        for i in range(num_flows):
            esc = tracker.record_flow(source_ip=test_ip, is_suspicious=True, timestamp=now + i * 0.1)
            if esc.escalate:
                escalated_any = True
        
        if escalated_any:
            st.error(f"🚨 ESCALATION TRIGGERED for {test_ip}! Threshold (5 suspicious flows) exceeded!")
        else:
            st.info(f"Recorded {num_flows} flow(s) for {test_ip}.")

st.divider()

st.subheader("📋 Active Tracked Hosts & Sliding Window States")

active_ips = list(tracker._records.keys())
if active_ips:
    table_rows = []
    now = time.time()
    for ip in active_ips:
        rec = tracker._records[ip]
        rec.purge_expired(now, tracker.time_window_seconds)
        count = len(rec.suspicious_timestamps)
        in_cd = tracker.is_in_cooldown(ip, current_time=now)
        cd_elapsed = now - rec.last_escalation_timestamp if rec.last_escalation_timestamp > 0 else 999.0
        remaining = max(0.0, tracker.cooldown_seconds - cd_elapsed) if in_cd else 0.0
        
        table_rows.append({
            "Source IP": ip,
            "Suspicious Flows in 60s Window": count,
            "Threshold Status": f"{count} / {tracker.escalation_threshold}" + (" (ESCALATED 🚨)" if count >= tracker.escalation_threshold else " (Normal)"),
            "In Cooldown?": "ACTIVE ⏳" if in_cd else "NO",
            "Cooldown Remaining (s)": f"{remaining:.1f}s" if in_cd else "0.0s",
        })
    
    st.dataframe(pd.DataFrame(table_rows), width="stretch")
else:
    st.info("No source IPs currently tracked in the active sliding window buffer. Use the simulator above to inject flows.")
