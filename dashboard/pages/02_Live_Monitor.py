"""Page 2: Live Monitor & Telemetry."""

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

from dashboard.session_init import ensure_session_state
from xrlids.capture.live_manager import LiveCaptureManager
from xrlids.events.manager import EventManager
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline

st.set_page_config(page_title="Live Monitor - XRL-IDARS", page_icon="📡", layout="wide")

event_mgr, pipeline, live_mgr = ensure_session_state()

st.title("📡 Live Monitor")
st.markdown("Real-time network traffic throughput, active flow state, and live security event stream.")

st.divider()

# Mode Indicator Banner
live_stats = live_mgr.get_stats()
status = live_stats["status"]

if status == "RUNNING":
    st.success(f"🟢 **MODE: LIVE WIRE CAPTURE ACTIVE** — Sniffing on interface `{live_stats['interface']}` with filter `{live_stats['bpf_filter']}`.")
elif status == "BLOCKED":
    st.warning(f"🟠 **MODE: LIVE SNIFFING BLOCKED** — {live_stats['last_error'] or 'Insufficient OS privileges (CAP_NET_RAW / root required).'}")
else:
    st.info("⚪ **MODE: CAPTURE IDLE** — Live capture daemon is not running. Use 'Packet & Flow Ingestion' to start sniffing or replay PCAP.")

# Top Telemetry Cards
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Packets Captured", live_stats["packets_captured"])
c2.metric("Throughput", f"{live_stats['packets_per_sec']} pkt/s")
c3.metric("Active Flows", live_stats["active_flows"])
c4.metric("Completed Flows", live_stats["completed_flows"])
c5.metric("Threats Flagged", live_stats["threats_detected"])

st.divider()

col_stream, col_dist = st.columns([2, 1])

with col_stream:
    st.subheader("Live Security Event Stream (Wire Traffic Only)")
    all_events = event_mgr.get_recent_events(limit=50)
    live_events = [ev for ev in all_events if getattr(ev, "source_mode", "LIVE") == "LIVE"]
    if live_events:
        rows = []
        for ev in reversed(live_events[:15]):
            rows.append({
                "Timestamp": ev.timestamp[:19].replace("T", " "),
                "Flow ID": ev.flow_id,
                "Source IP": ev.source_ip,
                "RF Score": round(ev.detection.get("attack_score", 0.0), 4),
                "Verdict": ev.hybrid_verdict,
                "Severity": ev.severity,
                "Action": ev.response.get("enforced_action", "ALLOW"),
                "Override": "YES" if ev.response.get("safety_override") else "NO",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.markdown("_No live wire capture events recorded yet. Start live capture from 'Packet & Flow Ingestion'._")

with col_dist:
    st.subheader("Live Verdict Distribution")
    total = len(live_events)
    threats = sum(1 for ev in live_events if ev.hybrid_verdict != "BENIGN" or ev.detection.get("attack_score", 0.0) >= 0.50)
    benign = max(0, total - threats)

    if total > 0:
        dist_df = pd.DataFrame([
            {"Verdict": "Benign", "Count": benign},
            {"Verdict": "Threat / Attack", "Count": threats},
        ])
        st.bar_chart(dist_df.set_index("Verdict"))
    else:
        st.markdown("_No events available for distribution._")

    st.markdown("#### System Controls")
    if st.button("🔄 Refresh Telemetry", use_container_width=True):
        st.rerun()
