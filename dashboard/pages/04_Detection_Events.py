"""Page 4: Detection & Events."""

from __future__ import annotations

from datetime import datetime, timezone
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

st.set_page_config(page_title="Detection & Events - XRL-IDARS", page_icon="🚨", layout="wide")

event_mgr, pipeline, live_mgr = ensure_session_state()

st.title("🚨 Detection & Security Events")
st.markdown("Detailed inspection of security events produced by Random Forest inference, deterministic protocol rules, and autonomous response decisions.")

stats = event_mgr.get_stats()
is_pg = bool(stats.get("postgres_active", False))
mode = str(stats.get("storage_mode", "memory"))
persisted = int(stats.get("postgres_persisted_events", 0))
queue_sz = int(stats.get("postgres_queue_size", 0))
errors = int(stats.get("postgres_errors", 0))
last_time_val = float(stats.get("postgres_last_persisted_time", 0.0))
last_persisted_str = (
    datetime.fromtimestamp(last_time_val, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if last_time_val > 0
    else "N/A"
)

if is_pg:
    st.success(
        f"🟢 **Storage Backend: PostgreSQL Connected** | Mode: `{mode}` | "
        f"Persisted: **{persisted}** | Pending Queue: **{queue_sz}** | Failed Writes: **{errors}** | "
        f"Last Persistence: `{last_persisted_str}`"
    )
else:
    st.info(
        f"⚪ **Storage Backend: In-Memory Ring Buffer + JSONL Audit File** | "
        f"PostgreSQL: `Disconnected` | Mode: `{mode}` | "
        f"Local Buffer: **{stats.get('buffer_size', 0)} events**"
    )

st.divider()

# Storage Source Selection
use_db = False
if stats.get("postgres_active"):
    c_src, _ = st.columns([2, 1])
    with c_src:
        source_sel = st.radio(
            "Event Retrieval Source",
            ["Live In-Memory Ring Buffer", "Persistent PostgreSQL Database (Historical)"],
            horizontal=True,
            index=0,
            key="events_data_source",
        )
        use_db = (source_sel == "Persistent PostgreSQL Database (Historical)")

# Filter Controls
col_f1, col_f2, col_f3, col_f4, col_f5 = st.columns([1, 1, 1, 1, 1.2])
with col_f1:
    mode_filter = st.selectbox("Source Mode", ["ALL", "LIVE", "PCAP", "SAMPLE"])
with col_f2:
    verdict_filter = st.selectbox("Verdict", ["ALL", "BENIGN", "ATTACK"])
with col_f3:
    severity_filter = st.selectbox("Severity", ["ALL", "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
with col_f4:
    action_filter = st.selectbox("Enforced Action", ["ALL", "ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE"])
with col_f5:
    source_ip_filter = st.text_input("Source IP", value="").strip()

if use_db:
    events = event_mgr.get_historical_events(
        limit=100,
        source_ip=source_ip_filter or None,
        severity=severity_filter if severity_filter != "ALL" else None,
        verdict=verdict_filter if verdict_filter != "ALL" else None,
        source_mode=mode_filter if mode_filter != "ALL" else None,
    )
else:
    events = event_mgr.get_recent_events(limit=100, source_ip=source_ip_filter or None)

# Filter events
filtered_events = []
event_list_ordered = events if use_db else list(reversed(events))
for ev in event_list_ordered:
    ev_mode = getattr(ev, "source_mode", "LIVE")
    if mode_filter != "ALL" and ev_mode != mode_filter:
        continue
    if verdict_filter != "ALL" and ev.hybrid_verdict != verdict_filter:
        continue
    if severity_filter != "ALL" and ev.severity != severity_filter:
        continue
    act = ev.response.get("enforced_action", "ALLOW")
    if action_filter != "ALL" and act != action_filter:
        continue
    if source_ip_filter and ev.source_ip != source_ip_filter:
        continue
    filtered_events.append(ev)

st.subheader(f"Security Event Stream ({len(filtered_events)} events)")

if filtered_events:
    table_rows = []
    for ev in filtered_events:
        table_rows.append({
            "Event ID": ev.event_id[:12],
            "Source Mode": getattr(ev, "source_mode", "LIVE"),
            "Timestamp": ev.timestamp[:19].replace("T", " "),
            "Flow ID": ev.flow_id,
            "Source IP": ev.source_ip,
            "Dest IP": ev.dest_ip,
            "RF Score": round(ev.detection.get("attack_score", 0.0), 4),
            "Hybrid Risk": round(getattr(ev, "hybrid_risk_score", ev.detection.get("attack_score", 0.0)), 4),
            "Verdict": ev.hybrid_verdict,
            "Severity": ev.severity,
            "Proposed": ev.response.get("proposed_action", "ALLOW"),
            "Enforced": ev.response.get("enforced_action", "ALLOW"),
            "Override": "YES" if ev.response.get("safety_override") else "NO",
        })
    st.dataframe(pd.DataFrame(table_rows), use_container_width=True)

    st.divider()

    # Event Detail Inspector
    st.subheader("Event Detail Inspector")
    selected_idx = st.selectbox(
        "Select Event to Inspect",
        range(len(filtered_events)),
        format_func=lambda i: f"[{filtered_events[i].timestamp[:19]}] [{getattr(filtered_events[i], 'source_mode', 'LIVE')}] {filtered_events[i].source_ip} -> {filtered_events[i].dest_ip} ({filtered_events[i].hybrid_verdict}, {filtered_events[i].severity})",
    )
    ev = filtered_events[selected_idx]

    c_det1, c_det2 = st.columns(2)

    with c_det1:
        st.markdown("#### 1. Flow Metadata & Features")
        st.markdown(f"**Flow ID:** `{ev.flow_id}`")
        st.markdown(f"**Endpoints:** `{ev.source_ip}:{ev.source_port}` → `{ev.dest_ip}:{ev.dest_port}` (Proto {ev.protocol})")
        st.markdown(f"**Source Status:** `{ev.source_status}` (Escalated: `{ev.source_escalated}`)")

        if ev.features:
            feat_df = pd.DataFrame([{"Feature": k, "Value": round(v, 4) if isinstance(v, float) else v} for k, v in ev.features.items()])
            st.dataframe(feat_df, use_container_width=True)

    with c_det2:
        st.markdown("#### 2. Detection & Response Decision")
        st.markdown(f"**Random Forest Probability:** `{ev.detection.get('attack_score', 0.0):.4f}`")
        st.markdown(f"**Hybrid Risk Score (Rules Floor):** `{getattr(ev, 'hybrid_risk_score', ev.detection.get('attack_score', 0.0)):.4f}`")
        st.markdown(f"**Classification Family:** `{ev.detection.get('attack_family', 'BENIGN')}`")
        st.markdown(f"**Hybrid Verdict:** `{ev.hybrid_verdict}` (Severity: `{ev.severity}`)")

        if ev.rule_matches:
            st.markdown(f"**Rule Matches ({len(ev.rule_matches)}):**")
            for r in ev.rule_matches:
                st.markdown(f"- `{r.get('rule_id', 'RULE')}`: {r.get('description', '')}")
        else:
            st.markdown("_No protocol rule violations._")

        st.markdown("---")
        st.markdown("#### Autonomous Response & Safety")
        resp = ev.response
        st.markdown(f"- **DQN Proposed Action:** `{resp.get('proposed_action', 'ALLOW')}`")
        st.markdown(f"- **Safety Enforced Action:** `{resp.get('enforced_action', 'ALLOW')}`")
        st.markdown(f"- **Safety Override:** `{'YES' if resp.get('safety_override') else 'NO'}`")
        if resp.get("override_reason"):
            st.markdown(f"- **Override Reason:** `{resp.get('override_reason')}`")
        st.markdown(f"- **Execution Mode:** `ADVISORY / DRY-RUN (Zero Mutations)`")
else:
    st.info("No security events match the selected criteria.")
