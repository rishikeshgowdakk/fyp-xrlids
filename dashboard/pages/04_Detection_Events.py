"""Page 4: Detection & Events."""

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

st.set_page_config(page_title="Detection & Events - XRL-IDARS", page_icon="🚨", layout="wide")

event_mgr, pipeline, live_mgr = ensure_session_state()
events = event_mgr.get_recent_events(limit=50)

st.title("🚨 Detection & Security Events")
st.markdown("Detailed inspection of security events produced by Random Forest inference, deterministic protocol rules, and autonomous response decisions.")

st.divider()

# Filter Controls
col_f1, col_f2, col_f3 = st.columns(3)
with col_f1:
    verdict_filter = st.selectbox("Filter by Verdict", ["ALL", "BENIGN", "ATTACK"])
with col_f2:
    severity_filter = st.selectbox("Filter by Severity", ["ALL", "INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
with col_f3:
    action_filter = st.selectbox("Filter by Enforced Action", ["ALL", "ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE"])

# Filter events
filtered_events = []
for ev in reversed(events):
    if verdict_filter != "ALL" and ev.hybrid_verdict != verdict_filter:
        continue
    if severity_filter != "ALL" and ev.severity != severity_filter:
        continue
    act = ev.response.get("enforced_action", "ALLOW")
    if action_filter != "ALL" and act != action_filter:
        continue
    filtered_events.append(ev)

st.subheader(f"Security Event Stream ({len(filtered_events)} events)")

if filtered_events:
    table_rows = []
    for ev in filtered_events:
        table_rows.append({
            "Event ID": ev.event_id[:12],
            "Timestamp": ev.timestamp[:19].replace("T", " "),
            "Flow ID": ev.flow_id,
            "Source IP": ev.source_ip,
            "Dest IP": ev.dest_ip,
            "RF Score": round(ev.detection.get("attack_score", 0.0), 4),
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
        format_func=lambda i: f"[{filtered_events[i].timestamp[:19]}] {filtered_events[i].source_ip} -> {filtered_events[i].dest_ip} ({filtered_events[i].hybrid_verdict}, {filtered_events[i].severity})",
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
        st.markdown(f"**Random Forest Attack Score:** `{ev.detection.get('attack_score', 0.0):.4f}`")
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
