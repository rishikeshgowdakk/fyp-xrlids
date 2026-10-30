"""Page 7: Safety & Execution Audit."""

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
from xrlids.response.safety import DEFAULT_CRITICAL_HOSTS, Action

st.set_page_config(page_title="Safety & Execution Audit - XRL-IDARS", page_icon="🛡️", layout="wide")

event_mgr, pipeline, live_mgr = ensure_session_state()
safety_gate = pipeline.safety_gate
events = event_mgr.get_recent_events(limit=50)

st.title("🛡️ Deterministic Safety & Execution Audit")
st.markdown("Formal verification of deterministic guardrails, critical asset protection, and zero-mutation response execution.")

st.divider()

# High-Level Safety Invariant Cards
c1, c2, c3, c4 = st.columns(4)
c1.metric("Critical Hosts Protected", len(safety_gate.critical_hosts))
c2.metric("Action Cooldown Window", f"{int(safety_gate.cooldown_steps)} steps")
c3.metric("Blast-Radius Threshold", f"{safety_gate.blast_radius_threshold*100:.0f}%")
c4.metric("Active Mitigations", len(pipeline.executor.active_mitigations))

st.divider()

col_invariants, col_test = st.columns([3, 2])

with col_invariants:
    st.subheader("Deterministic Production Invariants")
    st.markdown("""
    1. **Critical Infrastructure Invariant:** Mission-critical assets (Default Gateway `192.168.10.1`, DNS Server `192.168.10.2`, Domain Controllers) can NEVER be isolated or blocked. Any upstream policy recommendation of `ISOLATE` or `RATE_LIMIT` targeting an allowlisted host is unconditionally downgraded to `ALERT`.
    2. **Anti-Chattering Cooldown Invariant:** Successive aggressive mitigations against the same host within a 30-second window are suppressed to prevent service thrashing.
    3. **Blast-Radius Circuit Breaker:** At no point may the proportion of quarantined hosts exceed **5%** of active network hosts. If an isolation storm is detected, subsequent isolations are clamped.
    4. **Zero Kernel Mutation Invariant:** All autonomous actions operate in advisory dry-run mode. Zero modifications are made to `iptables`, `nftables`, or kernel routing tables.
    """)

    st.markdown("#### Allowlisted Critical Infrastructure")
    crit_df = pd.DataFrame([{"IP Address / CIDR": h, "Role": "Production Core Asset"} for h in safety_gate.critical_hosts])
    st.dataframe(crit_df, use_container_width=True)

with col_test:
    st.subheader("Interactive Safety Gate Verifier")
    st.caption("Verify safety gate enforcement against arbitrary target hosts.")

    test_host = st.selectbox("Select Target Host", ["192.168.10.1 (Default Gateway)", "192.168.10.2 (DNS Server)", "10.200.1.99 (Standard Workstation)", "172.16.0.45 (External Host)"])
    target_ip = test_host.split(" ")[0]
    test_action_name = st.selectbox("Proposed Policy Action", ["ISOLATE", "RATE_LIMIT", "ALERT", "ALLOW"])
    test_action = getattr(Action, test_action_name)

    if st.button("Run Deterministic Safety Check", type="primary", use_container_width=True):
        check_res = safety_gate.check(action=test_action, target_host=target_ip)
        st.markdown(f"**Proposed Action:** `{test_action.name}`")
        st.markdown(f"**Authorized Enforced Action:** `{check_res.action.name}`")
        if check_res.is_overridden:
            st.error(f"⚠️ **ACTION OVERRIDDEN:** {check_res.reason}")
        else:
            st.success(f"✅ **ACTION APPROVED:** {check_res.reason}")

st.divider()

# Safety Audit Trail Table
st.subheader("Safety Audit Trail")
if events:
    audit_rows = []
    for ev in reversed(events):
        resp = ev.response
        audit_rows.append({
            "Timestamp": ev.timestamp[:19].replace("T", " "),
            "Flow ID": ev.flow_id,
            "Target Host": ev.source_ip,
            "Proposed Action": resp.get("proposed_action", "ALLOW"),
            "Enforced Action": resp.get("enforced_action", "ALLOW"),
            "Overridden": "YES" if resp.get("safety_override") else "NO",
            "Reason": resp.get("override_reason") or "Approved by Invariant Checks",
            "Lifecycle State": resp.get("execution_report", {}).get("final_lifecycle_state", "VERIFIED"),
        })
    st.dataframe(pd.DataFrame(audit_rows), use_container_width=True)
else:
    st.info("No audit transactions logged yet. Process flows or evaluate sample attacks to populate the safety audit log.")
