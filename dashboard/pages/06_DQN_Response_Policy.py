"""Page 6: DQN Response Policy."""

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

from dashboard.session_init import ensure_session_state
from xrlids.events.manager import EventManager
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline
from xrlids.response.service import DQNResponseService
from xrlids.response.types import Action

st.set_page_config(page_title="DQN Response Policy - XRL-IDARS", page_icon="🤖", layout="wide")

event_mgr, pipeline, live_mgr = ensure_session_state()
events = event_mgr.get_recent_events(limit=50)

st.title("🤖 Dueling DQN Response Policy")
st.markdown("Autonomous response optimization via Dueling Deep Q-Networks formulated over a causal 6-dimensional state space and 4 discrete action tiers.")

st.info("ℹ️ **Policy Role Invariant:** Dueling DQN is an autonomous response policy agent, NOT an intrusion classifier. It recommends mitigation actions based on estimated cumulative returns. Q-values represent expected long-term system value, not probabilities or proof of optimality.")

st.divider()

tab_real, tab_offline = st.tabs(["📡 Real Event-Linked Decisions", "🧪 Offline Policy Inspector"])

with tab_real:
    st.subheader("1. Real Event-Linked Policy Decisions")

    if not events:
        st.info("No security events in memory. Process packets or inject a sample flow to inspect live DQN decisions.")
    else:
        selected_idx = st.selectbox(
            "Select Event for Decision Inspection",
            range(len(events)),
            format_func=lambda i: f"[{events[i].timestamp[:19]}] {events[i].source_ip} (RF: {events[i].detection.get('attack_score', 0.0):.4f}, Proposed: {events[i].response.get('proposed_action', 'ALLOW')}, Enforced: {events[i].response.get('enforced_action', 'ALLOW')})",
        )
        ev = events[selected_idx]
        resp = ev.response

        col_q, col_state = st.columns([1, 1])

        with col_q:
            st.markdown("#### Action Q-Values & Proposed Action")
            q_values = resp.get("q_values", {})
            if q_values:
                q_df = pd.DataFrame([{"Action": k, "Estimated Q-Value": round(v, 4)} for k, v in q_values.items()])
                st.bar_chart(q_df.set_index("Action")["Estimated Q-Value"])
                st.dataframe(q_df, use_container_width=True)

            st.markdown(f"**Proposed Policy Action:** `{resp.get('proposed_action', 'ALLOW')}`")
            st.markdown(f"**Safety Enforced Action:** `{resp.get('enforced_action', 'ALLOW')}`")
            if resp.get("safety_override"):
                st.warning(f"**Safety Gate Override:** {resp.get('override_reason')}")
            else:
                st.success("**Safety Gate:** Approved without modification.")

        with col_state:
            st.markdown("#### 6D Causal State Vector $\\mathbf{s}_t$")
            state_vec = resp.get("state_vector", [])
            if len(state_vec) >= 6:
                state_labels = [
                    ("S_t (Current Attack Score)", state_vec[0], "Continuous Random Forest / hybrid threat probability [0, 1]"),
                    ("ΔS_t (Score Trajectory)", state_vec[1], "First-difference change in threat score from previous step [-1, 1]"),
                    ("N_alert (Rolling Alert Density)", state_vec[2], "Normalized count of recent suspicious alerts from this source [0, 1]"),
                    ("a_{t-1} (Previous Action Taken)", state_vec[3], "Discrete index of last applied action (0=ALLOW, 1=ALERT, 2=RATE_LIMIT, 3=ISOLATE)"),
                    ("c_t (Critical Host Invariant)", state_vec[4], "Binary flag (1.0 = asset matches critical allowlist, 0.0 = standard)"),
                    ("v_t (Vulnerability Exposure)", state_vec[5], "Target host service exposure and vulnerability rating [0, 1]"),
                ]
                s_df = pd.DataFrame([{"State Dimension": l[0], "Value": round(l[1], 4), "Description": l[2]} for l in state_labels])
                st.dataframe(s_df, use_container_width=True)
            else:
                st.markdown(f"`{state_vec}`")

with tab_offline:
    st.subheader("2. Offline Policy Explorer [SIMULATION ONLY]")
    st.caption("Interactive forward pass through the trained DQN model weights. Modifying these sliders simulates policy response curves and does NOT execute any network actions.")

    col_sl1, col_sl2 = st.columns(2)
    with col_sl1:
        s_score = st.slider("Attack Score (S_t)", 0.0, 1.0, 0.85, 0.05)
        s_delta = st.slider("Score Trend (ΔS_t)", -1.0, 1.0, 0.30, 0.05)
        s_alerts = st.slider("Alert Density (N_alert)", 0.0, 1.0, 0.60, 0.05)

    with col_sl2:
        s_prev_act = st.selectbox("Previous Action (a_{t-1})", [0, 1, 2, 3], format_func=lambda a: ["0: ALLOW", "1: ALERT", "2: RATE_LIMIT", "3: ISOLATE"][a])
        s_crit = st.checkbox("Critical Host (c_t = 1.0)", value=False)
        s_vuln = st.slider("Vulnerability Rating (v_t)", 0.0, 1.0, 0.50, 0.05)

    sim_state = np.array([s_score, s_delta, s_alerts, float(s_prev_act), 1.0 if s_crit else 0.0, s_vuln], dtype=np.float32)

    # Compute DQN forward pass
    dqn_service = pipeline.response_service
    q_vals = dqn_service.get_q_values(sim_state)
    best_act_idx = int(np.argmax(q_vals))
    actions_map = [Action.ALLOW, Action.ALERT, Action.RATE_LIMIT, Action.ISOLATE]
    rec_action = actions_map[best_act_idx]

    st.markdown("#### Offline Evaluation Outcome")
    c_res1, c_res2 = st.columns(2)

    with c_res1:
        sim_q_df = pd.DataFrame([{"Action": actions_map[i].name, "Q-Value": round(float(q_vals[i]), 4)} for i in range(len(actions_map))])
        st.bar_chart(sim_q_df.set_index("Action")["Q-Value"])

    with c_res2:
        st.metric("DQN Proposed Action", rec_action.name)
        # Apply safety check
        dummy_ip = "192.168.10.1" if s_crit else "10.200.1.55"
        safety_chk = pipeline.safety_gate.check(action=rec_action, target_host=dummy_ip)
        st.metric("Safety Enforced Action", safety_chk.action.name)
        if safety_chk.is_overridden:
            st.warning(f"Safety Override: {safety_chk.reason}")
        else:
            st.success("Safety Invariants: Passed.")
