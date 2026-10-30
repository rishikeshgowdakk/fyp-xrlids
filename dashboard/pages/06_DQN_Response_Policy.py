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
                    ("S_t (Current Attack Score)", state_vec[0], "Continuous Random Forest / hybrid threat probability [0.0, 1.0] from operational detector"),
                    ("ΔS_t (Score Trajectory)", state_vec[1], "First-difference score velocity relative to recent score history [-1.0, 1.0]"),
                    ("N_alert (Rolling Alert Density)", state_vec[2], "Fraction of past 20 flows exceeding alert threshold (0.50) [0.0, 1.0]"),
                    ("a_{t-1} (Previous Action Taken)", state_vec[3], "Normalized index of previous action (ALLOW=0.0, ALERT=0.333, RATE_LIMIT=0.667, ISOLATE=1.0)"),
                    ("c_t (Remaining Cooldown Fraction)", state_vec[4], "Fraction of 30-step mandatory cooldown timer remaining [0.0, 1.0] before re-trigger"),
                    ("v_t (Normalized Volumetric Scale)", state_vec[5], "Log-scaled flow byte rate: log10(1 + bytes_per_s) / 8.0 [0.0, 1.0] (max 100 MB/s)"),
                ]
                s_df = pd.DataFrame([{"State Dimension": l[0], "Value": round(l[1], 4), "Description": l[2]} for l in state_labels])
                st.dataframe(s_df, use_container_width=True)
            else:
                st.markdown(f"`{state_vec}`")

with tab_offline:
    st.subheader("2. Offline Policy Explorer [SIMULATION ONLY]")
    st.caption("Interactive forward pass through the trained DQN model weights using the verified 6D causal state contract. Modifying these sliders simulates policy response curves and does NOT execute any network actions.")

    col_sl1, col_sl2 = st.columns(2)
    with col_sl1:
        s_score = st.slider("Attack Score (S_t)", 0.0, 1.0, 0.85, 0.05, help="Continuous threat score from ML detector in [0.0, 1.0]")
        s_delta = st.slider("Score Trajectory (ΔS_t)", -1.0, 1.0, 0.20, 0.05, help="Score velocity relative to historical average in [-1.0, 1.0]")
        s_alerts = st.slider("Rolling Alert Density (N_alert)", 0.0, 1.0, 0.50, 0.05, help="Fraction of recent flows exceeding alert threshold in [0.0, 1.0]")

    with col_sl2:
        actions_list = [Action.ALLOW, Action.ALERT, Action.RATE_LIMIT, Action.ISOLATE]
        s_prev_act = st.selectbox(
            "Previous Enforced Action (a_{t-1})",
            actions_list,
            index=0,
            format_func=lambda a: f"{a.value}: {a.name} (normalized: {a.value/3.0:.3f})",
            help="Previous action normalized by / 3.0",
        )
        s_cool_steps = st.slider("Cooldown Steps Remaining (c_t)", 0, 30, 0, 1, help="Fraction of 30-step window: steps / 30.0")
        s_bytes_sec = st.number_input(
            "Flow Byte Rate (bytes/s)",
            min_value=0.0,
            max_value=100000000.0,
            value=1250000.0,
            step=50000.0,
            help="Raw byte rate, normalized via log10(1 + bps) / 8.0 into [0.0, 1.0]",
        )

    # Transform parameters strictly following StateBuilder contract
    s0 = float(np.clip(s_score, 0.0, 1.0))
    s1 = float(np.clip(s_delta, -1.0, 1.0))
    s2 = float(np.clip(s_alerts, 0.0, 1.0))
    s3 = float(s_prev_act.value / 3.0)
    s4 = float(np.clip(s_cool_steps / 30.0, 0.0, 1.0))
    s5 = float(np.clip(np.log10(1.0 + max(0.0, s_bytes_sec)) / 8.0, 0.0, 1.0))

    sim_state = np.array([s0, s1, s2, s3, s4, s5], dtype=np.float32)

    # Compute DQN forward pass
    dqn_service = pipeline.response_service
    q_vals = dqn_service.get_q_values(sim_state)
    best_act_idx = int(np.argmax(q_vals))
    rec_action = actions_list[best_act_idx]

    st.markdown("#### Offline Evaluation Outcome")
    c_res1, c_res2 = st.columns(2)

    with c_res1:
        st.markdown("**Action Q-Values (Expected Returns)**")
        sim_q_df = pd.DataFrame([{"Action": actions_list[i].name, "Q-Value": round(float(q_vals[i]), 4)} for i in range(len(actions_list))])
        st.bar_chart(sim_q_df.set_index("Action")["Q-Value"])
        st.dataframe(sim_q_df, use_container_width=True)

    with c_res2:
        st.markdown("**Policy Recommendation & Deterministic Safety Gate**")
        st.metric("DQN Proposed Action", rec_action.name)
        
        # Asset criticality is tested by the safety gate, NOT injected into DQN state
        is_crit_target = st.checkbox("Target is Protected Critical Host (Gateway/DNS)", value=False, help="Informs the Safety Gate check (192.168.10.1 Core Gateway or 192.168.10.2 DNS)")
        target_ip = "192.168.10.1" if is_crit_target else "10.200.1.55"
        
        safety_chk = pipeline.safety_gate.check(action=rec_action, target_host=target_ip)
        st.metric("Safety Enforced Action", safety_chk.action.name)
        if safety_chk.is_overridden:
            st.warning(f"**Safety Override:** {safety_chk.reason}")
        else:
            st.success("**Safety Invariants:** Passed without override.")

        # Show constructed 6D state table
        sim_state_labels = [
            ("S_t (Current Attack Score)", s0, "Direct RF risk score [0, 1]"),
            ("ΔS_t (Score Trajectory)", s1, "Trajectory delta [-1, 1]"),
            ("N_alert (Rolling Alert Density)", s2, "Recent alert density [0, 1]"),
            ("a_{t-1} (Previous Action Taken)", s3, f"{s_prev_act.name} -> {s3:.3f}"),
            ("c_t (Remaining Cooldown Fraction)", s4, f"{s_cool_steps}/30 -> {s4:.3f}"),
            ("v_t (Normalized Volumetric Scale)", s5, f"{s_bytes_sec:,.0f} B/s -> {s5:.4f}"),
        ]
        st.dataframe(pd.DataFrame([{"Dim": l[0], "Normalized Input": round(l[1], 4), "Raw Transformation": l[2]} for l in sim_state_labels]), use_container_width=True)
