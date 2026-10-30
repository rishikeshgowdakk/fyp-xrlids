"""Page 7: DQN Response Policy & Deterministic Safety Gate (Phase 12).

Visualizes reinforcement learning autonomous response decision-making and safety guarantees:
- Dueling Deep Q-Network (DQN) policy evaluation using models/dqn/dqn_4action_best.pt
- 6D causal state vector construction: [S_t, Delta S_t, N_alert, a_{t-1}, c_t, v_t]
- Q-value bar charts across all 4 discrete actions (ALLOW, ALERT, RATE_LIMIT, ISOLATE)
- Deterministic Safety Gate validation (Critical host exemptions, blast radius limit, dry-run advisory)
"""

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

from xrlids.response.safety import Action, DeterministicSafetyGate, DEFAULT_CRITICAL_HOSTS
from xrlids.response.service import DQNResponseService

st.set_page_config(page_title="Response Policy - XRL-IDARS", page_icon="🤖", layout="wide")

st.title("🤖 DQN Autonomous Response Policy & Safety Gate")
st.markdown("""
Examine the autonomous mitigation tier. XRL-IDARS combines **Reinforcement Learning (Dueling DQN)**
to optimize the trade-off between attack containment and network service availability, protected by a
**Deterministic Safety Gate** that enforces non-negotiable operational invariants.
""")

st.divider()

col_state, col_qval = st.columns([1, 1])

with col_state:
    st.subheader("🎛️ Flow Threat Context & Target Profile")
    st.caption("Adjust flow parameters to observe the RL agent's response policy:")
    
    s_threat = st.slider("Attack Threat Score (S_t)", min_value=0.0, max_value=1.0, value=0.88, step=0.02)
    s_bytes_rate = st.slider("Flow Bytes / sec", min_value=0.0, max_value=2000000.0, value=450000.0, step=10000.0)
    
    actions_map = {
        "ALLOW": Action.ALLOW,
        "ALERT": Action.ALERT,
        "RATE_LIMIT": Action.RATE_LIMIT,
        "ISOLATE": Action.ISOLATE,
    }
    s_prev_act_str = st.selectbox("Previous Action (a_{t-1})", list(actions_map.keys()), index=0)
    s_prev_act = actions_map[s_prev_act_str]
    
    s_cd = st.slider("Cooldown Steps Remaining", min_value=0, max_value=10, value=0)
    
    target_ip = st.text_input("Target IP Address", value="10.0.0.55")
    is_critical_host = st.checkbox("Exempt as Critical Infrastructure (e.g. Domain Controller, DNS)", value=False)

with col_qval:
    st.subheader("📊 Q-Value Action Policy & Verification")
    
    try:
        service = DQNResponseService()
        
        crit_hosts = set(DEFAULT_CRITICAL_HOSTS)
        if is_critical_host:
            crit_hosts.add(target_ip)
            
        safety_gate = DeterministicSafetyGate(critical_hosts=frozenset(crit_hosts))
        
        rec = service.recommend_action(
            attack_score=s_threat,
            flow_bytes_per_s=s_bytes_rate,
            host_id=target_ip,
            last_action=s_prev_act,
            cooldown_remaining=s_cd,
        )
        
        # Verify via Safety Gate
        enforced_act, is_override, override_reason = safety_gate.enforce_safety(
            step=1,
            flow_id="sim-flow-01",
            host_id=target_ip,
            proposed_action=rec.action,
        )
        
        st.metric("Raw DQN Optimal Action", rec.action.name, f"Q = {rec.best_q_value:.3f}")
        
        if is_override:
            st.warning(f"⚠️ SAFETY GATE OVERRIDE: Downgraded to **{enforced_act.name}**\n\n**Reason:** {override_reason}")
        else:
            st.success(f"✅ SAFETY GATE APPROVED: Enforcing **{enforced_act.name}**")

        st.markdown("#### Action Q-Value Distribution $Q(s, a)$")
        q_df = pd.DataFrame([
            {"Action": act_name, "Expected Return Q(s, a)": round(q_val, 4)}
            for act_name, q_val in rec.q_values.items()
        ]).set_index("Action")
        st.bar_chart(q_df)
        
        st.markdown("#### 6D Causal State Vector $\\mathbf{s}_t$")
        st.json(rec.state_components)
        
    except Exception as ex:
        st.error(f"Error evaluating DQN policy: {ex}")

st.divider()

st.subheader("🛡️ Deterministic Safety Invariants")
invariants_data = [
    {
        "Invariant": "Critical Host Exemption",
        "Enforcement": "Hard Block on ISOLATE",
        "Description": "Critical infrastructure IPs (e.g., DNS, default gateways, auth servers) can never be isolated, preventing self-inflicted denial of service.",
        "Status": "ACTIVE",
    },
    {
        "Invariant": "Blast Radius Upper Bound",
        "Enforcement": "Max 5% Network Partition",
        "Description": "Limits simultaneous isolations across subnets to prevent cascading disruption during massive distributed scans.",
        "Status": "ACTIVE",
    },
    {
        "Invariant": "Cooldown Suppression",
        "Enforcement": "30-Second Min Delay",
        "Description": "Enforces minimum dampening interval between state transitions on the same target host to prevent action thrashing.",
        "Status": "ACTIVE",
    },
    {
        "Invariant": "Advisory Dry-Run Default",
        "Enforcement": "Zero Kernel Mutations",
        "Description": "All mitigation actions are logged and audited in dry-run advisory mode unless explicit operator confirmation enables enforcement.",
        "Status": "ACTIVE (SAFE)",
    },
]
st.dataframe(pd.DataFrame(invariants_data), use_container_width=True)
