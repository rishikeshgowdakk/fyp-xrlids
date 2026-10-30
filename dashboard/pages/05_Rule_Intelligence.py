"""Page 5: Rule Intelligence & Hybrid Arbitration (Phase 12).

Visualizes deterministic protocol rules, signature detection, and hybrid arbitration:
- Complete RFC 793/1122 deterministic rule catalog
- Interactive rule evaluation simulator
- Discrepancy matrix and hybrid arbitration logic
- Real-time rule match telemetry
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

from xrlids.rules.engine import RuleEngine
from xrlids.rules.hybrid import HybridDecisionEngine

st.set_page_config(page_title="Rule Intelligence - XRL-IDARS", page_icon="📜", layout="wide")

st.title("📜 Rule Intelligence & Hybrid Arbitration")
st.markdown("""
Inspect the deterministic protocol validation layer. While statistical machine learning excels at detecting
subtle traffic distribution anomalies, **protocol invariants (RFC 793 / RFC 1122)** provide mathematically guaranteed
zero-false-negative detection for illegal TCP flag combinations and abnormal connection states.
""")

st.divider()

st.subheader("📋 Canonical Deterministic Rule Catalog")
rules_catalog = [
    {
        "Rule ID": "RULE-TCP-NULL",
        "Name": "Null Scan Detection",
        "RFC Standard": "RFC 793 §3.9",
        "Invariant Condition": "syn=0, ack=0, rst=0, fin=0",
        "Severity": "HIGH",
        "Attack Pattern": "Stealth OS fingerprinting & firewall evasion",
    },
    {
        "Rule ID": "RULE-TCP-XMAS",
        "Name": "Xmas Scan Detection",
        "RFC Standard": "RFC 793 §3.9",
        "Invariant Condition": "fin=1, psh=1, urg=1 (syn=0, ack=0)",
        "Severity": "HIGH",
        "Attack Pattern": "Nmap stealth Xmas reconnaissance scan",
    },
    {
        "Rule ID": "RULE-TCP-SYN-FLOOD",
        "Name": "SYN Flood Invariant",
        "RFC Standard": "RFC 4987",
        "Invariant Condition": "syn_ack_ratio > 10.0, syn >= 50, ack == 0",
        "Severity": "CRITICAL",
        "Attack Pattern": "Half-open TCP state exhaustion DDoS",
    },
    {
        "Rule ID": "RULE-TCP-FIN-ALONE",
        "Name": "Orphan FIN Scan",
        "RFC Standard": "RFC 793 §3.5",
        "Invariant Condition": "fin=1 without preceding SYN/ACK handshake",
        "Severity": "MEDIUM",
        "Attack Pattern": "Subversive port sweep bypassing naive packet filters",
    },
    {
        "Rule ID": "RULE-TCP-LAND",
        "Name": "LAND Attack Invariant",
        "RFC Standard": "RFC 1122",
        "Invariant Condition": "src_ip == dst_ip and src_port == dst_port",
        "Severity": "CRITICAL",
        "Attack Pattern": "Self-referential loop resource exhaustion",
    },
]
st.dataframe(pd.DataFrame(rules_catalog), use_container_width=True)

st.divider()

col_sim, col_arb = st.columns([1, 1])

with col_sim:
    st.subheader("🧪 Interactive Rule Engine Simulator")
    st.caption("Inject packet flags and flow metrics into the deterministic rule engine:")
    
    sim_syn = st.slider("SYN Flags", 0, 100, 80)
    sim_ack = st.slider("ACK Flags", 0, 100, 0)
    sim_rst = st.slider("RST Flags", 0, 20, 0)
    sim_fin = st.slider("FIN Flags", 0, 20, 0)
    sim_dur = st.number_input("Flow Duration (ms)", value=250.0, min_value=0.0)
    
    ratio = float(sim_syn) if sim_ack == 0 else float(sim_syn) / float(sim_ack)
    st.metric("Computed SYN/ACK Ratio", f"{ratio:.2f}")

    sim_features = {
        "flow_duration_ms": sim_dur,
        "flow_packets_per_s": float(sim_syn + sim_ack) / max(0.001, sim_dur / 1000.0),
        "flow_bytes_per_s": 50000.0,
        "packet_length_mean": 60.0,
        "packet_length_std": 0.0,
        "syn_count": float(sim_syn),
        "ack_count": float(sim_ack),
        "rst_count": float(sim_rst),
        "fin_count": float(sim_fin),
        "syn_ack_ratio": ratio,
    }

    if st.button("⚡ Evaluate Protocol Invariants", type="primary"):
        engine = RuleEngine()
        matches = engine.evaluate_features(sim_features, endpoints={"src_ip": "10.0.0.1", "dst_ip": "192.168.1.1"})
        
        if matches:
            st.error(f"🚨 Rule Violations Detected: {len(matches)} match(es)")
            for m in matches:
                st.markdown(f"- **{m.rule_name}** (`{m.rule_id}`): Severity **{m.severity.name}**\n  _{m.description}_")
        else:
            st.success("✅ Clean Traffic: No protocol invariants violated.")

with col_arb:
    st.subheader("⚖️ Hybrid Arbitration Truth Matrix")
    st.caption("How XRL-IDARS reconciles statistical models and deterministic rules:")
    
    matrix_data = [
        {"ML Perception": "P(ATTACK) < 0.50", "Rule Engine": "Clean (No Violations)", "Arbitrated Verdict": "BENIGN", "Severity": "INFO", "Primary Source": "ML_MODEL"},
        {"ML Perception": "P(ATTACK) >= 0.50", "Rule Engine": "Clean (No Violations)", "Arbitrated Verdict": "ATTACK", "Severity": "MEDIUM", "Primary Source": "ML_MODEL"},
        {"ML Perception": "P(ATTACK) < 0.50", "Rule Engine": "Violation Detected", "Arbitrated Verdict": "ATTACK", "Severity": "HIGH", "Primary Source": "DETERMINISTIC_RULE ⚠️"},
        {"ML Perception": "P(ATTACK) >= 0.50", "Rule Engine": "Violation Detected", "Arbitrated Verdict": "ATTACK", "Severity": "CRITICAL", "Primary Source": "HYBRID_CONSENSUS 🚨"},
    ]
    st.dataframe(pd.DataFrame(matrix_data), use_container_width=True)

    st.markdown("""
    #### Architectural Guarantees:
    1. **Safety Floor:** If a deterministic rule triggers (e.g., illegal TCP state), the arbitrated verdict is **forced to ATTACK** with minimum severity `HIGH`, regardless of ML prediction.
    2. **Consensus Escalation:** When both statistical ML and deterministic rules flag an attack, the severity escalates to **CRITICAL**, raising the causal state for the response policy.
    """)
