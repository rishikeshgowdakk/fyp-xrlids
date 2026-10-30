"""Page 1: System Overview & Animated Architecture — XRL-IDARS."""

from __future__ import annotations

from pathlib import Path
import sys
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from dashboard.session_init import ensure_session_state
from xrlids.events.manager import EventManager
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline

st.set_page_config(page_title="Overview - XRL-IDARS", page_icon="🛡️", layout="wide")

event_mgr, pipeline, live_mgr = ensure_session_state()

st.title("🛡️ XRL-IDARS — System Overview & Architecture")
st.markdown("""
**Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)**  
A defense platform combining sub-millisecond Random Forest perception on 10 deterministic flow statistics ($R_{10}$), exact local TreeSHAP attribution, and a causal 6-dimensional Dueling Deep Q-Network (DQN) response policy governed by an inviolable deterministic safety shield and asynchronous PostgreSQL event persistence.
""")

st.divider()

# ---------------------------------------------------------------------------
# Section 1: Interactive Animated Operational Architecture Flowchart
# ---------------------------------------------------------------------------
st.subheader("1. Animated End-to-End Operational Pipeline")
st.caption("Live dataflow showing packet ingestion, ML perception, TreeSHAP explanation, DQN response recommendation, deterministic shielding, and asynchronous persistence.")

animated_architecture_html = """
<!DOCTYPE html>
<html>
<head>
<style>
  body {
    margin: 0;
    padding: 0;
    background-color: #0b1120;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #e2e8f0;
    overflow-x: auto;
  }
  .svg-container {
    width: 100%;
    min-width: 980px;
    height: 420px;
    display: flex;
    justify-content: center;
    align-items: center;
  }
  /* Animation path pulsing */
  @keyframes flowDash {
    to {
      stroke-dashoffset: -40;
    }
  }
  @keyframes pulseGlow {
    0%, 100% { filter: drop-shadow(0 0 3px #38bdf8); }
    50% { filter: drop-shadow(0 0 10px #38bdf8); }
  }
  @keyframes pulseGlowGreen {
    0%, 100% { filter: drop-shadow(0 0 3px #10b981); }
    50% { filter: drop-shadow(0 0 10px #10b981); }
  }
  @keyframes pulseGlowAmber {
    0%, 100% { filter: drop-shadow(0 0 3px #f59e0b); }
    50% { filter: drop-shadow(0 0 10px #f59e0b); }
  }
  .flow-line {
    stroke: #38bdf8;
    stroke-width: 2.5;
    stroke-dasharray: 6, 6;
    animation: flowDash 1.2s linear infinite;
    fill: none;
  }
  .flow-line-async {
    stroke: #10b981;
    stroke-width: 2.5;
    stroke-dasharray: 6, 6;
    animation: flowDash 1.6s linear infinite;
    fill: none;
  }
  .flow-line-rules {
    stroke: #f59e0b;
    stroke-width: 2.0;
    stroke-dasharray: 4, 4;
    animation: flowDash 1.8s linear infinite;
    fill: none;
  }
  .node-box {
    rx: 8;
    ry: 8;
    stroke-width: 1.5;
    transition: all 0.2s ease;
  }
  .node-title {
    font-size: 11px;
    font-weight: 700;
    text-anchor: middle;
    letter-spacing: 0.03em;
  }
  .node-sub {
    font-size: 9.5px;
    font-weight: 400;
    fill: #94a3b8;
    text-anchor: middle;
  }
  .badge-tag {
    font-size: 8.5px;
    font-weight: 700;
    text-anchor: middle;
  }
</style>
</head>
<body>
<div class="svg-container">
<svg viewBox="0 0 1000 420" width="100%" height="420" xmlns="http://www.w3.org/2000/svg">
  <defs>
    <linearGradient id="gradIngest" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#1e293b"/>
      <stop offset="100%" stop-color="#0f172a"/>
    </linearGradient>
    <linearGradient id="gradRF" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#0369a1"/>
      <stop offset="100%" stop-color="#075985"/>
    </linearGradient>
    <linearGradient id="gradDQN" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#4338ca"/>
      <stop offset="100%" stop-color="#3730a3"/>
    </linearGradient>
    <linearGradient id="gradSafety" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#b45309"/>
      <stop offset="100%" stop-color="#78350f"/>
    </linearGradient>
    <linearGradient id="gradPG" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#065f46"/>
      <stop offset="100%" stop-color="#064e3b"/>
    </linearGradient>
    <marker id="arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/>
    </marker>
    <marker id="arrowGreen" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#10b981"/>
    </marker>
  </defs>

  <!-- Flow Paths -->
  <!-- 1. Input to FlowEngine -->
  <path d="M 120 75 L 160 75" class="flow-line" marker-end="url(#arrow)"/>
  <!-- 2. FlowEngine to Feature Extractor -->
  <path d="M 280 75 L 320 75" class="flow-line" marker-end="url(#arrow)"/>
  <!-- 3. Feature Extractor to RF and Rules -->
  <path d="M 440 75 L 480 75" class="flow-line" marker-end="url(#arrow)"/>
  <path d="M 380 105 L 380 155 L 480 155" class="flow-line-rules" marker-end="url(#arrow)"/>
  <!-- 4. RF & Rules to Hybrid Arbitration -->
  <path d="M 600 75 L 640 75" class="flow-line" marker-end="url(#arrow)"/>
  <path d="M 600 155 L 620 155 L 620 90 L 640 90" class="flow-line-rules" marker-end="url(#arrow)"/>
  <!-- 5. Hybrid to TreeSHAP -->
  <path d="M 760 75 L 800 75" class="flow-line" marker-end="url(#arrow)"/>
  
  <!-- Row 2 Flow Paths -->
  <!-- TreeSHAP down to StateBuilder -->
  <path d="M 860 105 L 860 215 L 820 215" class="flow-line" marker-end="url(#arrow)"/>
  <!-- StateBuilder to Dueling DQN -->
  <path d="M 700 215 L 660 215" class="flow-line" marker-end="url(#arrow)"/>
  <!-- Dueling DQN to Safety Gate -->
  <path d="M 540 215 L 500 215" class="flow-line" marker-end="url(#arrow)"/>
  <!-- Safety Gate to Advisory Actuator -->
  <path d="M 380 215 L 340 215" class="flow-line" marker-end="url(#arrow)"/>
  <!-- Advisory Actuator to Event Manager -->
  <path d="M 220 215 L 180 215" class="flow-line" marker-end="url(#arrow)"/>

  <!-- Row 3: Dispatch & Persistence -->
  <!-- Event Manager to Streamlit Dashboard -->
  <path d="M 120 245 L 120 315 L 160 315" class="flow-line" marker-end="url(#arrow)"/>
  <!-- Event Manager to Asynchronous Worker & PostgreSQL (Dashed Branch) -->
  <path d="M 120 245 L 120 375 L 380 375" class="flow-line-async" marker-end="url(#arrowGreen)"/>
  <path d="M 540 375 L 640 375" class="flow-line-async" marker-end="url(#arrowGreen)"/>
  <path d="M 800 375 L 860 375" class="flow-line-async" marker-end="url(#arrowGreen)"/>

  <!-- NODES ROW 1 (Perception & Attribution) -->
  <!-- 1. Input Sources -->
  <g transform="translate(10, 45)">
    <rect class="node-box" width="110" height="60" fill="url(#gradIngest)" stroke="#38bdf8"/>
    <text class="node-title" x="55" y="24" fill="#38bdf8">WIRE / PCAP</text>
    <text class="node-sub" x="55" y="40">Scapy Capture</text>
    <text class="node-sub" x="55" y="52">Raw Sockets / Lab</text>
  </g>

  <!-- 2. Canonical FlowEngine -->
  <g transform="translate(160, 45)">
    <rect class="node-box" width="120" height="60" fill="url(#gradIngest)" stroke="#38bdf8"/>
    <text class="node-title" x="60" y="24" fill="#f8fafc">FLOW ENGINE</text>
    <text class="node-sub" x="60" y="40">Min&lt;Max 5-Tuple</text>
    <text class="node-sub" x="60" y="52">120s / FIN / RST</text>
  </g>

  <!-- 3. R10 Feature Extraction -->
  <g transform="translate(320, 45)">
    <rect class="node-box" width="120" height="60" fill="url(#gradIngest)" stroke="#38bdf8"/>
    <text class="node-title" x="60" y="24" fill="#f8fafc">R10 FEATURES</text>
    <text class="node-sub" x="60" y="40">10 Stats Moments</text>
    <text class="node-sub" x="60" y="52">StandardScaler</text>
  </g>

  <!-- 4. Random Forest (Operational ML) -->
  <g transform="translate(480, 45)">
    <rect class="node-box" width="120" height="60" fill="url(#gradRF)" stroke="#38bdf8" style="animation: pulseGlow 2.5s infinite;"/>
    <text class="node-title" x="60" y="24" fill="#ffffff">RANDOM FOREST</text>
    <text class="node-sub" x="60" y="40" fill="#e0f2fe">Sole Live ML (&lt;0.8ms)</text>
    <text class="badge-tag" x="60" y="52" fill="#7dd3fc">F1 = 0.9512</text>
  </g>

  <!-- 4b. Deterministic Rules -->
  <g transform="translate(480, 125)">
    <rect class="node-box" width="120" height="60" fill="url(#gradIngest)" stroke="#f59e0b" style="animation: pulseGlowAmber 3s infinite;"/>
    <text class="node-title" x="60" y="24" fill="#fbbf24">RULE ENGINE</text>
    <text class="node-sub" x="60" y="40">RFC 793/1122</text>
    <text class="node-sub" x="60" y="52">SYN / ICMP / Scan</text>
  </g>

  <!-- 5. Hybrid Arbitration -->
  <g transform="translate(640, 45)">
    <rect class="node-box" width="120" height="60" fill="url(#gradIngest)" stroke="#38bdf8"/>
    <text class="node-title" x="60" y="24" fill="#f8fafc">HYBRID VERDICT</text>
    <text class="node-sub" x="60" y="40">Risk Arbitration</text>
    <text class="node-sub" x="60" y="52">Source Activity</text>
  </g>

  <!-- 6. TreeSHAP Explainer -->
  <g transform="translate(800, 45)">
    <rect class="node-box" width="120" height="60" fill="url(#gradIngest)" stroke="#38bdf8"/>
    <text class="node-title" x="60" y="24" fill="#38bdf8">TreeSHAP</text>
    <text class="node-sub" x="60" y="40">Local Attributions</text>
    <text class="node-sub" x="60" y="52">Explains RF Model</text>
  </g>

  <!-- NODES ROW 2 (Autonomous Response & Safety Gate) -->
  <!-- 7. Causal 6D StateBuilder -->
  <g transform="translate(700, 185)">
    <rect class="node-box" width="120" height="60" fill="url(#gradIngest)" stroke="#818cf8"/>
    <text class="node-title" x="60" y="24" fill="#a5b4fc">6D StateBuilder</text>
    <text class="node-sub" x="60" y="40">[St, ΔSt, N_alert,</text>
    <text class="node-sub" x="60" y="52">at-1, ct, vt]</text>
  </g>

  <!-- 8. Dueling DQN -->
  <g transform="translate(540, 185)">
    <rect class="node-box" width="120" height="60" fill="url(#gradDQN)" stroke="#818cf8" style="animation: pulseGlow 2.5s infinite;"/>
    <text class="node-title" x="60" y="24" fill="#ffffff">DUELING DQN</text>
    <text class="node-sub" x="60" y="40" fill="#e0e7ff">Response Policy</text>
    <text class="badge-tag" x="60" y="52" fill="#c7d2fe">4 Actions (Q-Values)</text>
  </g>

  <!-- 9. Deterministic Safety Gate -->
  <g transform="translate(380, 185)">
    <rect class="node-box" width="120" height="60" fill="url(#gradSafety)" stroke="#f59e0b" style="animation: pulseGlowAmber 2.5s infinite;"/>
    <text class="node-title" x="60" y="24" fill="#ffffff">SAFETY GATE</text>
    <text class="node-sub" x="60" y="40" fill="#fef3c7">Inviolable Shield</text>
    <text class="node-sub" x="60" y="52" fill="#fef3c7">Cooldown / 5% Blast</text>
  </g>

  <!-- 10. Advisory Actuator -->
  <g transform="translate(220, 185)">
    <rect class="node-box" width="120" height="60" fill="url(#gradIngest)" stroke="#94a3b8"/>
    <text class="node-title" x="60" y="24" fill="#f8fafc">ACTUATOR</text>
    <text class="node-sub" x="60" y="40">Advisory / Dry-Run</text>
    <text class="node-sub" x="60" y="52">0 Host Mutations</text>
  </g>

  <!-- 11. Security Event Manager -->
  <g transform="translate(60, 185)">
    <rect class="node-box" width="120" height="60" fill="url(#gradIngest)" stroke="#38bdf8"/>
    <text class="node-title" x="60" y="24" fill="#38bdf8">EVENT MANAGER</text>
    <text class="node-sub" x="60" y="40">Ring Buffer (5k)</text>
    <text class="node-sub" x="60" y="52">Publish &amp; Subscribe</text>
  </g>

  <!-- NODES ROW 3 (UI & Persistent Storage Subsystems) -->
  <!-- 12. Streamlit Dashboard -->
  <g transform="translate(160, 290)">
    <rect class="node-box" width="180" height="50" fill="url(#gradIngest)" stroke="#38bdf8"/>
    <text class="node-title" x="90" y="22" fill="#38bdf8">STREAMLIT SOC DASHBOARD</text>
    <text class="node-sub" x="90" y="38">Overview · Live Demo · Benchmarks</text>
  </g>

  <!-- 13. Asynchronous Worker (Dashed Non-Blocking Branch) -->
  <g transform="translate(380, 350)">
    <rect class="node-box" width="160" height="50" fill="url(#gradIngest)" stroke="#10b981"/>
    <text class="node-title" x="80" y="20" fill="#34d399">ASYNC QUEUE WORKER</text>
    <text class="node-sub" x="80" y="36">Bounded Queue (10k) · Batch</text>
  </g>

  <!-- 14. PostgreSQL Database -->
  <g transform="translate(640, 350)">
    <rect class="node-box" width="160" height="50" fill="url(#gradPG)" stroke="#10b981" style="animation: pulseGlowGreen 3s infinite;"/>
    <text class="node-title" x="80" y="20" fill="#ffffff">POSTGRESQL DATABASE</text>
    <text class="node-sub" x="80" y="36" fill="#a7f3d0">Table: security_events (21 Cols)</text>
  </g>

  <!-- 15. Secondary JSONL -->
  <g transform="translate(860, 350)">
    <rect class="node-box" width="120" height="50" fill="url(#gradIngest)" stroke="#64748b"/>
    <text class="node-title" x="60" y="20" fill="#94a3b8">JSONL AUDIT</text>
    <text class="node-sub" x="60" y="36">Independent Log</text>
  </g>

  <!-- Clarification Banner in SVG -->
  <rect x="420" y="325" width="460" height="18" rx="4" fill="#0f172a" stroke="#10b981" stroke-width="0.8"/>
  <text x="650" y="338" font-size="9" fill="#10b981" font-weight="600" text-anchor="middle">
    Asynchronous Persistence Branch (O(1) Enqueue) — Non-Blocking &amp; Decoupled from Detection Path
  </text>
</svg>
</div>
</body>
</html>
"""
components.html(animated_architecture_html, height=430)

st.divider()

# ---------------------------------------------------------------------------
# Section 2: Pipeline Stage Dictionary & Performance Contracts
# ---------------------------------------------------------------------------
st.subheader("2. Operational Pipeline Stage Specifications")

pipeline_table = [
    {
        "Stage": "1. Packet Ingestion",
        "Subsystem": "Scapy Ingestion Engine",
        "Role": "Wire packet sniffing via raw sockets or PCAP stream parsing.",
        "Input / Output": "Raw L2/L3 frames → PacketInfo metadata",
        "Execution Latency": "~0.05 ms / pkt",
        "Operational Invariant": "Live packet ingestion is strictly non-blocking.",
    },
    {
        "Stage": "2. Flow Aggregation",
        "Subsystem": "Canonical FlowEngine",
        "Role": "Assembles packets into bidirectional flows keyed by sorted min<max 5-tuple.",
        "Input / Output": "Packet sequence → CanonicalFlow object",
        "Execution Latency": "0.012 ms / flow",
        "Operational Invariant": "Emits on TCP FIN/RST or 120s sliding window timeout.",
    },
    {
        "Stage": "3. Feature Extraction",
        "Subsystem": "R10 Statistical Contract",
        "Role": "Computes 10 standardized flow statistical moments and applies StandardScaler.",
        "Input / Output": "Flow packets → 10D Float Vector",
        "Execution Latency": "0.025 ms / flow",
        "Operational Invariant": "Strict feature ordering frozen in definitions.py.",
    },
    {
        "Stage": "4. ML Intrusion Detection",
        "Subsystem": "Random Forest Champion",
        "Role": "Sole operational ML detector. Evaluates flow threat probability P(ATTACK).",
        "Input / Output": "Standardized R10 vector → Threat Score ∈ [0.0, 1.0]",
        "Execution Latency": "0.78 ms / flow",
        "Operational Invariant": "F1 = 0.9512; operates statelessly to resist state exhaustion.",
    },
    {
        "Stage": "5. Deterministic Rules",
        "Subsystem": "RFC 793/1122 RuleEngine",
        "Role": "Deterministic protocol violation checking (SYN flood, ICMP flood, Port Scan).",
        "Input / Output": "Header flags & rates → Rule matches",
        "Execution Latency": "0.004 ms / flow",
        "Operational Invariant": "Runs in parallel; cannot be suppressed by low RF scores.",
    },
    {
        "Stage": "6. Decision Arbitration",
        "Subsystem": "Hybrid Arbiter & Tracker",
        "Role": "Blends ML score, rule matches, and sliding-window source IP activity.",
        "Input / Output": "Perception outputs → Hybrid Verdict & Risk Score",
        "Execution Latency": "0.005 ms / flow",
        "Operational Invariant": "BENIGN, RF, RULE, or HYBRID verdict assigned.",
    },
    {
        "Stage": "7. Local Explainability",
        "Subsystem": "TreeSHAP Explainer",
        "Role": "Computes exact Shapley attributions explaining why RF scored the flow.",
        "Input / Output": "RF Trees + Features → Feature Attributions (φi)",
        "Execution Latency": "1.82 ms / flow",
        "Operational Invariant": "Explains Random Forest prediction, distinct from RL decision.",
    },
    {
        "Stage": "8. State Construction",
        "Subsystem": "6D Causal StateBuilder",
        "Role": "Constructs Markov state: [St, ΔSt, N_alert, at-1, ct, vt].",
        "Input / Output": "History & Threat → 6D Box Vector",
        "Execution Latency": "0.008 ms / flow",
        "Operational Invariant": "Dimensionality strictly matches DQN training contract.",
    },
    {
        "Stage": "9. Response Optimization",
        "Subsystem": "Dueling Deep Q-Network",
        "Role": "Evaluates expected returns across ALLOW, ALERT, RATE_LIMIT, ISOLATE.",
        "Input / Output": "6D State Vector → Action Q-Values & Proposed Action",
        "Execution Latency": "0.18 ms / decision",
        "Operational Invariant": "Q-values represent expected return, not probabilities.",
    },
    {
        "Stage": "10. Invariant Shielding",
        "Subsystem": "Deterministic Safety Gate",
        "Role": "Enforces critical host exemptions, 30s cooldowns, and 5% blast-radius limit.",
        "Input / Output": "Proposed Action → Authorized Enforced Action",
        "Execution Latency": "0.001 ms / check",
        "Operational Invariant": "Inviolable software shield; overrides unsafe recommendations.",
    },
    {
        "Stage": "11. Action Actuation",
        "Subsystem": "Advisory Actuator",
        "Role": "Generates verified execution audit records without mutating host firewall.",
        "Input / Output": "Authorized Action → Verified Execution Report",
        "Execution Latency": "0.015 ms / action",
        "Operational Invariant": "ADVISORY dry-run guarantee: zero host network disruption.",
    },
    {
        "Stage": "12. Event Dispatching",
        "Subsystem": "Security Event Manager",
        "Role": "Thread-safe event publishing, in-memory ring buffer, and persistence routing.",
        "Input / Output": "SecurityEvent → Memory Buffer (5k) + Dispatched",
        "Execution Latency": "0.002 ms / event",
        "Operational Invariant": "Ring buffer provides immediate reactivity for UI feeds.",
    },
    {
        "Stage": "13. Database Persistence",
        "Subsystem": "PostgreSQL Async Worker",
        "Role": "Bounded asynchronous worker queue persisting complete JSONB event records.",
        "Input / Output": "Event Queue → PostgreSQL security_events Table",
        "Execution Latency": "O(1) Enqueue (<0.001 ms)",
        "Operational Invariant": "Database latency or outages never stall packet ingestion.",
    },
]

st.dataframe(pd.DataFrame(pipeline_table), use_container_width=True)

st.divider()

# ---------------------------------------------------------------------------
# Section 3: Model Provenance & Separation of Responsibilities
# ---------------------------------------------------------------------------
col_p1, col_p2 = st.columns([1, 1])

with col_p1:
    st.subheader("Operational Champion Models")
    st.markdown("""
    - **Operational ML Detector (Perception):**
      - Model: Random Forest (`models/rf/random_forest_cicids2017.joblib`)
      - Contract: Canonical $R_{10}$ (10 features)
      - Performance: **$F_1 = 0.9512$**, Accuracy = $99.06\\%$, Latency = $0.78\\,\\text{ms}$
      - Role: **Sole live operational ML detector** for packet sniffing and streaming replay.
    
    - **Autonomous Response Policy (Decision):**
      - Model: Dueling Deep Q-Network (`models/dqn/dqn_4action_best.pt`)
      - State Contract: 6D Causal Markov State Vector
      - Action Space: 4 Actions (`ALLOW`, `ALERT`, `RATE_LIMIT`, `ISOLATE`)
      - Role: Recommends cost-optimal response under deterministic safety gate.
    """)

with col_p2:
    st.subheader("Offline Research Benchmarks")
    st.markdown("""
    - **PyTorch LSTM FlowSeq Sequence Model:**
      - Artifact: `models/lstm/` (`EXP-P2-LSTM-VALID-001`)
      - Contract: $5 \\times 11$ temporal sequences
      - Status: **Offline research benchmark only**. Never invoked live.
    
    - **Convex RF–LSTM Score Fusion Model:**
      - Weights: $\\alpha = 0.70$ RF, $1 - \\alpha = 0.30$ LSTM (`models/fusion/`)
      - Status: **Offline research benchmark only**.
    
    - **XGBoost High-Throughput Baseline:**
      - Model: `models/xgboost/` (Candidate baseline, $F_1 = 0.9521$)
      - Status: **Offline benchmark only**.
    """)

st.info("ℹ️ **Scientific Separation of Concerns:** Random Forest performs intrusion perception. Dueling DQN optimizes mitigation decisions. TreeSHAP explains the Random Forest detector's local feature attributions. The deterministic safety gate guarantees critical host protection and zero host firewall mutations.")
