# XRL-IDARS Operational Dashboard — Acceptance Screenshots

Automated, high-fidelity browser screenshots captured from the running Streamlit operational dashboard (`dashboard/streamlit_app.py`) via Chrome DevTools Protocol (CDP) on headless Google Chrome 156 at a standard desktop viewport (1440 × 960).

**Repository:** `https://github.com/rishikeshgowdakk/fyp-xrlids`  
**Integration Branch:** `feature/final-acceptance-integration`  
**Timestamp:** `2026-10-30T17:54:42Z` (2026-10-30 23:24:42 IST)  
**Host Environment:** Ubuntu Linux, Python 3.14.4, Scapy 2.7.0, PyTorch 2.10.0, Streamlit 1.54.0

---

## Screenshot Evidence Manifest

| # | Filename | Page Name | Active Mode | Test Input / Data Source | What It Proves | Known Limitations |
|---|---|---|---|---|---|---|
| 01 | `01_overview.png` | System Overview & Architecture | OPERATIONAL | Active pipeline state & latency matrix | Proves end-to-end 4-tier pipeline architecture, sub-millisecond Random Forest primary detector role, TreeSHAP explainer, and Dueling DQN response engine under deterministic safety invariants. | Overview displays frozen architecture specification; interactive controls are on sub-pages. |
| 02 | `02_live_monitor_blocked.png` | Live Monitor | BLOCKED (Factual) | Local `lo` loopback interface attempt | Proves genuine permission boundary handling: unprivileged raw socket capture is factually flagged as `BLOCKED` with explicit error diagnostics without crashing background threads or faking live packets. | Raw packet capture on physical interfaces requires root or Linux `CAP_NET_RAW` capability. |
| 03 | `03_pcap_replay_active.png` | Packet & Flow Ingestion | PCAP REPLAY | `data/demo/sample_traffic.pcap` (42 packets) | Proves authentic PCAP replay through Canonical 5-Tuple FlowBuilder, FIN/RST bidirectional aggregation, and deterministic R10 feature vector extraction. | Replay speed is constrained by disk I/O and flow expiration timeouts. |
| 04 | `04_sample_evaluation.png` | Packet & Flow Ingestion | SAMPLE EVAL | Scenario C (TCP SYN Flood Burst, 60 pkts) | Proves genuine Scapy packet generation in isolated lab subnet, asymmetric TCP flag synthesis, and real-time flow reconstruction. | Synthetic packets are bound to isolated RFC-1918 addresses (`10.200.1.0/24`). |
| 05 | `05_detection_events.png` | Detection & Security Events | HYBRID OPERATIONAL | Unified Event Buffer (8 flows evaluated) | Proves single unified `SecurityEvent` schema linking Random Forest score, deterministic rule violations, TreeSHAP attribution, and DQN response decision to the same `flow_id`. | Rolling memory buffer retains the most recent 1,000 security events. |
| 06 | `06_treeshap_explainability.png` | TreeSHAP Local Explainability | OPERATIONAL | Evaluated attack flow (SYN flood / DoS) | Proves exact local Shapley feature attributions ($E[f(x)] + \sum \phi_i = f(x)$) computed via Lundberg & Lee TreeSHAP with feature attribution waterfall chart. | TreeSHAP computation introduces 35–45 ms attribution latency per explained flow. |
| 07 | `07_dqn_response_policy.png` | DQN Response Policy | ADVISORY | Live security events & 6D causal state vector | Proves Dueling DQN evaluates 6D state $s_t = [S_t, \Delta S_t, N_{\text{alert}}, a_{t-1}, c_t, v_t]$ to output Q-values across 4 discrete actions (`ALLOW`, `ALERT`, `RATE_LIMIT`, `ISOLATE`). | DQN functions as a response optimization policy, not an intrusion classifier. |
| 08 | `08_safety_execution_audit.png` | Safety & Execution Audit | ADVISORY (DRY-RUN) | Mission-critical traffic & high-rate attacks | Proves deterministic safety invariants: 100% gateway/DNS critical host protection, 30s rate-limit cooldown, 5% blast-radius circuit breaker, and 0 kernel mutations. | Live actuator is frozen in dry-run mode; zero host firewall mutations are executed. |
| 09 | `09_model_evaluation.png` | Model Evaluation & Validation | BENCHMARK | CSE-CIC-IDS2017 & 2018 held-out test sets | Proves primary Random Forest detector achieves 99.06% accuracy, 0.9512 F1-score, 0.9989 ROC-AUC, and < 0.80 ms CPU inference latency on 355,865 test flows. | Evaluated on frozen academic benchmark datasets; distribution shifts in new enterprise networks require domain fine-tuning. |
| 10 | `10_research_benchmarks.png` | Offline Research Benchmarks | RESEARCH (OFFLINE) | PyTorch LSTM sequence & RF-LSTM fusion | Proves explicit scientific separation: pretrained LSTM sequence model and RF-LSTM convex fusion are preserved exclusively for comparative research and are NEVER invoked live. | Sequential LSTM inference exhibits 22.1 ms latency on CPU, exceeding the 1.0 ms live wire budget. |
| 11 | `11_system_health.png` | System Health & Integrity | OPERATIONAL | Local host runtime & 25 model artifacts | Proves SHA-256 cryptographic integrity across all model weights, verifies zero kernel mutations (`iptables`/`nftables`), and reports Linux capability status. | Host lacks `CAP_NET_RAW`, safely restricting live packet capture to PCAP replay and synthetic sample modes. |
