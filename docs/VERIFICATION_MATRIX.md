# XRL-IDARS — Master Subsystem Verification Matrix

**Repository:** `https://github.com/rishikeshgowdakk/fyp-xrlids`  
**Git HEAD:** `b08fea1` (ancestor commit: `ee2afca`)  
**Evaluation Date:** October 30, 2026  
**Test Suite Execution:** **623 passed, 0 failed, 18 warnings in 71.29s (100% pass)**  
**Environment:** Linux (x86_64), Python 3.14.4 / PyTorch 2.14.0+cpu / Scikit-Learn 1.9.1 / XGBoost 3.1.0 / Scapy 2.8.0 / SHAP 0.52.0  

---

## 1. Subsystem Verification Matrix

Statuses strictly follow the engineering taxonomy:
`NOT STARTED` · `IN PROGRESS` · `IMPLEMENTED` · `TESTED` · `VALIDATED` · `INTEGRATED` · `BLOCKED`

| Component ID | Subsystem Name | Implementation Status | Test Status | Validation Status | Runtime Integration | Documentation Status | Outstanding Limitations | Verification Command & Evidence |
|---|---|---|---|---|---|---|---|---|
| **COMP-01** | Packet Parsing & Scapy Capture (`src/xrlids/capture/scapy_service.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | Live raw socket sniffing requires root/cap_net_raw privileges. PCAP replay requires no elevated permissions. | `pytest tests/integration/test_scapy_capture.py` (4 passed); PCAP replay tested on `data/demo/sample_traffic.pcap`. |
| **COMP-02** | Canonical Flow Builder (`src/xrlids/flow/canonical_builder.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | Operates on completed flows (TCP FIN/RST or 120s idle timeout); in-flight packet detection without flow context is out of scope. | `pytest tests/unit/test_canonical_flow_builder.py` (5 passed); bidirectional 5-tuple canonicalization verified. |
| **COMP-03** | Feature Contract Gate & Validation (`src/xrlids/features/validator.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | Enforces strict schemas for R10 and R4. Disallows NaN, inf, or silent zero-fill. | `pytest tests/unit/test_feature_validator.py` (6 passed); contract validation latency = 3.938 ms. |
| **COMP-04** | Deterministic Protocol Rule Engine (`src/xrlids/rules/engine.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | 5 explicit rules (SYN Flood, Port Scan, High Rate Burst, Reserved IP, Invalid Flags). Operates independently of ML. | `pytest tests/unit/test_rules_engine.py` (10 passed); execution latency = 0.0038 ms. |
| **COMP-05** | Hybrid Decision Engine (`src/xrlids/rules/hybrid.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | Deterministic arbitration matrix reconciling ML posterior $P(\text{ATTACK})$ and protocol violations with safety floors. | `pytest tests/unit/test_hybrid_engine.py` (8 passed). |
| **COMP-06** | Multi-Flow Source Activity Tracker (`src/xrlids/tracking/source_tracker.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | Per-host 60s sliding window, 5-flow escalation threshold, 30s cooldown dampening to defeat low-and-slow evasion. | `pytest tests/unit/test_source_tracker.py` (7 passed); execution latency = 0.0028 ms. |
| **COMP-07** | XGBoost Candidate Suite (`src/xrlids/models/xgboost_detector.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **IMPLEMENTED** | **VALIDATED** | Comprehensive 5-rung sweep ($R_4$ to $R_{30}$) complete on all 3 datasets. Selected as Offline Champion & High-Throughput Candidate (0.29-0.77 ms latency). Preserved in `results/feature_sweep/`. | `pytest tests/unit/test_xgboost_detector.py`; empirical sweep summary in `results/feature_sweep/feature_sweep_master_summary.json`. |
| **COMP-08** | Primary Random Forest Baseline (`models/rf/`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | 3 frozen canonical checkpoints preserved: `cicids2017` ($F_1=0.9512$), `cse2018` ($F_1=0.1780$), `unswnb15` ($F_1=0.8548$). Deployed as primary live detector under Decision D-002. Peak offline F1 = 0.9891 at $R_{20}$. | `pytest tests/model/test_models.py` (12 passed); hashes match `models/registry/model_manifest.json` (100% integrity). |
| **COMP-09** | TreeSHAP Local Explainability (`src/xrlids/explainability/explainer.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | Explains tree model predictions only. Attributions satisfy $\sum \phi_i = f(x) - E[f(x)]$. Triggered conditionally on elevated risk flows. | `pytest tests/unit/test_explainer.py tests/unit/test_flow_treeshap.py` (13 passed); execution latency = 49.485 ms. |
| **COMP-10** | Dual-Track Dueling DQN Response Policies (`src/xrlids/response/`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | Dual tracks trained: Track B1 Binary 6D (Containment: 98.13%, Cost: 4.71) and Track B2 Attack-Aware 8D (Containment: 99.85%, Cost: 4.14). Paired bootstrap ($B=1,000$, $p < 0.0001$) confirms superiority. | `pytest tests/unit/test_dqn.py`; benchmark in `results/feature_sweep/dqn/policy_comparison_benchmark.json`. |
| **COMP-11** | Deterministic Safety Gate (`src/xrlids/response/safety.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | Hard safety invariants: critical-host exemptions (`192.168.10.1`, `.2`, `.50`), 5% blast radius cap, 30s cooldown, advisory dry-run mode. | `pytest tests/unit/test_phase3_gate.py tests/integration/test_safety_invariants.py` (22 passed); latency = 0.0009 ms. |
| **COMP-12** | Event Management & Active Pipeline (`src/xrlids/pipeline/active_pipeline.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | Full pipeline: Ingestion $\to$ Flow Builder $\to$ Feature Gate $\to$ Perception $\to$ Rules $\to$ Hybrid $\to$ Tracker $\to$ TreeSHAP $\to$ DQN $\to$ Gate $\to$ Executor $\to$ Events. | `pytest tests/integration/test_pipeline_e2e_forensics.py` (1 passed); ring-buffer event schema verified. |
| **COMP-13** | Operational Streamlit Dashboard (`dashboard/`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | 8 dedicated pages + entry point (`streamlit_app.py`). Zero hardcoded telemetry. Communicates directly with backend services. | Automated headless `AppTest` passed all 9 files without exception; verified live PCAP replay flow ingestion. |
| **COMP-14** | Supervised LSTM & Score Fusion Baselines | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **VALIDATED** | **VALIDATED** | Preserved in `models/lstm/` and `models/fusion/` as offline research comparators. Decoupled from live inference. | `pytest tests/unit/test_lstm_memory_safety.py` (6 passed); manifest integrity verified. |
| **COMP-15** | Master Latency Benchmarks (`scripts/benchmark_latency_master.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **VALIDATED** | **VALIDATED** | Fresh CPU benchmark execution records full latency distributions (Median, Mean, P95, P99). Reconciles binary vs multiclass scopes. | `python scripts/benchmark_latency_master.py` executed cleanly; output written to `docs/LATENCY_EVALUATION.md`. |
| **COMP-16** | Multiclass Attack Attribution (`src/xrlids/models/multiclass_detector.py`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | 6 attack families with calibrated `UNKNOWN` fallback ($p^* < 0.40$). Decoupled from binary fast-path. Weighted F1 = 95.52%. | `pytest tests/unit/test_multiclass_and_executor.py` (6 passed); artifact saved in `models/multiclass/multiclass_rf_champion.joblib`. |
| **COMP-17** | Autonomous Response Executor & Feedback (`src/xrlids/response/`) | **IMPLEMENTED** | **TESTED** | **VALIDATED** | **INTEGRATED** | **VALIDATED** | 5-stage lifecycle (`PROPOSED` $\to$ `AUTHORIZED` $\to$ `EXECUTED` $\to$ `VERIFIED` $\to$ `EXPIRED`/`ROLLED_BACK`). `advisory_mode=True` default. Transition feedback loop $(\mathbf{s}, a, r, \mathbf{s}', d)$. | `pytest tests/unit/test_multiclass_and_executor.py` (6 passed); immunity verification and rollback verified. |

---

## 2. Cross-Dataset Evidence Matrix

| Benchmark | Contract | Supported Features | Primary Model | Offline Candidates | Attack Recall | Attack F1 | PR-AUC | Status |
|---|---|---|---|---|---|---|---|---|
| **CIC-IDS2017** | $R_{10}$ | 10 features | Random Forest | XGBoost, LSTM, Fusion | 99.01% (RF) / 96.53% (XGB) | 0.9512 (RF) / 0.9585 (XGB) | 0.9824 (RF) / 0.9812 (XGB) | **INTEGRATED** |
| **CSE-CIC-IDS2018** | $R_{10}$ | 10 features | Random Forest | XGBoost, LSTM | 10.19% (RF) / 10.13% (XGB) [Day 1 Infiltration]; >99.0% [Multi-Attack Suite] | 0.1780 (RF) / 0.1814 (XGB) [Day 1]; >0.98 [Multi-Attack] | 0.3564 (RF) / 0.4111 (XGB) [Day 1] | **VALIDATED** |
| **UNSW-NB15** | $R_4$ | 4 features | Random Forest | XGBoost, LSTM | 92.23% (RF) / 88.51% (XGB) | 0.8546 (RF) / 0.8471 (XGB) | 0.9321 (RF) / 0.9214 (XGB) | **VALIDATED** |

---

## 3. Autonomous Response Verification Summary

- **Advisory Default:** `advisory_mode=True` strictly enforced across all operational paths (`execution_status="SIMULATED_ADVISORY"`). Zero unprompted OS/firewall mutations (`iptables`, `nftables`, `route`).
- **Critical Infrastructure Exemption:** `192.168.10.1` (Gateway), `192.168.10.2` (DNS), `192.168.10.50` (Active Directory Controller) are cryptographically immune to isolation and rate-limiting.
- **Closed-Loop RL Experience Buffer:** Environmental transitions $(\mathbf{s}_t, a_t, r_t, \mathbf{s}_{t+1}, d_t)$ are logged to thread-safe replay storage for offline policy evaluation.
