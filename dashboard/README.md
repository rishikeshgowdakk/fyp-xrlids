# XRL-IDARS Operational Dashboards & Research Workbench

XRL-IDARS provides two complementary dashboard interfaces:

1. **🛡️ Primary Operational Command Center (Streamlit)**: High-level operational command center running on port 8501 (`dashboard/streamlit_app.py` with 8 dedicated sub-pages in `dashboard/pages/01_Overview.py` through `08_System_Telemetry.py`). Integrates real-time Scapy sniffing, PCAP replay, sample traffic generation, Random Forest detection, Lundberg TreeSHAP explanations, RFC protocol rules, multi-flow source tracking, and Dueling DQN response recommendations.
2. **🔬 Supplementary Research Workbench & Demo Interface (Pure-Python)**: Zero-dependency web server running on port 8000 (`dashboard/server.py`, `dashboard/index.html`, `dashboard/demo.html`, `dashboard/app.js`). Prioritizes full held-out benchmark evaluations, multi-model comparisons, runtime microbenchmarks, and 2-minute live exhibition demonstration scenarios.

---

## 🏛️ Workbench Architecture (2 Modes & 5 Core Research Sections)

The workbench is organized into two top-level operating modes with five core research sections:

### Mode 1: 🔬 Research & Model Validation (Default Mode)
Dedicated to held-out empirical benchmark evaluations, multi-model comparisons, runtime microbenchmarks, TreeSHAP attributions, autonomous response policies, and audited scientific limitations:

#### 1. 📊 Section 1: Dataset Explorer & Evaluation
- Evaluates held-out benchmark splits across four benchmark configurations:
  - **CIC-IDS2017** (Flagship — 355,833 aligned test flows, R10 contract)
  - **CSE-CIC-IDS2018** (Enterprise Cloud — 1,662,419 test flows, R10 contract)
  - **UNSW-NB15** (Sensor Degraded — 24,496 test flows, R4 contract)
  - **CSE-CIC-IDS2018 Temporal Holdout** (1,631,630 test flows across chronological future days)
- Population slice toggle: Aligned Sequence Slice ($355,833$) vs Tabular Split ($355,865$), with the exact 32-flow boundary derivation documented ($8 \text{ capture files} \times (T-1) \text{ boundary flows for } T=5$).
- High-level metric tiles: Accuracy, Precision, Recall, F1-Score, ROC-AUC, PR-AUC.
- Held-out Confusion Matrix visualizer (TN, FP, FN, TP).
- Per-class and per-attack-family breakdown tables with support counts.
- Calibration reliability curve summary.
- **📂 Custom CSV Dataset Evaluation & Ingestion**:
  - Live upload, paste, or demo sample loading of arbitrary network flow CSV records.
  - Strict contract enforcement: validates R10 (10 features) or R4 (4 features) schema.
  - Target leakage prevention: separates ground-truth labels from inference inputs.
  - Evaluates against frozen model artifacts (`preprocessor.joblib` + `random_forest.joblib`).
  - Distinguishes ad-hoc evaluation from official benchmark results without altering historical artifacts.
  - Downloadable CSV export with full evaluation metadata provenance headers.

#### 2. ⚖️ Section 2: Model Comparison
- Aligned comparative benchmark comparing Majority Baseline, Logistic Regression, Decision Tree, Random Forest, Supervised LSTM, and Fusion.
- 95% empirical bootstrap confidence intervals and multi-seed stability (seeds 42, 123, 456).
- **Fusion Weighting Configuration**: Exposes $\alpha$ and $(1-\alpha)$. Clearly flags degenerate configurations (e.g. $\alpha = 0.00$ on CSE-CIC-IDS2018 where fusion reduces to pure LSTM).
- **LSTM Shuffled-Window Ablation**: Exposes the empirical finding that sequence order gain is zero ($\Delta \text{F1} = -0.0038$), proving spatial pooling rather than temporal reasoning.
- **Temporal Generalization Gap**: Highlights the collapse of CSE-2018 RF from F1 0.8861 down to 0.0113 on future days.

#### 3. ⏱️ Section 3: Performance Benchmarks & Scope Reconciliation
- Evaluates decision policy latencies: analytic Cost-Optimal (1.95 µs) is **~51.4x faster** than neural Dueling DQN (100.23 µs).
- **Dual Latency Scope Reconciliation**:
  - *Scope 1 (Isolated Microbenchmark)*: Pure 100-tree RF traversal on a pre-extracted float32 feature vector is **3,525.08 µs (~3.53 ms)** single-thread (53.87 µs/flow in vectorized batches of 100).
  - *Scope 2 (Streaming Burst Pipeline Queue)*: Under a 1,000-packet line-rate burst (`EXP-P3-BURST-1000-001`), packet capture (0.50 µs), flow assembly (12.89 µs), feature extraction (763.72 µs), dual-model sequence queuing with thread contention (**35,416.18 µs / ~35.42 ms P50**), policy evaluation (916.16 µs), and safety checks (14.12 µs) yield a median end-to-end flow completion latency of **37,513.87 µs (~37.51 ms P50)**.
- **Dual Memory Scope Reconciliation**:
  - *Scope 1 (Quiescent Weights)*: Cold process RAM with loaded weights is **~123.2 MB** (RF 117.4 MB, LSTM 1.2 MB, DQN 0.4 MB, hash table 4.2 MB) with 0.2% idle CPU.
  - *Scope 2 (Peak Flood Stress RSS)*: Continuous socket stress and 10,000 soak flows (`EXP-P3K-STRESS-SECURITY-001`) cause peak transient RSS to reach **1,049.45 MiB (~1.05 GiB)** before safely returning to **175.74 MiB** post-soak (+12.05 MiB / 7.36% net growth over 10k flows; zero unbounded memory leaks).
- **Canonical Artifacts Registry**: 10 canonical JSON result files dynamically loaded, parsed, and validated directly from disk.

#### 4. 💡 Section 4: Explainability & Attack Analysis
- Explains the Random Forest detector via TreeSHAP (TreeExplainer) on evaluated test flows.
- Global feature importance rankings with mean absolute SHAP values.
- **Critical Attack Blind Spots**: Discloses severe detection failures on low-footprint application attacks (Infiltration recall 0.00%, SQL Injection recall 0.00%, XSS recall 2.78%) due to L3/L4 flow statistical invariance.
- **Scientific Notice**: TreeSHAP explains tree decision paths of the Random Forest ONLY; it does not explain the LSTM, the Fusion model, or the DQN.

#### 5. 🛡️ Section 5: Autonomous Response
- Controlled benchmark comparing trained Deep Q-Network against the zero-parameter `CostOptimalThresholdPolicy` on held-out 355k test flows.
- Multi-regime selector: Standard Enterprise, High Availability, High Security Enclave across 3-action and 4-action modes.
- Paired statistical comparison with 95% bootstrap CI and p-values.
- Highlights that the analytic Cost-Optimal baseline beats DQN in 4 of 6 settings (up to 20.12% lower cost) and executes ~51x faster (1.95 µs vs 100.23 µs policy-only).
- Deterministic Safety Gate status: 100% authoritative override on invalid actions. Production autonomous enforcement remains strictly `NO-GO`.

#### Supporting Research Views:
- **📋 Platform Overview**: System architecture, current Git commit, clean working-tree verification, runtime environment, and component verification matrix.
- **🔍 Flow Explorer**: Paginated, filterable browsing of evaluated test flows directly from `predictions_test.csv` with strict ground truth visual isolation.
- **⚠️ Research Limitations**: Candid plain-language review of all 9 audited scientific limitations.

---

### Mode 2: ⚡ Live Exhibition Demo (Observational Traffic & Attack Simulation)
Dedicated to live packet inspection, pure-Python streaming replay, and in-memory attack simulation without production network mutations:
- Strictly separates the 5 traffic execution modes:
  - **Mode 1**: Offline Dataset Evaluation (Frozen test split)
  - **Mode 2**: Dataset Demonstration Stream (Curated benchmark feature vectors; display endpoints are synthetic)
  - **Mode 3**: PCAP Replay (Recorded packets parsed through flow builder)
  - **Mode 4**: Synthetic Attack Simulation (In-memory packet scripts)
  - **Mode 5**: Live Packet Capture (Raw AF_PACKET socket, root required, observational only).
- **🎯 Detected Attack Sources Panel**:
  - Aggregates detected alert events by Source IP.
  - Displays alert frequency, peak model confidence score, and suggested policy action.
- **📱 WiFi Devices (Passive Discovery Panel)**:
  - Discovers local network hosts passively via broadcast/multicast frames (ARP, DHCP, mDNS, SSDP) and neighbour cache.
  - Resolves MAC addresses to hardware vendors via local OUI cache.
  - Displays IP address, hostname/label, packet count, relative last-seen age, and dynamic router admin link.
  - Active network scanning, probing, or router credential storage is strictly prohibited.
- **⚡ Attack Simulator**:
  - 7 calibrated attack scenarios (Slowloris, SYN Flood, UDP Flood, Port Sweep, Slow HTTP DoS, Shrew, Normal Traffic).
- **⚠️ Operational Disclaimer Banner**:
  - Prominently warns that live operational traffic lacks ground-truth labels and that benchmark accuracy on closed datasets does not prove live operational accuracy.

---

### ⚡ Live Demonstration & Exhibition Page (`/demo.html`)
Designed for live exhibition visitors and demonstrations to present a clean, unfussy explanation of the system in 30 seconds without navigating complex statistical tables:
1. **Interactive Pipeline Strip**: Packets → Features → Detector (RF+LSTM) → TreeSHAP → Action Gate with animated live stage transitions.
2. **Four Clean Counters Only**: Replay sample counters for `Flows Analysed`, `Attacks Caught`, `Attacks Missed`, and `False Alarms`.
3. **Flow Stream & "Why?" Card**: Real-time interactive timeline showing incoming flows. Clicking any flow reveals its confidence score, policy action (`ALLOW`, `ALERT`, `BLOCK`), and top 3 plain-English TreeSHAP factors.
4. **Distinct Benchmark Strip**: Full held-out test set metrics (355,833 flows) clearly separated from the replay sample.
5. **2-Minute Demonstration Scenario & Scorecard**: One-click bounded demonstration passing through normal baseline, port scans, DDoS floods, and DoS attacks, terminating in a clean evaluation scorecard modal.

---

## 🚀 Quick Start

### 1. Launch Primary Operational Dashboard (Streamlit)
```bash
# Activate virtual environment
source .venv/bin/activate

# Launch Streamlit Operational Command Center (default port 8501)
streamlit run dashboard/streamlit_app.py --server.port 8501
```
- **Primary Operational Dashboard**: [http://127.0.0.1:8501](http://127.0.0.1:8501)

### 2. Launch Supplementary Research Workbench & Demo (Pure-Python)
```bash
# Launch the Pure-Python Research Workbench & Demonstration Server (default port 8000)
python dashboard/server.py
```
- **Live Demonstration Page**: [http://127.0.0.1:8000/demo.html](http://127.0.0.1:8000/demo.html)
- **Full Research Workbench**: [http://127.0.0.1:8000/index.html](http://127.0.0.1:8000/index.html)

---

## 🛡️ Streamlit Operational Command Center (Phase 12)

Alongside the HTML5 Research Workbench, XRL-IDARS provides a comprehensive multi-page **Streamlit Command Center** covering end-to-end active pipeline operations:

```bash
# Launch Streamlit Command Center (port 8501)
.venv/bin/streamlit run dashboard/streamlit_app.py
```

### 8 Dedicated Streamlit Operational Modules:
1. `01_Overview.py`: Architecture KPIs, active pipeline health, and real-time security event stream.
2. `02_Live_Ingestion.py`: Streaming PCAP replay controls, Scapy socket capture, and active canonical 5-tuple flow assembler.
3. `03_Model_Evaluation.py`: Multi-dataset benchmark metrics (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15) with dynamic head-to-head RF vs XGBoost tables and latency speedups.
4. `04_Explainability.py`: Interactive TreeSHAP local feature attribution explorer, waterfall rankings, and threat direction badges.
5. `05_Rule_Intelligence.py`: Canonical RFC 793/1122 protocol rule catalog, packet simulator, and hybrid arbitration truth matrix.
6. `06_Source_Tracking.py`: Per-host 60s sliding window table, active cooldown timers, and multi-flow escalation trigger simulation.
7. `07_Response_Policy.py`: 6D causal state inputs, Dueling DQN Q-value bar charts, and Deterministic Safety Gate verification.
8. `08_System_Telemetry.py`: End-to-end latency waterfall chart, searchable JSON audit trail, and export facilities.


