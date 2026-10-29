# XRL-IDARS Research Evaluation Workbench

A zero-dependency web interface and forensic evaluation workbench for the **Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)**.

The interface is structured as a **Research Evaluation Workbench**, prioritizing genuine held-out evaluation outputs, statistical confidence bounds, and candid empirical findings over synthetic demonstrations.

---

## 🏛️ Workbench Architecture (7 Research Views)

The workbench is organized into seven specialized pages:

### 1. 📊 Dataset Evaluation (Primary Page — Default Active View)
- Evaluates held-out benchmark splits across four benchmark settings:
  - **CIC-IDS2017** (Flagship — 355,833 aligned test flows, R10 contract)
  - **CSE-CIC-IDS2018** (Enterprise Cloud — 1,662,419 test flows, R10 contract)
  - **UNSW-NB15** (Sensor Degraded — 24,496 test flows, R4 contract)
  - **CSE-CIC-IDS2018 Temporal Holdout** (1,631,630 test flows across chronological future days)
- Population slice toggle: Aligned Sequence Slice ($355,833$) vs Tabular Split ($355,865$), with the exact 32-flow boundary derivation documented.
- High-level metric tiles: Accuracy, Precision, Recall, F1-Score, ROC-AUC, PR-AUC.
- Held-out Confusion Matrix visualizer (TN, FP, FN, TP).
- Per-class and per-attack-family breakdown tables.
- Calibration reliability curve summary.
- **📂 Custom CSV Dataset Evaluation & Ingestion**:
  - Live upload, paste, or demo sample loading of arbitrary network flow CSV records.
  - Strict contract enforcement: validates R10 (10 features) or R4 (4 features) schema.
  - Target leakage prevention: separates ground-truth labels from inference inputs.
  - Evaluates against frozen model artifacts (`preprocessor.joblib` + `random_forest.joblib`).
  - Distinguishes ad-hoc evaluation from official benchmark results without altering historical artifacts.
  - Downloadable CSV export with full evaluation metadata provenance headers.

**CSV evaluation validation rules:** the benchmark and feature contract are a paired configuration (CIC-IDS2017/R10, CSE-CIC-IDS2018/R10, UNSW-NB15/R4). The evaluator separates the label column from inference features, rejects unknown or ambiguous labels, coerces numeric features, accounts for dropped non-finite rows, and applies the canonical feature order. CSV evaluations are ad-hoc analyses against frozen artifacts; they do not alter historical benchmark outputs or retrain models. Treat exported records as evaluation outputs, not as new benchmark evidence.

### 2. 📋 Overview
- Platform architecture, current Git commit, clean working-tree verification, and runtime environment.
- Formal Component Verification Matrix with statuses:
  - Random Forest: `VERIFIED_FOR_DEFINED_SCOPE`
  - Supervised LSTM: `PARTIALLY_VERIFIED`
  - RF-LSTM Fusion: `PARTIALLY_VERIFIED`
  - Deep Q-Network: `REQUIRES_REFORMULATION`
  - Deterministic Safety Gate: `VERIFIED_FOR_DEFINED_SCOPE`
- Benchmark inventory table and audit links.

### 3. ⚖️ Model Comparison
- Aligned comparative benchmark comparing Majority Baseline, Logistic Regression, Decision Tree, Random Forest, Supervised LSTM, and Fusion.
- 95% bootstrap confidence intervals and multi-seed stability (seeds 42, 123, 456).
- **Fusion Weighting Configuration**: Exposes $\alpha$ and $(1-\alpha)$. Clearly flags degenerate configurations (e.g. $\alpha = 0.00$ on CSE-CIC-IDS2018 where fusion reduces to pure LSTM).
- **LSTM Shuffled-Window Ablation**: Exposes the empirical finding that sequence order gain is zero ($\Delta \text{F1} = -0.0038$), proving spatial pooling rather than temporal reasoning.
- **Temporal Generalization Gap**: Highlights the collapse of CSE-2018 RF from F1 0.8861 down to 0.0113 on future days.

### 4. 🔍 Flow Explorer
- Paginated, filterable browsing of evaluated test flows directly from `predictions_test.csv`.
- Filters: All Flows, Correct Classifications, Classification Errors, False Positives (FP), Missed Attacks (FN).
- **Ground Truth Isolation Invariant**: Ground truth is displayed in a separate, isolated visual container, never fed into model inputs.
- Export Button: Generates and downloads a CSV export of filtered flows with research metadata headers.

### 5. 💡 Explainability
- Explains the Random Forest detector via TreeSHAP (TreeExplainer).
- Global feature importance rankings with mean absolute SHAP values.
- **Scientific Notice**: TreeSHAP explains tree decision paths of the Random Forest ONLY; it does not explain the LSTM, the Fusion model, or the DQN.

### 6. 🛡️ Autonomous Response
- Controlled benchmark comparing the trained Deep Q-Network against the zero-parameter `CostOptimalThresholdPolicy` on held-out 355k test flows.
- Multi-regime selector: Standard Enterprise, High Availability, High Security Enclave across 3-action and 4-action modes.
- Paired statistical comparison with 95% bootstrap CI and p-values.
- Highlights that the analytic Cost-Optimal baseline beats DQN in 4 of 6 settings (up to 20.12% lower cost) and executes ~51x faster (1.95 µs vs 100.23 µs policy-only).
- Deterministic Safety Gate status: 100% authoritative override on invalid actions. Production autonomous enforcement remains strictly `NO-GO`.

### 7. ⚠️ Research Limitations
- Plain-language review of all 9 audited limitations:
  1. Random Split vs Temporal Holdout Generalization Gap
  2. Random Forest Probability Calibration Gap
  3. Supervised LSTM Sequence Locality
  4. Degenerate Fusion Weighting ($\alpha = 0.00$)
  5. Sensor Schema Degradation on UNSW-NB15 (R4 vs R10)
  6. Exogenous Flow Replay vs Sequential MDP ($\gamma = 0.95$ ungrounded)
  7. DQN Inferiority to Analytic Cost-Optimal Baseline
  8. Observational Live Capture vs Network-Wide Visibility
  9. Strict Prohibition of Autonomous Production Enforcement.

### 8. ⚡ Live Monitor & Traffic Modes (Secondary View)
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
  - Live capture only: non-live replay modes show an explicit notice and never fabricate device entries.

---

## 🚀 Quick Start

```bash
# Activate virtual environment
source .venv/bin/activate

# Launch the Research Evaluation Workbench (default port 8000)
python dashboard/server.py

# Optional: Run on custom port
python dashboard/server.py 8080
```

Open `http://127.0.0.1:8000/` in your browser.
By default, the workbench opens in idle observational mode on **Page B: Dataset Evaluation**, ready for interactive inspection of verified experimental results.
