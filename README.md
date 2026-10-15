# XRL-IDARS

**Explainable Reinforcement Learning Based Intrusion Detection and Autonomous Response System**

XRL-IDARS is a research framework for network-flow intrusion detection and controlled autonomous response. It couples tabular and temporal machine learning detection (Random Forest + LSTM score fusion) with TreeSHAP feature attributions, context-aware reinforcement learning response policies (Dueling DQN), and deterministic safety constraints with atomic transaction rollback to prevent self-inflicted denial-of-service and unauthorized network mutations.

---

## Architecture

```text
Network / PCAP
      ↓
Packet Capture
      ↓
Flow Construction
      ↓
Feature Extraction
      ↓
   RF + LSTM
      ↓
    Fusion
      ↓
SHAP + Threat Score
      ↓
  DQN Response
      ↓
  Safety Gate
      ↓
Controlled Response / Rollback
```

---

## Key Components

| Component | Description |
|---|---|
| **Dataset & Preprocessing** | Leakage-safe split pipeline, chunked streaming audits, and canonical feature contracts (R10 / R4). |
| **Random Forest** | Low-latency tabular flow classifier for statistical traffic patterns. |
| **Supervised LSTM** | Sequence model ($T=5$) capturing multi-flow temporal dependencies. |
| **RF + LSTM Fusion** | Calibrated convex score combination balancing spatial and temporal signals. |
| **SHAP Explainability** | TreeSHAP feature attributions explaining classification drivers. |
| **DQN Response Policy** | Context-aware Dueling DQN policy with Prioritized Experience Replay. |
| **Live Packet/Flow Processing** | Pure-Python PCAP replay and streaming bidirectional flow construction. |
| **Safety Gate** | Deterministic non-bypassable constraints (cooldowns, blast-radius limits, critical host exemptions). |
| **Transaction & Rollback** | Pre-action state snapshots, watchdog TTL monitoring, and automated compensation rollback. |
| **Isolated Laboratory Validation** | Controlled evaluation in virtualized Linux network namespaces (`10.200.1.0/24`) with zero host network mutations. |

---

## Research Results

Authoritative in-domain test evaluation metrics across multi-file benchmark datasets:

- **CIC-IDS2017:** Accuracy = **0.9906 (99.06%)**, F1 = **0.9745**, ROC-AUC = **0.9989** (Fusion $\alpha = 0.50$, $N = 355,833$)
- **CSE-CIC-IDS2018:** Accuracy = **0.9912 (99.12%)**, F1 = **0.9603**, ROC-AUC = **0.9966** (LSTM / Fusion $\alpha = 0.00$, $N = 1,662,419$)
- **UNSW-NB15:** Accuracy = **0.8996 (89.96%)**, F1 = **0.8970**, ROC-AUC = **0.9674** (Fusion $\alpha = 0.60$, R4 contract, $N = 24,496$)

Cross-dataset experiments show significant domain-shift limitations, which are documented in the research report.

---

## Run

### 1. Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Test Suite

Execute the full 388-test verification suite:

```bash
.venv/bin/pytest -q
```

### 3. Run Replay Demonstration

Execute the packet-to-prediction PCAP replay demo:

```bash
python scripts/demo/run_replay_demo.py
```

### 4. Run Monitoring Dashboard

Launch the zero-dependency web dashboard to visualize replay statistics and TreeSHAP attributions:

```bash
python dashboard/server.py
# Or: python scripts/demo/run_dashboard.py
```

Open `http://localhost:8000` in your web browser.

> **Note:** The replay demonstration runs immediately out of the box in user space using `data/demo/sample_traffic.pcap` and the trained model artifact in `results/experiments/EXP-P1-CIC2017-R10-001/random_forest.joblib`. Retraining on full raw benchmark datasets (~8.7 GB across 20 CSV files) requires downloading raw data into `data/raw/` as detailed in [`docs/DATASETS.md`](docs/DATASETS.md). Live namespace enforcement requires an isolated Linux testbed with root privileges.

---

## Project Status

| Component | Status |
|---|---|
| Detection pipeline | Complete |
| RF/LSTM/Fusion | Complete |
| SHAP | Complete |
| DQN response | Complete |
| Safety/Rollback | Complete |
| Live/lab pipeline | Complete within lab scope |
| Web dashboard | Complete (minimalist zero-dependency server) |
| Production deployment | Not validated |

---

## Documentation

- [`PROJECT_STATUS.md`](PROJECT_STATUS.md) — Comprehensive implementation and empirical status registry
- [`docs/final/FINAL_RESEARCH_REPORT.md`](docs/final/FINAL_RESEARCH_REPORT.md) — Comprehensive research report covering methodology, findings, and limitations
- [`docs/final/RELEASE_AUDIT.md`](docs/final/RELEASE_AUDIT.md) — Final release audit, governance verification, and checklist
- [`docs/final/REPRODUCIBILITY_MAP.md`](docs/final/REPRODUCIBILITY_MAP.md) — Detailed environment configuration and reproduction commands
- [`docs/viva/FINAL_VIVA_GUIDE.md`](docs/viva/FINAL_VIVA_GUIDE.md) — Technical defense questions, rationale, and empirical answers

Detailed methodology, experiments, limitations, reproducibility information, and viva material are documented separately.

---

## Scope & Safety

Autonomous response enforcement is validated strictly within a controlled, isolated laboratory environment (Linux network namespaces on `10.200.1.0/24`) with verified zero mutations to the host networking stack. The project does not claim or support production deployment on uncontrolled operational networks such as campus or enterprise Wi-Fi.

---

## License

This project is licensed under the [MIT License](LICENSE). Raw benchmark datasets (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15) carry their own respective terms of use recorded in `data/manifests/dataset_registry.yaml`.
