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

### Primary Flagship Dual-Benchmark (95%+ Target Exceeded Across 2.01M Test Flows)

The flagship models (Random Forest + LSTM Score Fusion under the canonical 10-feature R10 contract) consistently deliver **>99% accuracy** across the two enterprise-scale benchmark populations:

- **CIC-IDS2017:** Accuracy = **99.06% (0.9906)**, F1 = **0.9745**, ROC-AUC = **0.9989** (Fusion $\alpha = 0.50$, $N = 355,833$)
- **CSE-CIC-IDS2018:** Accuracy = **99.12% (0.9912)**, F1 = **0.9603**, ROC-AUC = **0.9966** (LSTM / Fusion $\alpha = 0.00$, $N = 1,662,419$)
- **Combined Primary Fleet Accuracy:** **99.11%** across 2,018,252 held-out test flows.

> **Scope note (important):** these are **in-domain random-split** metrics. A strict future-day
> holdout on CSE-CIC-IDS2018 produced RF **F1 0.0113** (recall 0.0068, ROC-AUC 0.3905) versus
> 0.8861 on the random split. The 99% figures are upper bounds, not future-day or production
> performance claims. See [Temporal Holdout](#temporal-holdout-cse-cic-ids2018-gap-p06) below.

### Auxiliary Benchmark (Degraded Sensor Schema)

- **UNSW-NB15 (Auxiliary R4 Fallback):** Accuracy = **89.96% (0.8996)**, F1 = **0.8970**, ROC-AUC = **0.9674** (Fusion $\alpha = 0.60$, $N = 24,496$). Evaluated under a 4-feature contract due to missing transport flags in Argus exporter. Cross-dataset experiments show significant domain-shift limitations documented in the research report.

### Multi-Seed Robustness (Seeds 42 / 123 / 456)

Each benchmark was re-run end-to-end with three seeds (population std); seed 42 reproduces the frozen artifacts exactly. Fusion detector, mean ± std:

| Dataset | Accuracy | F1 | ROC-AUC |
|:---|:---:|:---:|:---:|
| CIC-IDS2017 | 0.9903 ± 0.0005 | 0.9735 ± 0.0016 | 0.9986 ± 0.0002 |
| CSE-CIC-IDS2018 | 0.9912 ± 0.0001 | 0.9602 ± 0.0004 | 0.9965 ± 0.0000 |
| UNSW-NB15 | 0.8988 ± 0.0008 | 0.8963 ± 0.0006 | 0.9674 ± 0.0004 |

Full RF / LSTM / Fusion table: [`reports/generated/multi_seed_report.md`](reports/generated/multi_seed_report.md). Per-seed records: `results/experiments/<EXP>/seed_<n>/`.

### Bootstrap Uncertainty (Seed 42)

Per-seed 95% bootstrap intervals from the frozen held-out predictions (B=1000; threshold metrics on the full test population, ROC-AUC on a fixed 100k stratified sample). These quantify **test-set sampling uncertainty**, not training-seed variance:

| Dataset | Model | F1 [95% CI] | ROC-AUC [95% CI] |
|:---|:---|:---:|:---:|
| CIC-IDS2017 | Random Forest | 0.9512 [0.9500, 0.9524] | 0.9968 [0.9965, 0.9971] |
| CIC-IDS2017 | Fusion ($\alpha=0.50$) | 0.9745 [0.9737, 0.9754] | 0.9989 [0.9987, 0.9991] |
| CSE-CIC-IDS2018 | Random Forest | 0.8861 [0.8851, 0.8872] | 0.9902 [0.9893, 0.9914] |
| CSE-CIC-IDS2018 | Fusion ($\alpha=0.00$) | 0.9603 [0.9597, 0.9610] | 0.9966 [0.9962, 0.9972] |
| UNSW-NB15 | Random Forest | 0.8548 [0.8502, 0.8599] | 0.9487 [0.9462, 0.9511] |
| UNSW-NB15 | Fusion ($\alpha=0.60$) | 0.8970 [0.8930, 0.9009] | 0.9674 [0.9654, 0.9693] |

Full table: [`reports/generated/bootstrap_ci_report.md`](reports/generated/bootstrap_ci_report.md).

### Temporal Holdout (CSE-CIC-IDS2018, GAP-P06)

`EXP-P1-CSE2018-TEMPORAL-R10-001` sorts the 8,312,295 modelling rows by the real CSE `Timestamp`, trains on 14–20 Feb 2018, validates on 20–22 Feb, and tests on 22 Feb–2 Mar. L-01/L-02/L-05 pass. The frozen RF result is a **negative generalization finding**:

| Metric | Random split | Temporal holdout |
|:---|:---:|:---:|
| Accuracy | 0.9723 | 0.9633 |
| Precision | 0.8242 | 0.0332 |
| Recall | 0.9580 | 0.0068 |
| F1 | 0.8861 | **0.0113** [0.0101, 0.0124] |
| ROC-AUC | 0.9902 | 0.3905 |

The future test contains 50,306 attacks (3.08%) after Policy A removed conflicting/duplicate rows; these are the surviving unique future flows. Bot recall falls from 99.17% to 0.09%, infiltration from 10.70% to 0.94%, and web/XSS/SQL to 0%. The random-split 99% numbers are in-domain upper bounds, not future-day readiness claims. Full comparison: [`reports/generated/temporal_split_report.md`](reports/generated/temporal_split_report.md).

---

## Run

### 1. Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Test Suite

Execute the full 408-test verification suite:

```bash
.venv/bin/pytest -q
```

### 3. Run Replay Demonstration

Execute the packet-to-prediction PCAP replay demo:

```bash
python scripts/demo/run_replay_demo.py
```

### 4. Run Monitoring Dashboard (Live Monitor + Replay & Evidence)

Launch the zero-dependency web dashboard. It has two tabs: a **Live Monitor** (observational packet capture → flows → frozen detector, with IP endpoints, a **Detected Attack Sources** summary, threat scores, per-alert feature/score provenance, and a calibrated **Attack Simulator** panel) and a **Replay & Evidence** tab (replay verification statistics, offline RF/LSTM/fusion comparison, TreeSHAP attributions, research figures):

```bash
python dashboard/server.py
# Or: python scripts/demo/run_dashboard.py
```

Open `http://localhost:8000` in your web browser.

- **Live interface capture** (real packets from your network) requires root / `CAP_NET_RAW`:
  ```bash
  sudo .venv/bin/python dashboard/server.py --live --iface <interface>
  # or start it from the UI after launching the server with sudo
  ```
- **No root available?** Use the *Sample stream* mode in the UI: it replays `data/demo/sample_traffic.pcap` in real time through the exact same live pipeline (clearly labeled as sample traffic).
- Live monitoring is **strictly observational** (zero firewall/routing mutations) and shows **no accuracy numbers** (live traffic has no ground truth) — only flows, alerts, and model scores.
- **Attack Simulator (simulation only):** the Live Monitor includes a calibrated attack-scenario injector — packets are synthesised **in memory** and pushed through the exact monitoring pipeline (nothing is transmitted). Scenario scores are pre-verified against the frozen detector by `scripts/demo/verify_attack_scenarios.py`; `scripts/demo/explain_score.py` prints a scenario's exact R10 features and the frozen model's `predict_proba` output (with a benign control), and the UI's **features** dialog shows the same values per alert. "Evasion demo" scenarios are documented non-detections, shown deliberately. See [`dashboard/README.md`](dashboard/README.md#attack-simulator-simulation-only).

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
| Web dashboard | Complete (live monitor + replay evidence; zero-dependency) |
| Production deployment | Not validated |

---

## Documentation

- [`PROJECT_STATUS.md`](PROJECT_STATUS.md) — Comprehensive implementation and empirical status registry
- [`docs/final/FINAL_RESEARCH_REPORT.md`](docs/final/FINAL_RESEARCH_REPORT.md) — Comprehensive research report covering methodology, findings, and limitations
- [`docs/final/RELEASE_AUDIT.md`](docs/final/RELEASE_AUDIT.md) — Final release audit, governance verification, and checklist
- [`docs/final/REPRODUCIBILITY_MAP.md`](docs/final/REPRODUCIBILITY_MAP.md) — Detailed environment configuration and reproduction commands
- [`docs/viva/FINAL_VIVA_GUIDE.md`](docs/viva/FINAL_VIVA_GUIDE.md) — Technical defense questions, rationale, and empirical answers
- [`docs/viva/DEMO_AND_VIDEO_SCRIPT.md`](docs/viva/DEMO_AND_VIDEO_SCRIPT.md) — Demo runbook, viva script, video recording shot list, readiness verdict, and recovery playbook
- [`docs/HOW_IT_WORKS.md`](docs/HOW_IT_WORKS.md) — End-to-end system explanation (real vs. simulated traffic, pipeline, score calculation, thresholds, live capture, DL-model placement, anti-bluffing proof)

Detailed methodology, experiments, limitations, reproducibility information, and viva material are documented separately.

---

## Scope & Safety

Autonomous response enforcement is validated strictly within a controlled, isolated laboratory environment (Linux network namespaces on `10.200.1.0/24`) with verified zero mutations to the host networking stack. The project does not claim or support production deployment on uncontrolled operational networks such as campus or enterprise Wi-Fi.

---

## License

This project is licensed under the [MIT License](LICENSE). Raw benchmark datasets (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15) carry their own respective terms of use recorded in `data/manifests/dataset_registry.yaml`.
