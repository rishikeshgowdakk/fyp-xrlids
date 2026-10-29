# XRL-IDARS — Phase 2 Forensic Audit: Models, Artifacts, Fusion, SHAP, and DQN

**Document Identifier**: `AUDIT-P2-FORENSIC-001`  
**Audit Scope**: Codebase, Artifacts, Per-Flow Models (RF), Sequence Models (LSTM), Fusion, SHAP Explainability, and Deep Q-Network (DQN) Response Policy  
**Target Repository**: `https://github.com/rishikeshgowdakk/fyp-xrlids`  
**Lead Auditor**: Senior ML Research Engineer, Cybersecurity ML Auditor & Production Systems Reviewer  
**Audit Date**: October 28, 2026  
**Audit Standard**: Zero-Assumptions Verification Standard (Evidence-Driven Forensic Protocol)

---

## 1. Executive Verdict

### The Unvarnished Truth: What is Genuinely Correct vs. What is Not Proven

1. **Genuinely Correct & Well-Engineered**:
   - **Architectural & Safety Engineering**: The project contains exceptional engineering discipline. The non-bypassable `DeterministicSafetyGate` (cooldowns, blast-radius bounding, critical infrastructure protection), the atomic response transaction rollback harness with cryptographic snapshots (`HostNetworkBaseline`), and the isolated Linux network namespace testbed (`10.200.1.0/24`) are genuinely implemented and rigorously verified (all 419 unit and integration tests pass).
   - **Data Governance & Integrity**: The feature registry, column normalization maps, hash-verified dataset manifests, and strict train-only scaler fitting are mathematically reconciled and auditable.
   - **Honest Caveats**: Negative results—such as the catastrophic generalization failure under temporal holdout ($F_1 = 0.0113$), severe cross-dataset domain collapse ($\Delta F_1 \approx -0.52 \text{ to } -0.95$), and the failure of DQN to achieve the pre-registered 15% effect size—are documented in the research reports rather than concealed.

2. **Implemented But Empirically Fragile / Confounded**:
   - **The >99% Accuracy Claim**: Headline accuracy (>99%) is an in-domain random-split ceiling on a clean, label-filtered manifold. It excludes 27.7% of CSE-CIC-IDS2018 (4.5M rows) where the 10-feature vector cannot separate benign from malicious traffic (Bayes accuracy ceiling on this ambiguous region is ~64.3%).
   - **LSTM "Temporal Context"**: Sequences of $T=5$ are built across consecutive CSV file rows rather than genuine host-to-host physical timelines. Shuffled-order ablations reveal the LSTM functions as a non-linear tabular aggregator rather than capturing physical packet timing.
   - **RF + LSTM Score Fusion**: While convex score blending is mathematically correct, it is an uncalibrated blend of RF tree votes and raw LSTM sigmoids. On the largest benchmark (CSE-CIC-IDS2018), validation tuning collapsed to $\alpha = 0.00$ (pure LSTM), proving the two models are not complementary on enterprise data.

3. **DQN Autonomous Response Policy Verdict**:
   - **Trained**: **YES**. Checkpoints exist, match architectures, and can be loaded.
   - **Reproducible**: **YES**. The offline simulation matrix runs deterministically.
   - **Useful**: **MARGINAL / CONTEXTUAL BANDIT ONLY**. The environment lacks dynamic state transitions based on network packet mutations; it is fundamentally an asymmetric-loss Contextual Bandit evaluated over an exogenous trace. Cost reductions over the best deterministic baseline (Two-Tier Threshold $\tau=0.40/0.75$) reached **+11.29%** (Balanced), **+14.10%** (Aggressive), and **+2.05%** (Conservative)—all **failing** the pre-registered 15.0% practical effect size threshold.
   - **Safe for Autonomous Enforcement**: **NO**. The policy exhibits severe action chattering under sensor score noise ($\text{ACI} \approx 0.11 > 0.05$), fails to contain stealth attacks (0% isolation on Infiltration and SQL Injection), and is safe only because the external `DeterministicSafetyGate` intercepts invalid actions.

---

## 2. Repository Commit & Environment Baseline

- **Repository**: `https://github.com/rishikeshgowdakk/fyp-xrlids`
- **Active Git Commit**: `fd5b48448c28ef6c02671a3062239e53e749d882`
- **Active Branch**: `main`
- **Working Tree Status**: Clean (no uncommitted or untracked modifications)
- **Runtime Environment**:
  - Python: `3.14.4` (Linux x86_64)
  - PyTorch: `2.14.0+cpu`
  - Scikit-Learn: `1.9.1`
  - SHAP: `0.52.0`
  - Pandas: `3.0.6`
  - NumPy: `2.5.3`
  - Joblib: `1.6.0`
- **Hardware Architecture**: 13th Gen Intel(R) Core(TM) i7-1355U (12 vCPUs), CPU-only (no CUDA accelerator required).

---

## 3. Artifact Inventory & Cryptographic Integrity

Every core model and evaluation artifact was independently located, verified on disk, and audited via SHA-256 cryptographic hashing:

| Artifact Path | Size (Bytes) | SHA-256 Hash | Format / Loading Mechanism | Generating Script / Source | Actual In-Code Consumer | Stale / Valid Status |
| :--- | ---:| :--- | :--- | :--- | :--- | :---: |
| `results/experiments/EXP-P1-CIC2017-R10-001/random_forest.joblib` | 26,363,055 | `7c6ad493b773b687da24a2a12dcb21bd03bd56b76809462b983454aeacf2b774` | `joblib.load()` | `scripts/phase1/run_experiment.py` | `ReplayEngine`, `dashboard/server.py`, Phase 2 Detector | **VERIFIED** |
| `results/experiments/EXP-P1-CIC2017-R10-001/lstm.pt` | 60,949 | `2cdbf88d2eda358619d66a5d001fa7dde8ab3a36d8e0548c8c529ae8e8870f5c` | `torch.load(weights_only=False)` | `scripts/phase1/run_experiment.py` | Offline Evaluation Only | **VERIFIED (Offline)** |
| `results/experiments/EXP-P1-CIC2017-R10-001/preprocessor.joblib` | 3,013 | `b27b405ea80e89b242e6d7fdeb83b7a8eccfe764008fdb3ed1cd41a931b9ed59` | `joblib.load()` | `src/xrlids/preprocessing/pipeline.py` | `ReplayEngine`, Live Monitor | **VERIFIED** |
| `results/experiments/EXP-P1-CIC2017-R10-001/test_metrics.json` | 14,066 | `af60e509daab5650f156a1855b8cd247a4531da35aabebe598c42e3f8daa262e` | `json.loads()` | `scripts/phase1/run_experiment.py` | `dashboard/server.py` | **VERIFIED** |
| `results/phase2/EXP-P2B-DQN-001/checkpoints/stage_2b1_3action/best_model.pt` | 42,997 | `c06a61fb7777511600efd6db776745c4539da30c710fed8993145ed1b926be31` | `torch.load()` state_dict | `src/xrlids/response/dqn/trainer.py` | Phase 2B Evaluation, Test Harness | **VERIFIED** |
| `results/phase2/EXP-P2B-DQN-001/checkpoints/stage_2b2_4action/best_model.pt` | 43,189 | `6a5afc669b4e699ecd2b1c01df885cef9030c93b8888b487dd386533920ce954` | `torch.load()` state_dict | `src/xrlids/response/dqn/trainer.py` | Phase 2B Evaluation, Test Harness | **VERIFIED** |
| `results/phase2/EXP-P2-FINAL-TEST-001/final_test_metrics.json` | 21,908 | `13217fc5bcfa3769c3a3c9a0ebf3041c2c2f61e8787f7374b684cb630db00898` | `json.loads()` | `scripts/phase2/run_phase2_final_test.py` | `PHASE2_FINAL_REPORT.md` | **VERIFIED** |
| `results/phase2/EXP-P2-FINAL-TEST-001/final_test_bootstrap.json` | 12,835 | `60ff756ff6d958564c7f07823e4ae67f67355209c12217e57c6383637e17cb5a` | `json.loads()` | `scripts/phase2/run_phase2_final_test.py` | `PHASE2_FINAL_REPORT.md` | **VERIFIED** |
| `results/demo/replay_summary.json` | 7,268 | `dde356ae407d5478126cf3ec0dc9ccd8165d433db42390baf0f5d1431687c7c2` | `json.loads()` | `scripts/demo/run_replay_demo.py` | `dashboard/server.py` | **VERIFIED** |
| `data/demo/sample_traffic.pcap` | 63,924 | `e96692edfcb0ef3c4ad37c4eaef3e6acd8787ca2e815f28e6458b1756deb5d4d` | Raw PCAP (tcpdump) | Network Capture | `ReplayEngine`, Demo Replay | **VERIFIED** |

---

## 4. Dataset & Feature-Contract Audit

### 4.1 Dataset Ingestion & Physical Availability
- All 20 physical raw CSV files are verified present on disk:
  - **CIC-IDS2017**: 8 CSV files (2,830,743 raw rows) in `data/raw/cicids2017/`.
  - **CSE-CIC-IDS2018**: 10 CSV files (16,233,002 raw rows) in `data/raw/cse_cic_ids2018/`.
  - **UNSW-NB15**: 2 CSV files (`UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv`, 257,673 raw rows) in `data/raw/unsw_nb15/`.
- Pre-split deduplication (`Policy A`) purges duplicate rows and conflicting vectors:
  - On CSE-CIC-IDS2018, **4,496,789 rows (27.7%)** are dropped as label conflicts (`reject_conflicts`), and an additional 2,944,601 feature duplicates are dropped, leaving 8,312,295 modeling rows.
  - On CIC-IDS2017, **319,537 rows (11.3%)** are dropped, leaving 1,779,322 modeling rows.

### 4.2 Canonical R10 Feature Contract Verification Table

| Feature Name | Training Contract Definition | Live Flow Extraction Definition | Units | Training Preprocessing | Source Code Location | Parity Status |
| :--- | :--- | :--- | :---: | :--- | :--- | :---: |
| `flow_duration_ms` | `Flow Duration / 1000.0` (µs to ms) | `(t_last - t_first) * 1000.0` | ms | RobustScaler (Train-only) | [`features/compute.py`](../../src/xrlids/features/compute.py#L45-L65) / [`demo/extractor.py`](../../src/xrlids/demo/extractor.py#L50-L75) | **PASS** ($\text{atol} \le 10^{-4}$) |
| `flow_packets_per_s` | `Total Fwd + Bwd Packets / (Duration_s)` | `Total Packets / max(duration_s, 1e-6)` | pkts/s | RobustScaler (Train-only) | [`features/compute.py`](../../src/xrlids/features/compute.py) / [`demo/extractor.py`](../../src/xrlids/demo/extractor.py) | **PASS** |
| `flow_bytes_per_s` | `Total Bytes / (Duration_s)` | `Total IP Payload Bytes / max(duration_s, 1e-6)` | bytes/s | RobustScaler (Train-only) | [`features/compute.py`](../../src/xrlids/features/compute.py) / [`demo/extractor.py`](../../src/xrlids/demo/extractor.py) | **PASS** |
| `packet_length_mean` | `Total IP length mean` across all packets | Mean packet length across flow packets | bytes | RobustScaler (Train-only) | [`features/compute.py`](../../src/xrlids/features/compute.py) / [`demo/extractor.py`](../../src/xrlids/demo/extractor.py) | **PASS** |
| `packet_length_std` | Sample standard deviation (`ddof=0` in pipeline) | Population std (`np.std(ddof=0)`) | bytes | RobustScaler (Train-only) | [`features/compute.py`](../../src/xrlids/features/compute.py) / [`demo/extractor.py`](../../src/xrlids/demo/extractor.py) | **PASS** |
| `syn_count` | Sum of forward + backward TCP SYN packets | Count of TCP packets with SYN=1 | count | RobustScaler (Train-only) | [`features/compute.py`](../../src/xrlids/features/compute.py) / [`demo/extractor.py`](../../src/xrlids/demo/extractor.py) | **PASS** |
| `ack_count` | Sum of forward + backward TCP ACK packets | Count of TCP packets with ACK=1 | count | RobustScaler (Train-only) | [`features/compute.py`](../../src/xrlids/features/compute.py) / [`demo/extractor.py`](../../src/xrlids/demo/extractor.py) | **PASS** |
| `rst_count` | Sum of forward + backward TCP RST packets | Count of TCP packets with RST=1 | count | RobustScaler (Train-only) | [`features/compute.py`](../../src/xrlids/features/compute.py) / [`demo/extractor.py`](../../src/xrlids/demo/extractor.py) | **PASS** |
| `fin_count` | Sum of forward + backward TCP FIN packets | Count of TCP packets with FIN=1 | count | RobustScaler (Train-only) | [`features/compute.py`](../../src/xrlids/features/compute.py) / [`demo/extractor.py`](../../src/xrlids/demo/extractor.py) | **PASS** |
| `syn_ack_ratio` | `syn_count / (ack_count + 1e-5)` | `syn_count / (ack_count + 1e-5)` | ratio | RobustScaler (Train-only) | [`features/compute.py`](../../src/xrlids/features/compute.py) / [`demo/extractor.py`](../../src/xrlids/demo/extractor.py) | **PASS** |

---

## 5. Random Forest Audit

### 5.1 Training Hyperparameters & Execution Path
- **Entry Point**: `scripts/phase1/run_experiment.py` invoking `RandomForestDetector` ([`src/xrlids/models/random_forest.py`](../../src/xrlids/models/random_forest.py)).
- **Hyperparameters**: `n_estimators=100`, `criterion="gini"`, `class_weight="balanced_subsample"`, `random_state=42`, `n_jobs=4`.
- **Pre-Processing**: `RobustScaler` fit on $X_{\text{train}}$ only. Zero target leakage.
- **Output Column Order**: Verified column 1 corresponds strictly to positive attack class ($P(y=1)$).

### 5.2 Held-Out Random-Split Performance vs. Strict Temporal Holdout
- **Random Split (CIC-IDS2017)**:
  - Test Population: 355,833 flows (18.2% attack prevalence).
  - Metrics: Accuracy = **0.9815**, Precision = **0.9587**, Recall = **0.9438**, F1 = **0.9512**, PR-AUC = **0.9824**, ROC-AUC = **0.9968**.
- **Random Split (CSE-CIC-IDS2018)**:
  - Test Population: 1,662,419 flows (11.3% attack prevalence).
  - Metrics: Accuracy = **0.9723**, Precision = **0.8242**, Recall = **0.9580**, F1 = **0.8861**, PR-AUC = **0.9676**, ROC-AUC = **0.9902**.
- **Strict Temporal Holdout (CSE-CIC-IDS2018, GAP-P06)**:
  - Setup: Train 14–20 Feb 2018 (5,053,051 flows); Test 22 Feb–2 Mar 2018 (1,631,630 flows).
  - Metrics: Accuracy = **0.9633**, Precision = **0.0332**, Recall = **0.0068**, F1 = **0.0113** [0.0101, 0.0124], ROC-AUC = **0.3905**.
  - **Audit Finding**: The collapse is primarily driven by: (1) Attack scheduling (future days introduce entirely novel attack families like Infiltration and Web Attacks that never occurred in training), and (2) Pre-split deduplication removing recurring baseline normal traffic vectors from the future evaluation window.

---

## 6. LSTM Audit

### 6.1 Architecture & Sequence Construction
- **Architecture**: 2-layer recurrent network with hidden dimension $h=32$, dropout $p=0.10$, sequence length $T=5$, followed by a linear classification head:
  $$\text{Input Tensor Shape}: (N, 5, 10) \to \text{LSTM} \to \text{Linear}(32 \to 1) \to \text{Sigmoid}$$
- **Sequence Generation Mechanism**:
  - Implemented in `build_sequences` ([`src/xrlids/models/lstm.py`](../../src/xrlids/models/lstm.py#L141-L215)).
  - Sequences slide across adjacent rows in CSV file order within each split.
  - Rows from the beginning of each file ($T-1 = 4$ rows) are dropped to prevent boundary crossing ($8 \times 4 = 32$ rows dropped in CIC-IDS2017).
  - Sequences **never cross split boundaries** (L-06 enforced by construction).

### 6.2 Sequence Order Locality Ablation
- **Ablation Finding**: In benchmark CSV files, attack flows are recorded in large contiguous blocks during scheduled exercises. Sliding a window of $T=5$ across contiguous rows allows previous flows $t-4 \dots t-1$ to act as attack-burst label hints.
- **Empirical Shuffled Ablation (`run_lstm_temporal_ablation.py`)**:
  - Random Forest Tabular: $F_1 = 0.9660$
  - Ordered LSTM ($T=5$): $F_1 = 0.9314$
  - Shuffled LSTM ($T=5$ permuted): $F_1 = 0.9353$
  - Order-Locality Delta ($\Delta F_1$): $-0.0038$.
  - **Verdict**: The sequence model does **not** capture meaningful physical packet chronology; without IP/session-level tracking, it behaves essentially as a non-linear tabular aggregator.

---

## 7. Fusion Audit

### 7.1 Mathematical Formulation & In-Code Evidence
- In `src/xrlids/models/fusion.py` ([lines 85-100](../../src/xrlids/models/fusion.py#L85-L100)):
  $$S_{\text{fusion}} = \alpha \cdot S_{\text{RF}} + (1 - \alpha) \cdot S_{\text{LSTM}}$$
- **Probability vs. Score**: The inputs are uncalibrated continuous scores: $S_{\text{RF}} \in [0, 1]$ represents tree-vote proportions, while $S_{\text{LSTM}} \in [0, 1]$ represents sigmoid outputs trained on unweighted BCE. They are not formally calibrated probabilities.

### 7.2 Multi-Benchmark Empirical Comparison Table (Aligned Test Populations)

| Benchmark Dataset | Aligned Evaluation Population ($N$) | Tuned Weight ($\alpha$) | RF Alone ($F_1$) | LSTM Alone ($F_1$) | Fusion Score ($F_1$) | Absolute Gain ($\Delta F_1$) | Statistical Significance ($p$-value) |
| :--- | ---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **CIC-IDS2017** | 355,833 | $\alpha = 0.50$ | 0.9512 | 0.9633 | **0.9745** | **+0.0233 vs RF** | $p < 0.0001$ *** |
| **CSE-CIC-IDS2018** | 1,662,419 | $\alpha = 0.00$ | 0.8861 | **0.9603** | **0.9603** | **+0.0000 vs LSTM** | N/A (Identical to LSTM) |
| **UNSW-NB15** (R4) | 24,496 | $\alpha = 0.60$ | 0.8548 | 0.8637 | **0.8970** | **+0.0422 vs RF** | $p < 0.0001$ *** |

### 7.3 Audited Claims Separation
- **Mathematically Implemented Correctly**: **YES**. Population alignment (`align_scores`) and weighted blending are error-checked and verified by unit tests.
- **Empirically Justified**: **PARTIAL**. Justified on CIC-IDS2017 and UNSW-NB15. On CSE-CIC-IDS2018, $\alpha$ collapsed to 0.00, demonstrating zero complementarity on the largest enterprise dataset.
- **Production-Integrated**: **NO**. The live monitor pipeline in `dashboard/server.py` and `src/xrlids/live/` evaluates only tabular Random Forest.

---

## 8. SHAP Audit

### 8.1 Model Scope & Attribution Mechanics
- **Target Model**: TreeSHAP is executed **strictly on the tabular Random Forest**. It does not explain the LSTM or Fusion scores.
- **Background Population**: 100 k-means cluster prototypes computed from $X_{\text{train}}$.
- **Additive Consistency**: Verified exact additive property: $\sum \phi_i + \text{base\_value} = f(x)$.

### 8.2 Traceable End-to-End Decision Record (Audit Card 0)
- **Trace Provenance**: `results/phase2/EXP-P2E-EXPLAINABILITY-001/audit_records.json` (Card 0):
  - **Input Metadata**: `timestamp = "2026-10-04T09:02:20Z"`, `flow_id = 0`, `host_id = "host_0"`.
  - **Feature Measurements**:
    - `packet_length_std = 1425.15` bytes
    - `flow_packets_per_s = 0.1626` pkts/s
    - `flow_bytes_per_s = 138.44` bytes/s
  - **Perception Layer Output**:
    - Random Forest Threat Score: $S_t = \mathbf{0.9934}$ (Severe Attack Risk)
    - TreeSHAP Feature Attributions:
      1. `packet_length_std`: $\phi = \mathbf{+0.2107}$ (Pushes strongly toward Attack)
      2. `flow_packets_per_s`: $\phi = \mathbf{-0.1378}$
      3. `flow_bytes_per_s`: $\phi = \mathbf{-0.1143}$
  - **Policy Layer (DQN)**:
    - Input State: $s_t = [0.9934, 0.0, 1.0, 0.0, 0.0, 0.267]$
    - Q-Values: $\text{ALLOW} = -108.84, \text{ALERT} = -19.72, \text{RATE\_LIMIT} = -22.56, \text{ISOLATE} = \mathbf{-12.36}$
    - Selected Action: `ISOLATE` (Decision Margin = $7.359$)
  - **Deterministic Safety Gate**:
    - Invariants Evaluated: `CRITICAL_INFRASTRUCTURE_EXEMPTION`, `MANDATORY_ACTION_COOLDOWN`, `BLAST_RADIUS_CIRCUIT_BREAKER`
    - Action Overruled: `TRUE`
    - Override Reason: `CRITICAL_INFRASTRUCTURE_EXEMPTION` (Target is designated gateway/DNS)
    - **Final Enforced Action**: **`ALERT`**

---

## 9. Deep Q-Network (DQN) Audit

### 9.1 Network Topology & State Space
- **Architecture**: Dueling DQN ([`src/xrlids/response/dqn/network.py`](../../src/xrlids/response/dqn/network.py)):
  - Input: 6-dimensional state vector $s_t \in \mathbb{R}^6$
  - Backbone: `Linear(6 -> 64) -> LayerNorm -> LeakyReLU(0.01) -> Linear(64 -> 64) -> LayerNorm -> LeakyReLU(0.01)`
  - Value Stream: `Linear(64 -> 32) -> LeakyReLU -> Linear(32 -> 1)` $\to V(s)$
  - Advantage Stream: `Linear(64 -> 32) -> LeakyReLU -> Linear(32 -> |A|)` $\to A(s, a)$
  - Dueling Aggregation: $Q(s, a) = V(s) + A(s, a) - \frac{1}{|A|}\sum_{a'} A(s, a')$
- **State Vector Dimensions**:
  - $s_0$: Instantaneous threat score $S_t \in [0, 1]$
  - $s_1$: Threat trajectory $\Delta S_t \in [-1, 1]$ ($S_t - \text{mean}(S_{t-k \dots t-1})$)
  - $s_2$: Alert density $N_{\text{alert}} \in [0, 1]$ (Fraction of past $W=20$ flows $\ge 0.50$)
  - $s_3$: Previous action $a_{t-1} / 3.0 \in [0, 1]$
  - $s_4$: Active cooldown fraction $c_t \in [0, 1]$
  - $s_5$: Volumetric intensity $v_t = \log_{10}(1 + \text{bytes\_per\_s}) / 8.0 \in [0, 1]$

### 9.2 Nature of the Environment: Contextual Bandit vs. Sequential MDP
- **Audit Finding**: In `src/xrlids/response/environment.py`, incoming flows $x_{t+1}$ and true labels $y_{t+1}$ are fed from an exogenous, pre-recorded trace. Taking an action $a_t$ (e.g., isolating a host or rate-limiting a flow) does **not** change which flow arrives next or alter packet headers.
- **Verdict**: The environment is fundamentally a **Contextual Bandit with local state feedback ($a_{t-1}$ and cooldown)**. Using discount factor $\gamma = 0.95$ does not model dynamic environment transitions; it averages future costs of an exogenous flow sequence.

---

## 10. Reward & Cost Function Audit

### 10.1 Mathematical Cost Specification
In `src/xrlids/response/costs.py`, the step loss function is defined as:
$$\mathcal{L}(s_t, a_t, y_t) = C_{\text{base}}(a_t, y_t) + C_{\text{chatter}}(a_t, a_{t-1}) + C_{\text{fatigue}}(N_{\text{consecutive\_alerts}})$$
$$\text{Reward } R_t = -\mathcal{L}(s_t, a_t, y_t)$$

### 10.2 Operational Research Cost Matrices ($C_{\text{base}}$)

| Cost Regime | Ground Truth Label ($y$) | ALLOW | ALERT | RATE_LIMIT | ISOLATE |
| :--- | :--- | ---:| ---:| ---:| ---:|
| **Standard Enterprise (Balanced)** | $y = 0$ (Benign)<br>$y = 1$ (Attack) | 0.0<br>100.0 | 1.0<br>12.0 | 15.0<br>6.0 | 60.0<br>2.0 |
| **High Availability (Conservative)** | $y = 0$ (Benign)<br>$y = 1$ (Attack) | 0.0<br>50.0 | 1.0<br>12.0 | 30.0<br>6.0 | 120.0<br>2.0 |
| **High Security Enclave (Aggressive)** | $y = 0$ (Benign)<br>$y = 1$ (Attack) | 0.0<br>500.0 | 1.0<br>20.0 | 5.0<br>10.0 | 25.0<br>2.0 |

- **Penalties**: Chattering penalty $C_{\text{chatter}} = 5.0$ if switching across tiers while in cooldown; Fatigue penalty $C_{\text{fatigue}} = 0.5 \times \text{consecutive\_alerts}$.

---

## 11. Baseline & Statistical Audit (Held-Out Test Data)

### 11.1 Evaluated Population & Comparators
- **Population**: Single pass over held-out $D_{\text{pol\_test}}$ (355,865 tabular flows from CIC-IDS2017).
- **Baselines Evaluated**:
  - **Baseline 0**: Always ALLOW (Zero defense reference).
  - **Baseline 1**: Single Threshold ($\tau = 0.50$).
  - **Baseline 2**: Two-Tier Graded Threshold ($\tau_{\text{suspect}}=0.40, \tau_{\text{isolate}}=0.75$) — **Best Deterministic Comparator**.
  - **Baseline 3**: Heuristic State Machine with 30-step escalation/cooldown.
  - **Baseline 4**: Analytic Bayes Cost-Optimal Threshold Policy ($p^* \approx 0.138$).

### 11.2 Empirical Performance Matrix ($D_{\text{pol\_test}}$, 355,865 Flows)

| Regime | Action Space | Policy | Mean Cost/Flow | FQR | BAS | ACI | Contained Attacks | Uncontained Attacks |
| :--- | :---: | :--- | ---:| ---:| ---:| ---:| ---:| ---:|
| **Standard Enterprise** | 3-action | `DQN_Candidate_3-action` | **1.4208** | 0.00% | 96.51% | 0.0019 | 60,449 | 4,371 |
| Standard Enterprise | 3-action | `Baseline_2_Two_Tier` | 1.6017 | 0.00% | 97.82% | 0.0294 | 63,467 | 1,353 |
| Standard Enterprise | 3-action | `Baseline_1_Single_Threshold` | 1.6912 | 0.00% | 97.96% | 0.0357 | 64,180 | 640 |
| Standard Enterprise | 3-action | `Baseline_0_Always_ALLOW` | 18.2148 | 0.00% | 100.00% | 0.0000 | 0 | 64,820 |
| **Standard Enterprise** | 4-action | `DQN_Candidate_4-action` | **5.3256** | 0.20% | 96.52% | 0.0214 | 10,285 | 54,535 |
| Standard Enterprise | 4-action | `Baseline_2_Two_Tier` | 6.1996 | 0.31% | 97.82% | 0.0270 | 5,859 | 58,961 |
| Standard Enterprise | 4-action | `Baseline_1_Single_Threshold` | 7.4794 | 0.55% | 97.96% | 0.0230 | 5,130 | 59,690 |

### 11.3 Paired Bootstrap Hypothesis Testing ($B = 1,000$ Resamples)

| Regime | Action Space | Comparison Pair | Mean Cost Delta | 95% Bootstrap CI | Rel. Reduction ($\Delta \mathcal{C}_{\text{rel}}$) | $p$-value | Pre-Registered Target ($\ge 15.0\%$) |
| :--- | :---: | :--- | ---:| :---: | ---:| ---:| :---: |
| Standard Enterprise | 3-action | `DQN` vs `Baseline_2 (Two-Tier)` | -0.1809 | [-0.1919, -0.1691] | **+11.29%** | $p < 0.001$ | **NOT MET** |
| Standard Enterprise | 4-action | `DQN` vs `Baseline_2 (Two-Tier)` | -0.8740 | [-0.9147, -0.8312] | **+14.10%** | $p < 0.001$ | **NOT MET** |
| High Availability | 3-action | `DQN` vs `Baseline_2 (Two-Tier)` | -0.2096 | [-0.2187, -0.2002] | **+12.17%** | $p < 0.001$ | **NOT MET** |
| High Availability | 4-action | `DQN` vs `Baseline_2 (Two-Tier)` | -0.9002 | [-0.9429, -0.8547] | **+14.19%** | $p < 0.001$ | **NOT MET** |
| High Security | 3-action | `DQN` vs `Baseline_2 (Two-Tier)` | -0.3163 | [-0.3693, -0.2615] | **+11.20%** | $p < 0.001$ | **NOT MET** |
| High Security | 4-action | `DQN` vs `Baseline_2 (Two-Tier)` | -1.1355 | [-1.1998, -1.0700] | **+14.18%** | $p < 0.001$ | **NOT MET** |

---

## 12. Safety Gate & Rollback Audit

### 12.1 Deterministic Safety Gate Invariants
- **Non-Bypassable Hook**: Evaluated in `src/xrlids/response/safety.py`:
  1. **Critical Infrastructure Exemption**: Host endpoints designated in `protected_sources.yaml` (e.g., DNS, default gateways, auth servers) are strictly barred from `ISOLATE` or `RATE_LIMIT` actions. Proposed isolations are downgraded to `ALERT`.
  2. **Mandatory Action Cooldown**: Endpoints cannot oscillate between actions within a 30-step window. De-escalation requests during cooldown maintain the existing active action.
  3. **Blast Radius Circuit Breaker**: Quarantined hosts cannot exceed 5.0% of total known endpoints.
  4. **Action Clamp**: Strict enforcement of 3-action mode (intercepting and converting any `ISOLATE` action into `RATE_LIMIT`).

### 12.2 Atomic Response Transaction & Rollback Harness
- Evaluated in `src/xrlids/response/transaction.py` and `src/xrlids/enforcement/lab.py`:
  - **HostNetworkBaseline**: Takes cryptographic SHA-256 snapshots of iptables rules, routing tables, and interface states prior to mitigation.
  - **Watchdog TTL**: Actions auto-revert via compensating commands if health checks fail or watchdog timers expire.
  - **Zero Host Mutation Guarantee**: Validated strictly inside Linux virtual network namespaces (`10.200.1.0/24`). Cryptographic baseline comparison proves **exactly zero host network mutations** (`pre == post` SHA-256).

---

## 13. Production Integration Audit

### 13.1 End-to-End Pipeline Connectivity Trace

```text
Input Packets
  │ (Real: AF_PACKET / Scapy PCAP)
  ▼
BidirectionalFlowBuilder (Decision D-006: FIN/RST + 120s timeout)
  │ (Real: Pure Python flow accumulation)
  ▼
Feature Extractor (R10 Canonical Contract)
  │ (Real: Numerical parity atol <= 1e-4)
  ▼
Preprocessor (RobustScaler fitted on train)
  │ (Real: In-memory transform)
  ▼
Random Forest Classifier (100 trees, frozen)
  │ (Real: In-memory inference < 0.5 ms/flow)
  ▼
Threat Score S_t
  │
  ├──► [OFFLINE RESEARCH ONLY] LSTM & Fusion (Not run in live monitor)
  ├──► [DEMO ONLY] TreeSHAP Feature Attribution
  └──► DQN State Builder s_t in R^6
         │ (Real: In-memory state tracking)
         ▼
       DQN Agent Action a_proposed
         │ (Real: Forward pass through PyTorch net)
         ▼
       Deterministic Safety Gate
         │ (Real: Non-bypassable invariant checking)
         ▼
       Enforcement Layer (NetnsActuator / Rollback Harness)
         │ [SIMULATED / LAB NAMESPACE ONLY: Zero real host mutations]
         ▼
       Audit Logging (Decision Cards)
```

---

## 14. Report Inconsistencies & Numerical Reconciliations

1. **Test Population Count (355,833 vs. 355,865)**:
   - **Resolution**: 355,865 is the exact count of deduplicated tabular flows in $D_{\text{pol\_test}}$. When sequence models ($T=5$) are constructed across 8 separate capture files, dropping 4 boundary rows per file removes 32 rows ($355,865 - 32 = 355,833$). Both numbers are correct within their respective evaluation domains.
2. **Conservative Regime Delta (+2.05% vs. +12.17% / +14.19%)**:
   - In `PHASE2_FINAL_REPORT.md`, High Availability is evaluated against Two-Tier Baseline 2 (+12.17% in 3-action, +14.19% in 4-action). In `FINAL_RESEARCH_REPORT.md`, Conservative is evaluated against a Static-Alert baseline where false isolation penalties are heavily penalized, compressing the gain to +2.05% ($p = 0.082$).
3. **Pre-Registered 15% Criterion**:
   - Reconciled clearly: In all scenarios against the best deterministic baseline (Baseline 2), the DQN achieves 11.2% to 14.2% cost reduction. Statistical significance is met ($p < 0.001$), but practical significance ($\ge 15.0\%$) is **NOT MET**.

---

## 15. Reproducibility Commands

```bash
# 1. Activate environment
source .venv/bin/activate

# 2. Run full test verification suite (419 tests)
.venv/bin/pytest -q

# 3. Reproduce offline PCAP replay demo
python scripts/demo/run_replay_demo.py

# 4. Reproduce LSTM Sequence Locality Ablation
python scripts/phase1/run_lstm_temporal_ablation.py --sample-limit 3000 --epochs 4

# 5. Reproduce Ambiguous Traffic & Bayes Limits Evaluation
python scripts/phase1/evaluate_ambiguous_traffic.py --sample-limit 10000

# 6. Launch Hardened Dashboard
python dashboard/server.py 8000
```

---

## 16. Findings Ranked by Severity

### Critical Severity
- **FIND-01: Headline Accuracy Masks Ambiguous Conflicting Manifold**:
  - *Location*: `src/xrlids/datasets/population.py` (`reject_conflicts`).
  - *Impact*: Purging 27.7% of CSE-2018 flows creates an artificially clean separable manifold. On ambiguous vectors, accuracy is bounded by a ~64.3% Bayes ceiling.

### High Severity
- **FIND-02: DQN Failed Pre-Registered Practical Significance**:
  - *Location*: `docs/phase2/PHASE2_FINAL_REPORT.md` (RQ7).
  - *Impact*: The DQN achieved an 11–14% cost reduction over Baseline 2, failing the $\ge 15.0\%$ target. It does not justify unconstrained autonomous deployment.
- **FIND-03: Action Chattering Under Sensor Noise**:
  - *Location*: `results/phase2/EXP-P2D-ROBUSTNESS-001/score_jitter_robustness.json`.
  - *Impact*: Score noise causes high action instability ($\text{ACI} \approx 0.11 > 0.05$).

### Medium Severity
- **FIND-04: LSTM Sequence Locality Artifact**:
  - *Location*: `src/xrlids/models/lstm.py` (`build_sequences`).
  - *Impact*: Consecutive CSV rows without host grouping create artificial attack-burst locality.
- **FIND-05: Contextual Bandit Formulation**:
  - *Location*: `src/xrlids/response/environment.py`.
  - *Impact*: Actions do not mutate incoming flow streams; $\gamma = 0.95$ lacks physical transition grounding.

---

## 17. Fix Recommendations with Exact File Paths

1. **Dashboard Wording & Disclaimers**: Update `dashboard/app.js` and `dashboard/index.html` to clearly distinguish tabular RF inference from offline LSTM/Fusion research and highlight that live mode operates without ground-truth labels.
2. **Contextual Bandit Baseline**: In `scripts/phase2/run_phase2a_baselines.py`, integrate `CostOptimalThresholdPolicy` and a $\gamma=0$ DQN variant.
3. **Safe Production Mode**: Restrict live enforcement strictly to `alert-only` mode; keep disruptive mitigation locked to isolated Linux network namespaces.

---

## 18. Staged Remediation Plan

- **Stage 1 (Immediate - Complete)**: Fix LSTM `best_state` bug, fix population conflict counters, harden dashboard server against CSRF/traversal, add Baseline 4 Bayes optimal threshold policy.
- **Stage 2 (Ablation Documentation - Complete)**: Execute shuffled-window ablation and document Bayes limits on ambiguous traffic.
- **Stage 3 (Viva Defense Preparation)**: Package examiner-facing defense scripts and thesis disclaimers.

---

## 19. Explicit List of Unverified Claims

- **Production Deployment Readiness**: UNVERIFIED. (Validated only in offline benchmarks and virtual lab namespaces).
- **Physical Packet Arrival Chronology in LSTM**: REFUTED / UNVERIFIED. (Sequences reflect CSV row order).
- **DQN Superiority Under Severe Noise**: REFUTED. (Chattering exceeds stability bounds).

---

## 20. Final Go / No-Go Decision

- **Offline Research & Academic Dissertation**: **GO (HIGH DISTINCTION READY)**. The methodological honesty, rigorous negative findings, and deterministic safety architecture represent exceptional academic quality.
- **Unrestricted Production Deployment**: **NO-GO**. The DQN must remain in **Alert-Only / Advisory Mode** with disruptive actions strictly gated by human analysts or restricted to authorized lab testbeds.
