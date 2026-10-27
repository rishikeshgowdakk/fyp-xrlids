# REPRODUCIBILITY

Goal: anyone cloning `fyp-xrlids` can set up the environment, verify committed model binaries, run tests, replay demonstrations, and independently audit or reproduce experimental results.

> **Status:** Environment pinned and reproducible. All 9 canonical model binaries, preprocessors, and test splits are physically committed to Git and 100% hash-verified. Raw benchmark CSVs (~8.7 GB across 20 files) remain uncommitted due to licensing and storage limits.

---

## 1. Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .            # editable install of the package
```

| Component | Pinned Version | Execution Mode |
|:---|:---:|:---|
| Python | `3.14.4` | CPython x86_64 Linux |
| PyTorch | `2.14.0+cpu` | Deterministic CPU (No GPU required) |
| scikit-learn | `1.9.1` | Deterministic CPU (`n_jobs=1` default) |
| NumPy | `2.5.3` | CPU |
| pandas | `3.0.6` | CPU |
| SHAP | `0.52.0` | TreeSHAP |
| pytest | `9.1.1` | Test Runner |

Verify runtime environment:
```bash
.venv/bin/python -m xrlids.cli info
```

---

## 2. Test Suite Execution (423 Tests)

```bash
.venv/bin/pytest -q
```

All **423 tests** across `tests/unit/` (329), `tests/data/` (45), `tests/integration/` (31), and `tests/model/` (18) pass with zero failures.

To run only the response policy and safety subsystem verification suite (43 tests):
```bash
.venv/bin/pytest tests/unit/test_response* -v
```

---

## 3. Canonical Model Verification (Committed Artifacts)

All 9 canonical models are tracked directly in Git and verify against [`models/registry/model_manifest.json`](models/registry/model_manifest.json):

```bash
.venv/bin/python scripts/phase2/run_phase2b_readiness_audit.py --out-dir results/phase2/EXP-P2B-READINESS-AUDIT-001
```

| Model Artifact | Type | Dataset | Feature Contract | SHA-256 Digest Match |
|:---|:---:|:---:|:---:|:---:|
| `models/rf/random_forest_cicids2017.joblib` | RF | CIC-IDS2017 | `R10` (10 features) | `7c6ad493b773b687...` (VERIFIED) |
| `models/rf/random_forest_cse2018.joblib` | RF | CSE-CIC-IDS2018 | `R10` (10 features) | `b7d2dc7bacca1a46...` (VERIFIED) |
| `models/rf/random_forest_unswnb15.joblib` | RF | UNSW-NB15 | `R4` (4 features) | `c432eb067507ad5b...` (VERIFIED) |
| `models/lstm/lstm_cicids2017.pt` | LSTM | CIC-IDS2017 | `R10` (Sequence $T=5$) | `18b0bfb48d3b031c...` (VERIFIED) |
| `models/lstm/lstm_cse2018.pt` | LSTM | CSE-CIC-IDS2018 | `R10` (Sequence $T=5$) | `ea5b8198c20faa15...` (VERIFIED) |
| `models/lstm/lstm_unswnb15.pt` | LSTM | UNSW-NB15 | `R4` (Sequence $T=5$) | `4d9386ff44c99eed...` (VERIFIED) |
| `models/dqn/dqn_4action_best.pt` | DQN | CIC-IDS2017 | `response_state_v1` (6D) | `6a5afc669b4e699e...` (VERIFIED) |
| `models/dqn/dqn_3action_best.pt` | DQN | CIC-IDS2017 | `response_state_v1` (6D) | `c06a61fb77775116...` (VERIFIED) |
| `models/fusion/fusion_weights.json` | Fusion | All | Score Combination | `fd50a413119d3ec3...` (VERIFIED) |

---

## 4. Evaluation Population Reconciliation (355,865 vs 355,833 Flows)

In CIC-IDS2017, evaluations use two mathematically consistent population numbers:

$$\text{Sequence Aligned Flows} = 355,865 - (8 \text{ capture files} \times 4 \text{ boundary flows dropped for } T=5) = 355,833$$

1. **Tabular Held-Out Split (355,865 flows):** Evaluated by the primary Random Forest detector and the Phase 2 offline response simulator (`d_pol_test_flows.joblib`). Evaluates all individual flows without temporal sequence constraints (291,045 benign, 64,820 attack).
2. **Sequence-Aligned Test Slice (355,833 flows):** Evaluated by the supervised LSTM and score-level Fusion models. For sequence length $T=5$, constructing causal sequences strictly within each capture file requires dropping the first $(T-1)=4$ flows of each file so sequences never cross unrelated capture files. Across the 8 capture files, exactly 32 flows (all benign) are dropped (291,013 benign, 64,820 attack).

---

## 5. Negative Research Findings & Reality Bounds

Scientific rigor requires reporting negative outcomes and empirical bounds rather than obscuring them:

1. **DQN vs. Zero-Parameter Analytic Baseline:**
   - In `EXP-P2A-COST-OPTIMAL-001` across 355,865 held-out test flows, the zero-parameter analytic `CostOptimalThresholdPolicy` achieves lower operational cost than the trained DQN in **4 out of 6 experimental settings**.
   - In 4-action High Availability, Cost-Optimal beats DQN by **20.12% lower cost** ($1,547,511.0$ vs $1,937,476.5$).
   - In the remaining 2 settings, DQN's cost reduction is only ~8.8%, failing the pre-registered 15.0% practical improvement target.
2. **CSE-CIC-IDS2018 Fusion Weight $\alpha = 0.00$:**
   - In [`models/fusion/fusion_weights.json`](models/fusion/fusion_weights.json), CSE-2018 has optimal $\alpha = 0.00$. The Random Forest contributes 0% weight, making the reported F1 of 0.9603 an **LSTM-only result**, not evidence of multi-model synergy.
3. **Temporal Generalization Collapse:**
   - On CSE-CIC-IDS2018, when tested on genuine chronological future days (`EXP-P1-CSE2018-TEMPORAL-R10-001`), Random Forest test F1 collapses from 0.8861 down to **0.0113** (bot recall drops from 99.17% to 0.09%). In-domain 99% accuracy figures do not indicate future-day robustness.
4. **Causal Reality of the Simulator:**
   - Network flow arrivals are strictly exogenous replay. Actions do not alter future traffic, attacker behaviors, or packet inter-arrival times. Setting $\gamma = 0.95$ optimizes noise correlations across 20 steps of exogenous traffic. The problem is properly modeled as an **Asymmetric-Loss Contextual Decision Policy with Hysteresis Constraints**.
5. **Statistical Bootstrap Bounds:**
   - Empirical p-values reported as `0.0` from $B=1,000$ resamples are bounded by finite Monte Carlo resolution: $p < 1/(B+1) = 0.000999 < 0.001$. Flow-level i.i.d. resampling understates uncertainty due to temporal attack burst clustering.

---

## 6. Task-by-Task Reproducibility Matrix

| Evaluation Task | Executable Command | Required Datasets / Artifacts | Reproduction Status | Output Artifact |
|:---|:---|:---|:---:|:---|
| **Response Unit Tests** | `pytest tests/unit/test_response* -v` | Repository code only | **REPRODUCIBLE** | 43 passed (0.60s) |
| **Full Verification Suite** | `pytest -q` | Repository code only | **REPRODUCIBLE** | 423 passed (40.5s) |
| **Phase 2B Readiness Audit** | `python scripts/phase2/run_phase2b_readiness_audit.py` | Committed models & registries | **REPRODUCIBLE** | `results/phase2/EXP-P2B-READINESS-AUDIT-001/` |
| **Phase 2A Cost-Optimal Benchmark** | `python scripts/phase2/run_phase2a_cost_optimal_comparison.py` | `d_pol_test_flows.joblib`, DQN models | **REPRODUCIBLE** | `results/phase2/EXP-P2A-COST-OPTIMAL-001/` |
| **PCAP Offline Replay Demo** | `python scripts/demo/run_replay_demo.py` | Bundled sample PCAP & RF model | **REPRODUCIBLE** | `results/demo/replay_summary.json` |
| **Web Dashboard Startup** | `python dashboard/server.py` | Committed models & replay data | **REPRODUCIBLE** | HTTP Port 8000 |
| **Detector Training from Scratch** | `python scripts/phase1/run_experiment.py` | External raw CSVs (~8.7 GB) | **REQUIRES RAW DATA** | `data/raw/` download needed |

---

## 7. Raw Dataset Acquisition (For Retraining Only)

Raw datasets are not required to run tests, load models, replay PCAPs, launch the dashboard, or evaluate the response policies. If you wish to retrain models from scratch:

```bash
# Display download URLs and placement instructions:
.venv/bin/python scripts/phase1/prepare_dataset.py instructions

# Verify checksums after placing files in data/raw/<dataset>/:
.venv/bin/python scripts/phase1/prepare_dataset.py verify --dataset cicids2017
```
