# XRLIDS Model Artifacts & Registry

This directory contains the canonical trained model weights and artifact registry for the XRLIDS framework.

> **CIC-IDS2017 LSTM checkpoint note (2026-10-29):** the canonical `lstm_cicids2017.pt` was replaced with the seed-42 checkpoint that carries the real `best_epoch`, `best_val_loss`, and training `history`. The model weights are bit-identical to the previous canonical file; only the metadata payload and file checksum changed. Historical `results/verification/FINAL-CLOSURE-*` records refer to the previous checksum.
>
> **Fusion metadata note (2026-10-29):** `fusion_weights.json` previously declared `"calibrated": true`. The alpha values are unchanged, but the flag was corrected to `"probability_calibrated": false` because the convex blend is not a calibrated probability.

## Structure

```
models/
├── rf/                  # Random Forest classifiers (.joblib)
│   ├── random_forest_cicids2017.joblib   # Trained on CIC-IDS2017 R10 (Test Acc: 0.9815, F1: 0.9512)
│   ├── random_forest_cse2018.joblib      # Trained on CSE-CIC-IDS2018 R10 (Test Acc: 0.9723, F1: 0.8861)
│   └── random_forest_unswnb15.joblib     # Trained on UNSW-NB15 R4 (Test Acc: 0.8590, F1: 0.8548)
├── lstm/                # PyTorch LSTM temporal sequence models (.pt)
│   ├── lstm_cicids2017.pt                # Trained on CIC-IDS2017 R10 (Test Acc: 0.9867, F1: 0.9633)
│   ├── lstm_cse2018.pt                   # Trained on CSE-CIC-IDS2018 R10 (Test Acc: 0.9912, F1: 0.9603)
│   └── lstm_unswnb15.pt                  # Trained on UNSW-NB15 R4 (Test Acc: 0.8683, F1: 0.8637)
├── dqn/                 # Dueling Deep Q-Networks with Prioritized Replay (.pt)
│   ├── dqn_4action_best.pt               # 4-Action response agent (ALLOW, ALERT, RATE_LIMIT, ISOLATE)
│   └── dqn_3action_best.pt               # 3-Action response agent (ALLOW, ALERT, RATE_LIMIT)
├── fusion/              # Score-level fusion configurations (.json)
│   └── fusion_weights.json               # Score-level convex fusion (alpha tuned on validation; no probability calibration):
│                                         #   Primary: CIC-IDS2017 (99.06%), CSE-CIC-IDS2018 (99.12%) -> 99.11% population-weighted mean
│                                         #   Auxiliary: UNSW-NB15 (89.96%, alpha=0.60)
└── registry/            # Machine-readable artifact registries
    ├── model_manifest.json               # JSON registry with SHA-256 hashes and metadata
    └── registry.yaml                     # YAML registry conforming to FR-020
```

## Headline Performance Summary (Aligned Test Sets)

### Primary Flagship Dual-Benchmark (95%+ Target Exceeded Across 2.01M Test Flows)

| Dataset | Feature Contract | Model Architecture | Test Accuracy | Test F1 Score | Test ROC-AUC | Test PR-AUC | Population |
|:---|:---:|:---|:---:|:---:|:---:|:---:|---:|
| **CIC-IDS2017** | R10 (10 feat) | Random Forest | 0.9815 | 0.9512 | 0.9968 | 0.9824 | 355,833 |
| **CIC-IDS2017** | R10 (10 feat) | Supervised LSTM | 0.9867 | 0.9633 | 0.9974 | 0.9904 | 355,833 |
| **CIC-IDS2017** | R10 (10 feat) | **RF + LSTM Fusion ($\alpha=0.50$)** | **0.9906 (99.06%)** | **0.9745** | **0.9989** | **0.9947** | 355,833 |
| **CSE-CIC-IDS2018** | R10 (10 feat) | Random Forest | 0.9723 | 0.8861 | 0.9902 | 0.9676 | 1,662,419 |
| **CSE-CIC-IDS2018** | R10 (10 feat) | **Supervised LSTM** | **0.9912 (99.12%)** | **0.9603** | **0.9966** | **0.9865** | 1,662,419 |
| **CSE-CIC-IDS2018** | R10 (10 feat) | **RF + LSTM Fusion ($\alpha=0.00$)\*** | **0.9912 (99.12%)** | **0.9603** | **0.9966** | **0.9865** | 1,662,419 |
| **Population-weighted mean (CIC + CSE)** | **R10** | **Descriptive aggregate; not a single model** | **0.9911 (99.11%)** | — | — | — | **2,018,252** |

> \* **Note on CSE-CIC-IDS2018 Fusion ($\alpha=0.00$):** In `models/fusion/fusion_weights.json`, the optimal fusion weight for CSE-2018 is $\alpha = 0.00$. The Random Forest contributes 0% weight, making this result mathematically and empirically identical to the single LSTM detector, NOT evidence of multi-model synergy.
>
> **Note on Population Reconciliation (355,865 vs 355,833 Flows):** The tabular held-out test split contains **355,865 flows** (evaluated by Random Forest and the Phase 2 response simulator). Sequence models (LSTM and Fusion) drop $(T - 1) = 4$ initial boundary flows from each of the 8 capture files to prevent sequences crossing file boundaries, yielding **355,833 sequence-aligned flows** ($355,865 - (8 \times 4) = 355,833$). Both counts evaluate the exact same underlying population.

### Auxiliary Benchmark (Degraded 4-Feature NetFlow Schema)

| Dataset | Feature Contract | Model Architecture | Test Accuracy | Test F1 Score | Test ROC-AUC | Test PR-AUC | Population |
|:---|:---:|:---|:---:|:---:|:---:|:---:|---:|
| **UNSW-NB15** | R4 (4 feat) | Random Forest | 0.8590 | 0.8548 | 0.9487 | 0.9323 | 24,496 |
| **UNSW-NB15** | R4 (4 feat) | Supervised LSTM | 0.8683 | 0.8637 | 0.9334 | 0.8903 | 24,496 |
| **UNSW-NB15** | R4 (4 feat) | **RF + LSTM Fusion ($\alpha=0.60$)** | **0.8996 (89.96%)** | **0.8970** | **0.9674** | **0.9538** | 24,496 |

### Multi-Seed Robustness (Seeds 42 / 123 / 456)

All benchmarks re-run end-to-end with three seeds (population std); seed 42 reproduces the frozen predictions to floating-point tolerance (serialized joblib/`.pt` bytes can differ across library versions). Fusion detector, mean ± std:

| Dataset | Accuracy | F1 | ROC-AUC |
|:---|:---:|:---:|:---:|
| CIC-IDS2017 | 0.9903 ± 0.0005 | 0.9735 ± 0.0016 | 0.9986 ± 0.0002 |
| CSE-CIC-IDS2018 | 0.9912 ± 0.0001 | 0.9602 ± 0.0004 | 0.9965 ± 0.0000 |
| UNSW-NB15 | 0.8988 ± 0.0008 | 0.8963 ± 0.0006 | 0.9674 ± 0.0004 |

Full RF / LSTM / Fusion table: [`../reports/generated/multi_seed_report.md`](../reports/generated/multi_seed_report.md).

### DQN Response Policy (Held-Out `D_pol_test`, 355,865 Flows, `standard_enterprise` Regime)

DQN agents are reinforcement-learning policies, not classifiers — F1/accuracy do not apply. Checkpoints were selected by the pre-registered rule `pre_registered_minimum_validation_cost` on `mean_cost_per_flow`:

| Model | Selected Step | Validation Cost/Flow | Test Cost/Flow | Test FQR | Test BAS | Test ACI |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|
| `dqn_3action_best.pt` | 10,000 | 2.0437 | 1.4208 | 0.00% | 96.51% | 0.0019 |
| `dqn_4action_best.pt` | 45,000 | 2.2416 | 5.3256 | 0.20% | 96.52% | 0.0214 |

FQR = False Quarantine Rate · BAS = Business Availability Score · ACI = Action Chattering Index.
Source: `results/phase2/EXP-P2-FINAL-TEST-001/final_test_metrics.json` (full metric block in [`registry/model_manifest.json`](registry/model_manifest.json)).

> **Cost-Optimal Baseline Comparison (EXP-P2A-COST-OPTIMAL-001):**
> When evaluated against the zero-parameter analytic `CostOptimalThresholdPolicy` on the 355,865 held-out flows:
> - The Cost-Optimal baseline achieved lower operational cost than the trained DQN in **4 of 6 benchmark settings** (e.g. 20.12% lower cost in 4-action High Availability).
> - In the 2 settings where DQN had lower cost, its advantage was only ~8.8%, failing the pre-registered 15.0% target.
> - **Calibration Warning:** Raw Random Forest voting scores exhibit severe probability distortion in intermediate score bins (e.g. predicted 0.1335 vs observed 0.0137, ~10× overconfidence). Analytical thresholds are cost-optimal with respect to an assumed score, not proven Bayes-optimal under true attack risk.

## Model Verification & Integrity

Every artifact is cryptographically checksummed using SHA-256 in [`registry/model_manifest.json`](registry/model_manifest.json).
All models were trained deterministically under seed `42` with strict train-validation-test isolation (zero test leakage).

## Loading Models in Code

### Random Forest (Tabular Flow Classifier)
```python
import joblib
import pandas as pd
from xrlids.models.random_forest import RandomForestDetector

# Load the registered detector object
detector = joblib.load("models/rf/random_forest_cicids2017.joblib")

# predict_proba takes a pandas DataFrame with canonical R10 features
# and returns 1D P(attack) scores directly (np.ndarray):
probabilities = detector.predict_proba(X_test_df)
predictions = detector.predict(X_test_df, threshold=0.50)
```

### Supervised LSTM (Temporal Sequence Classifier)
```python
from xrlids.models.lstm import LSTMDetector

# Load checkpoint (includes model state_dict, sequence length, and hyperparameters)
detector = LSTMDetector.load("models/lstm/lstm_cicids2017.pt")

# The internal PyTorch sequence network is automatically set to eval mode:
# detector.model.eval()
```

### Autonomous Response DQN (Dueling Deep Q-Network)
```python
import torch
from xrlids.response.dqn.network import DuelingQNetwork

# Checkpoint contains online network weights, step count, and validation metrics
checkpoint = torch.load("models/dqn/dqn_4action_best.pt", map_location="cpu")

# 6-dimensional causal state vector: s_t = [S_t, ΔS_t, N_alert, a_(t-1), c_t, v_t]
q_net = DuelingQNetwork(input_dim=6, action_dim=4)
q_net.load_state_dict(checkpoint["online_net_state_dict"])
q_net.eval()
```
