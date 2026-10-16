# XRLIDS Model Artifacts & Registry

This directory contains the canonical trained model weights and artifact registry for the XRLIDS framework.

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
│   └── fusion_weights.json               # Calibrated convex fusion achieving highest aggregate accuracy:
│                                         #   Primary: CIC-IDS2017 (99.06%), CSE-CIC-IDS2018 (99.12%) -> 99.11% Fleet Acc
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
| **CSE-CIC-IDS2018** | R10 (10 feat) | **RF + LSTM Fusion ($\alpha=0.00$)** | **0.9912 (99.12%)** | **0.9603** | **0.9966** | **0.9865** | 1,662,419 |
| **Primary Fleet Total** | **R10** | **Flagship System** | **0.9911 (99.11%)** | — | — | — | **2,018,252** |

### Auxiliary Benchmark (Degraded 4-Feature NetFlow Schema)

| Dataset | Feature Contract | Model Architecture | Test Accuracy | Test F1 Score | Test ROC-AUC | Test PR-AUC | Population |
|:---|:---:|:---|:---:|:---:|:---:|:---:|---:|
| **UNSW-NB15** | R4 (4 feat) | Random Forest | 0.8590 | 0.8548 | 0.9487 | 0.9323 | 24,496 |
| **UNSW-NB15** | R4 (4 feat) | Supervised LSTM | 0.8683 | 0.8637 | 0.9334 | 0.8903 | 24,496 |
| **UNSW-NB15** | R4 (4 feat) | **RF + LSTM Fusion ($\alpha=0.60$)** | **0.8996 (89.96%)** | **0.8970** | **0.9674** | **0.9538** | 24,496 |

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
