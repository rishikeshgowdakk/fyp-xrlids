# XRLIDS Model Artifacts & Registry

This directory contains the canonical trained model weights and artifact registry for the XRLIDS framework.

## Structure

```
models/
├── rf/                  # Random Forest classifiers (.joblib)
│   ├── random_forest_cicids2017.joblib   # Trained on CIC-IDS2017 R10 (Test F1: 0.9512)
│   ├── random_forest_cse2018.joblib      # Trained on CSE-CIC-IDS2018 R10 (Test F1: 0.8861)
│   └── random_forest_unswnb15.joblib     # Trained on UNSW-NB15 R10 (Test F1: 0.8546)
├── lstm/                # PyTorch LSTM temporal sequence models (.pt)
│   ├── lstm_cicids2017.pt                # Trained on CIC-IDS2017 R10 (Test F1: 0.9633)
│   ├── lstm_cse2018.pt                   # Trained on CSE-CIC-IDS2018 R10 (Test F1: 0.9603)
│   └── lstm_unswnb15.pt                  # Trained on UNSW-NB15 R10 (Test F1: 0.8637)
├── dqn/                 # Dueling Deep Q-Networks with Prioritized Replay (.pt)
│   ├── dqn_4action_best.pt               # 4-Action response agent (ALLOW, ALERT, RATE_LIMIT, ISOLATE)
│   └── dqn_3action_best.pt               # 3-Action response agent (ALLOW, ALERT, RATE_LIMIT)
├── fusion/              # Score-level fusion configurations (.json)
│   └── fusion_weights.json               # Linear score fusion weights (alpha) & calibration parameters
└── registry/            # Machine-readable artifact registries
    ├── model_manifest.json               # JSON registry with SHA-256 hashes and metadata
    └── registry.yaml                     # YAML registry conforming to FR-020
```

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
