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

### Random Forest
```python
import joblib

rf = joblib.load("models/rf/random_forest_cicids2017.joblib")
probabilities = rf.predict_proba(X_test)[:, 1]
```

### Supervised LSTM
```python
import torch
from xrlids.models.lstm import SupervisedLSTM

model = SupervisedLSTM(input_dim=10, hidden_dim=32, num_layers=2, dropout=0.2)
model.load_state_dict(torch.load("models/lstm/lstm_cicids2017.pt"))
model.eval()
```

### Autonomous Response DQN
```python
import torch
from xrlids.response.environment import DuelingQNetwork

q_net = DuelingQNetwork(state_dim=10, action_dim=4)
q_net.load_state_dict(torch.load("models/dqn/dqn_4action_best.pt"))
q_net.eval()
```
