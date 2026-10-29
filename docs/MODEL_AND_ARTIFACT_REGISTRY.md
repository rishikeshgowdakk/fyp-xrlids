# XRL-IDARS — Model and Artifact Registry

> **Canonical Model Artifact Registry**  
> *Target System: XRL-IDARS (Intrusion Detection and Autonomous Response System)*  
> *Registry Version: 1.0.0 (Forensic Integrity Verified)*  
> *Canonical Registry Manifest: `models/registry/model_manifest.json`*  
> *Total Registered Models: 9 (3 Random Forest, 3 Supervised LSTM, 2 Dueling DQN, 1 Convex Score Fusion)*

---

## 1. Registry Architecture & Integrity Standard

Every trained model checkpoint and weight configuration in XRL-IDARS is tracked under strict cryptographic provenance:
1. **Immutable Checkpoints**: Model binaries are stored under `models/` with identical copies preserved in their respective training experiment runs under `results/experiments/` and `results/phase2/`.
2. **Cryptographic Checksumming**: Every artifact is indexed with its exact file size in bytes and SHA-256 hash in [model_manifest.json](../models/registry/model_manifest.json).
3. **Zero Data Leakage**: All models were trained strictly on source-domain training splits post-Policy A deduplication. No validation or test data was leaked into preprocessing parameters, feature scalers, or model weights.
4. **Contract Pairing**: Each model strictly validates its input feature contract (`R10` 10-feature, `R4` 4-feature, or `response_state_v1` 6D state) and rejects misaligned inputs.

---

## 2. Canonical Artifact Master Matrix

| # | Model ID | Family | Canonical Path | Size (Bytes) | SHA-256 Checksum | Feature Contract | Target Benchmark | Validated Headline Metric |
|:---:|:---|:---:|:---|---:|:---|:---:|:---:|:---:|
| **1** | `random_forest_cicids2017.joblib` | RF | `models/rf/random_forest_cicids2017.joblib` | 26,363,055 | `7c6ad493b773b687da24a2a12dcb21bd03bd56b76809462b983454aeacf2b774` | `R10` (10 feats) | CIC-IDS2017 | **F1: 0.9512** (Acc: 0.9815) |
| **2** | `random_forest_cse2018.joblib` | RF | `models/rf/random_forest_cse2018.joblib` | 68,240,031 | `b7d2dc7bacca1a46f4da35aee2c19e1604020d429a5d29b72d742130215ba9b3` | `R10` (10 feats) | CSE-CIC-IDS2018 | **F1: 0.8861** (Acc: 0.9723) |
| **3** | `random_forest_unswnb15.joblib` | RF | `models/rf/random_forest_unswnb15.joblib` | 22,639,151 | `c432eb067507ad5b29a542b372ac6d35e609e783a9e6094c9764d0cfe654ec7c` | `R4` (4 feats) | UNSW-NB15 | **F1: 0.8548** (Acc: 0.8590) |
| **4** | `lstm_cicids2017.pt` | LSTM | `models/lstm/lstm_cicids2017.pt` | 60,949 | `2cdbf88d2eda358619d66a5d001fa7dde8ab3a36d8e0548c8c529ae8e8870f5c` | `R10` (10 feats) | CIC-IDS2017 | **F1: 0.9633** (Acc: 0.9867) |
| **5** | `lstm_cse2018.pt` | LSTM | `models/lstm/lstm_cse2018.pt` | 60,949 | `ea5b8198c20faa15d5d45ae7d081b754a76dbae1342a93b8234e0e06cfe8a33a` | `R10` (10 feats) | CSE-CIC-IDS2018 | **F1: 0.9603** (Acc: 0.9912) |
| **6** | `lstm_unswnb15.pt` | LSTM | `models/lstm/lstm_unswnb15.pt` | 57,813 | `4d9386ff44c99eed822f8ace5c64429fab571b4f8aad847d6cc78bae5f308fbd` | `R4` (4 feats) | UNSW-NB15 | **F1: 0.8637** (Acc: 0.8683) |
| **7** | `dqn_4action_best.pt` | DQN | `models/dqn/dqn_4action_best.pt` | 43,189 | `6a5afc669b4e699ecd2b1c01df885cef9030c93b8888b487dd386533920ce954` | `response_state_v1` (6D) | CIC-IDS2017 Flows | **Mean Cost: 5.326/flow** (45k steps) |
| **8** | `dqn_3action_best.pt` | DQN | `models/dqn/dqn_3action_best.pt` | 42,997 | `c06a61fb7777511600efd6db776745c4539da30c710fed8993145ed1b926be31` | `response_state_v1` (6D) | CIC-IDS2017 Flows | **Mean Cost: 1.421/flow** (10k steps) |
| **9** | `fusion_weights.json` | Fusion | `models/fusion/fusion_weights.json` | 1,214 | `e35df25179a4574c83192bf35ebd0041772007c8b360151df489a5d9bd5450d0` | `alpha_blend` | Multi-Domain | **CIC F1: 0.9745** (α=0.50) |

---

## 3. Checkpoint Details & Provenance

### 3.1 Random Forest Detectors

All three Random Forest classifiers are wrapped in `RandomForestDetector` (`src/xrlids/models/random_forest.py`). Each wraps an underlying `sklearn.ensemble.RandomForestClassifier` with an explicit contract validation layer.

#### 1. `random_forest_cicids2017.joblib`
- **Source Experiment**: `results/experiments/EXP-P1-CIC2017-R10-001/random_forest.joblib`
- **Training Population**: CIC-IDS2017 (8 days post-Policy A deduplication, 1,067,594 training flows)
- **Feature Contract**: `R10` (10 features: `flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean`, `packet_length_std`, `syn_count`, `ack_count`, `rst_count`, `fin_count`, `syn_ack_ratio`)
- **Hyperparameters**: `n_estimators=100`, `max_depth=20`, `min_samples_split=5`, `class_weight="balanced"`, `random_state=42`, `n_jobs=-1`
- **Held-Out Test Results**: 355,865 tabular flows · **Accuracy**: 0.9815 · **Precision**: 0.9782 · **Recall**: 0.9256 · **F1-Score**: 0.9512 · **ROC-AUC**: 0.9968
- **Inference Snippet**:
  ```python
  import joblib, pandas as pd
  detector = joblib.load("models/rf/random_forest_cicids2017.joblib")
  # Input must be a DataFrame matching detector.feature_names
  probabilities = detector.predict_proba(df_r10)
  ```

#### 2. `random_forest_cse2018.joblib`
- **Source Experiment**: `results/experiments/EXP-P1-CSE2018-R10-MULTI-001/random_forest.joblib`
- **Training Population**: CSE-CIC-IDS2018 (10 days post-Policy A deduplication, 4,987,257 training flows)
- **Feature Contract**: `R10` (10 features)
- **Hyperparameters**: `n_estimators=100`, `max_depth=25`, `min_samples_split=5`, `class_weight="balanced"`, `random_state=42`
- **Held-Out Test Results**: 1,662,419 tabular flows · **Accuracy**: 0.9723 · **Precision**: 0.8934 · **Recall**: 0.8790 · **F1-Score**: 0.8861 · **ROC-AUC**: 0.9902

#### 3. `random_forest_unswnb15.joblib`
- **Source Experiment**: `results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001/random_forest.joblib`
- **Training Population**: UNSW-NB15 (2 files post-Policy A deduplication, 73,488 training flows)
- **Feature Contract**: `R4` (4 features: `flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean` — Argus flow exporter omitted flags and standard deviation)
- **Hyperparameters**: `n_estimators=100`, `max_depth=20`, `class_weight="balanced"`, `random_state=42`
- **Held-Out Test Results**: 24,496 tabular flows · **Accuracy**: 0.8590 · **Precision**: 0.8654 · **Recall**: 0.8445 · **F1-Score**: 0.8548 · **ROC-AUC**: 0.9487

---

### 3.2 Supervised LSTM Sequence Detectors

Supervised recurrent models are implemented in PyTorch under `LSTMDetector` (`src/xrlids/models/lstm.py`). They ingest causal sliding windows of $T=5$ consecutive flows to capture inter-flow temporal dynamics.

#### Architecture Specification
- **Backbone**: 2-layer unidirectional PyTorch `nn.LSTM`
- **Sequence Context Length**: $T = 5$ consecutive flows
- **Hidden Unit Dimension**: $h = 32$
- **Dropout**: 0.20 between recurrent layers
- **Head**: Linear projection ($32 \to 1$) followed by Sigmoid activation for binary attack probability
- **Parameter Count**: 13,089 trainable parameters (R10) / 12,321 trainable parameters (R4)

#### Checkpoint Inventory
1. **`lstm_cicids2017.pt`**:
   - Trained on CIC-IDS2017 causal sequences ($T=5$, R10 contract).
   - Validated at epoch 14 (loss: 0.0412); test set size: 355,833 aligned flows.
   - **Performance**: **F1: 0.9633**, **Accuracy: 0.9867**, **ROC-AUC: 0.9975**.
2. **`lstm_cse2018.pt`**:
   - Trained on CSE-CIC-IDS2018 causal sequences ($T=5$, R10 contract).
   - Validated at epoch 18 (loss: 0.0389); test set size: 1,662,419 aligned flows.
   - **Performance**: **F1: 0.9603**, **Accuracy: 0.9912**, **ROC-AUC: 0.9981**.
3. **`lstm_unswnb15.pt`**:
   - Trained on UNSW-NB15 causal sequences ($T=5$, R4 contract).
   - Validated at epoch 12 (loss: 0.3120); test set size: 24,496 aligned flows.
   - **Performance**: **F1: 0.8637**, **Accuracy: 0.8683**, **ROC-AUC: 0.9521**.

- **Inference Snippet**:
  ```python
  import torch
  from xrlids.models.lstm import LSTMDetector

  detector = LSTMDetector.load("models/lstm/lstm_cicids2017.pt")
  # Tensor input shape: (batch_size, seq_len=5, n_features=10)
  detector.model.eval()
  with torch.no_grad():
      logits = detector.model(tensor_bx)
      attack_probabilities = torch.sigmoid(logits).cpu().numpy()
  ```

---

### 3.3 Deep Q-Network Autonomous Response Agents

Autonomous response policies are trained via Dueling Deep Q-Networks (`DqnAgent` in `src/xrlids/response/dqn/agent.py`) using Prioritized Experience Replay (PER).

#### State Representation Contract (`response_state_v1`)
The state vector is a 6-dimensional continuous tuple:
$$\mathbf{s}_t = [s_t, p_a, \Delta p, \lambda_{\text{rate}}, a_{t-1}, d_{\text{flow}}]$$
1. $s_t \in [0, 1]$: Raw detector anomaly score.
2. $p_a \in [0, 1]$: Risk-weighted attack probability.
3. $\Delta p \in [-1, 1]$: First-order score difference ($s_t - s_{t-1}$).
4. $\lambda_{\text{rate}} \in [0, \infty)$: Flow arrival rate (packets/second normalized).
5. $a_{t-1} \in \{0, 1, 2, 3\}$: Previous applied action index (encodes hysteresis).
6. $d_{\text{flow}} \in [0, \infty)$: Log-normalized flow duration.

#### Dueling Network Architecture
- **Input Dimension**: 6
- **Shared Representation**: 2 Linear layers (64 units each) with ReLU activations.
- **Value Stream**: Linear ($64 \to 32$) $\to$ Linear ($32 \to 1$).
- **Advantage Stream**: Linear ($64 \to 32$) $\to$ Linear ($32 \to |\mathcal{A}|$).
- **Aggregation**: $Q(s, a) = V(s) + \left(A(s, a) - \frac{1}{|\mathcal{A}|} \sum_{a'} A(s, a')\right)$.

#### Checkpoints
1. **`dqn_4action_best.pt`** (4 Actions: `ALLOW`, `ALERT`, `RATE_LIMIT`, `ISOLATE`):
   - Selected at step 45,000 on validation criterion `mean_cost_per_flow`.
   - Test Performance (Standard Enterprise): Total Cost: $1,895,196.5$, Mean Cost: $5.326$/flow, Contained Attacks: 10,285, Business Availability: 96.52%.
2. **`dqn_3action_best.pt`** (3 Actions: `ALLOW`, `ALERT`, `RATE_LIMIT`):
   - Selected at step 10,000 on validation criterion `mean_cost_per_flow`.
   - Test Performance (Standard Enterprise): Total Cost: $505,610.5$, Mean Cost: $1.421$/flow, Contained Attacks: 60,449, Business Availability: 96.51%.

- **Inference Snippet**:
  ```python
  import torch
  from xrlids.response.dqn.network import DuelingQNetwork

  checkpoint = torch.load("models/dqn/dqn_4action_best.pt", map_location="cpu", weights_only=False)
  q_net = DuelingQNetwork(input_dim=6, action_dim=4, hidden_dim=64)
  q_net.load_state_dict(checkpoint["online_net_state_dict"])
  q_net.eval()

  state = torch.tensor([[0.92, 0.90, 0.05, 120.0, 1.0, 3.5]], dtype=torch.float32)
  with torch.no_grad():
      q_values = q_net(state)
      recommended_action = int(torch.argmax(q_values, dim=1).item())
  ```

---

### 3.4 Convex Score Fusion (`fusion_weights.json`)

The score fusion engine combines tabular tree decisions with recurrent sequence representations via a linear alpha-blend:
$$S_{\text{fusion}} = \alpha \cdot S_{\text{RF}} + (1 - \alpha) \cdot S_{\text{LSTM}}$$

> [!NOTE]
> The fused score is a continuous threat metric in $[0, 1]$. As documented under Decision D-003, it is uncalibrated (not a true posterior probability) and thresholded at $\tau = 0.50$ for benchmark evaluation.

#### Validated Weights by Domain
- **CIC-IDS2017**: $\alpha = 0.50$ (Balanced blend). RF F1 = 0.9512, LSTM F1 = 0.9633 $\to$ **Fusion F1 = 0.9745** (statistically significant gain, paired bootstrap $p < 0.001$).
- **CSE-CIC-IDS2018**: $\alpha = 0.00$ (**Degenerate Blend Alert**). Validation grid search found that the LSTM outperformed the RF across all slices. At $\alpha = 0.00$, the fusion model is mathematically identical to the standalone LSTM detector (F1 = 0.9603).
- **UNSW-NB15**: $\alpha = 0.60$ (RF-weighted blend). RF F1 = 0.8548, LSTM F1 = 0.8637 $\to$ **Fusion F1 = 0.8970** ($p < 0.001$).

---

## 4. Verification & Self-Test Script

To verify that all 9 registered models exist and match their cryptographic SHA-256 hashes on any machine:

```bash
python -c '
import json, hashlib
from pathlib import Path

manifest = json.loads(Path("models/registry/model_manifest.json").read_text())
all_pass = True
for a in manifest["artifacts"]:
    p = Path(a["canonical_path"])
    if not p.exists():
        print(f"[FAIL] Missing {p}")
        all_pass = False
        continue
    h = hashlib.sha256(p.read_bytes()).hexdigest()
    sz = p.stat().st_size
    ok = (h == a["sha256"]) and (sz == a["size_bytes"])
    status = "OK" if ok else "MISMATCH"
    if not ok: all_pass = False
    print(f"[{status}] {a[\"model_id\"]} ({sz:,} bytes) - Hash: {h[:12]}...")
assert all_pass, "Model verification failed!"
print("All 9 canonical models verified successfully against registry manifest.")
'
```
