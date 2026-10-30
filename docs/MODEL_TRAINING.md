# XRL-IDARS — Model Training, Evaluation, and Reproduction Guide

**Purpose:** Comprehensive guide for training, evaluating, and reproducing all machine learning and reinforcement learning models in **XRL-IDARS**.  
**Architectural Separation:** Live detection uses the canonical **Random Forest** detector and **Multiclass Attack Classifier** with **TreeSHAP** local attributions; **XGBoost** is preserved as an offline candidate; **LSTM** and **Score Fusion** are preserved as offline research benchmarks; **Dueling DQN** recommends mitigation actions within the 6D causal state space under advisory safety constraints.

---

## 1. Model Ecosystem Overview

| Model Identifier | Architecture | Primary Task | Feature Contract | Training Dataset | Checkpoint Path | Status |
|---|---|---|---|---|---|---|
| `random_forest_cicids2017.joblib` | Ensembled Decision Trees (100 estimators) | Binary Intrusion Detection | $R_{10}$ (10 features) | CIC-IDS2017 | `models/rf/random_forest_cicids2017.joblib` | **Canonical Live Champion** |
| `random_forest_cse2018.joblib` | Ensembled Decision Trees (100 estimators) | Binary Intrusion Detection | $R_{10}$ (10 features) | CSE-CIC-IDS2018 | `models/rf/random_forest_cse2018.joblib` | **Canonical Benchmark** |
| `random_forest_unswnb15.joblib` | Ensembled Decision Trees (100 estimators) | Binary Intrusion Detection | $R_4$ (4 features) | UNSW-NB15 | `models/rf/random_forest_unswnb15.joblib` | **Auxiliary Domain Benchmark** |
| `xgboost_cicids2017.json` | Gradient Boosted Trees (XGBoost) | Binary Intrusion Detection | $R_{10}$ (10 features) | CIC-IDS2017 | `models/xgboost/xgboost_cicids2017.json` | **Offline Candidate Wrapper** |
| `multiclass_rf_champion.joblib` | Multi-output Random Forest (100 estimators) | 6-Family Attack Attribution | $R_{10}$ (10 features) | CIC-IDS2017 | `models/multiclass/multiclass_rf_champion.joblib` | **Active Attribution Tier** |
| `dqn_4action_best.pt` | Dueling Q-Network (PyTorch) | Autonomous Response Policy | 6D Causal State | CIC-IDS2017 | `models/dqn/dqn_4action_best.pt` | **Active Response Policy** |
| `lstm_cicids2017.pt` | Recurrent LSTM (PyTorch) | Sequential Anomaly Benchmark | $R_{10}$ (10 features) | CIC-IDS2017 | `models/lstm/lstm_cicids2017.pt` | **Offline Research Comparator** |
| `fusion_weights.json` | Calibrated Score Fusion | Hybrid Anomaly Scoring | Multi-score weights | Multi | `models/fusion/fusion_weights.json` | **Offline Research Comparator** |

---

## 2. Environment, Dependencies & Prerequisites

Training and evaluating models requires the project virtual environment with pinned dependencies:

```bash
# Set up Python 3.12 or 3.14 virtual environment
python -m venv .venv
source .venv/bin/activate

# Upgrade pip and install package with dev dependencies
python -m pip install --upgrade pip
pip install --extra-index-url https://download.pytorch.org/whl/cpu -e ".[dev]"
```

Required packages:
- `torch >= 2.14.0` (CPU inference/training)
- `scikit-learn >= 1.9.0` (Random Forest, preprocessing, evaluation metrics)
- `xgboost >= 3.0.0` (Gradient boosting engine)
- `shap >= 0.52.0` (TreeSHAP explanations)
- `joblib >= 1.4.0` (Artifact serialization)
- `pandas >= 2.2.0`, `numpy >= 1.26.0`, `pyarrow >= 19.0.0`

---

## 3. Data Split Methodology & Leakage Prevention

All model training adheres to strict leakage-prevention protocols under Decision **D-001** and **D-005**:
1. **Source Data Isolation:** Datasets are partitioned into distinct Training, Validation, and Test subsets prior to any feature transformation.
2. **Preprocessing Fitting:** Preprocessors (scaling, imputation, quantile transformation) are **fit strictly on the Training split**. The fitted preprocessor is then applied transform-only to Validation and Test splits.
3. **Threshold Tuning:** Decision thresholds ($\tau$) and hyperparameters are optimized strictly on the **Validation set**. The Test set is evaluated exactly once for final reporting.
4. **Group and Temporal Separation:** Multi-day captures (e.g. CIC-IDS2017 Friday vs Wednesday) preserve temporal and session boundaries to avoid inter-packet or inter-flow leakage.

---

## 4. Reproducible Model Training Workflows

### 4.1 Training the XGBoost Candidate Detector

The XGBoost detector is trained on the canonical $R_{10}$ contract using the reproducible script:

```bash
.venv/bin/python scripts/phase1/train_xgboost_candidate.py \
    --dataset cicids2017 \
    --config configs/experiments/EXP-P1-CIC2017-R10-001.yaml \
    --output-dir results/experiments/EXP-P1-CIC2017-XGB-001 \
    --random-seed 42
```

**Training Parameters:**
- `n_estimators`: 200 (with early stopping at 15 rounds on validation log-loss)
- `learning_rate`: 0.05
- `max_depth`: 6
- `subsample`: 0.8
- `colsample_bytree`: 0.8
- `eval_metric`: `logloss`

**Generated Artifacts:**
- `model.json`: Native XGBoost JSON model format.
- `metadata.json`: Feature names, schema hashes, hyperparameters, and class mapping.
- `evaluation_metrics.json`: Accuracy, Precision, Recall, F1, PR-AUC, ROC-AUC, FPR.

### 4.2 Training the Multiclass Attack Classifier

The multiclass attribution model identifies specific attack families among flows confirmed as malicious:

```bash
.venv/bin/python -c "
from xrlids.models.multiclass_detector import MulticlassAttackClassifier
# Trains and serializes multiclass Random Forest on holdout partition
MulticlassAttackClassifier.train_and_save(
    data_dir='data/raw/cicids2017',
    output_path='models/multiclass/multiclass_rf_champion.joblib'
)
"
```

**Expected Metric Benchmarks (Test Set):**
- Weighted F1: **95.52%**
- Brute Force F1: **0.9967**
- DDoS F1: **0.9711**
- DoS F1: **0.9645**
- Port Scan F1: **0.9574**
- Web Attack F1: **0.8710**
- Benign F1: **0.9469**

### 4.3 Training the Dueling DQN Response Policy

The DQN agent is trained in an episodic network mitigation environment over the 6D causal state space:

```bash
.venv/bin/python scripts/phase2/run_phase2b_dqn.py \
    --episodes 500 \
    --steps-per-episode 100 \
    --learning-rate 0.0005 \
    --gamma 0.99 \
    --epsilon-decay 0.995 \
    --output-dir results/phase2/EXP-P2B-DQN-001
```

**Network Architecture:**
- Input Dimension: 6 (`[S_t, ΔS_t, N_alert, a_{t-1}, c_t, v_t]`)
- Shared Layers: Linear(6, 64) $\to$ ReLU $\to$ Linear(64, 64) $\to$ ReLU
- Value Stream: Linear(64, 32) $\to$ ReLU $\to$ Linear(32, 1)
- Advantage Stream: Linear(64, 32) $\to$ ReLU $\to$ Linear(32, 4)
- Aggregation: $Q(s, a) = V(s) + \left(A(s, a) - \frac{1}{|\mathcal{A}|}\sum_{a'} A(s, a')\right)$
- Checkpoint: Saved to `models/dqn/dqn_4action_best.pt`

### 4.4 Evaluating Baseline Random Forest and Offline Comparators

Run full empirical cross-evaluation of the Random Forest baseline and offline research models:

```bash
.venv/bin/python scripts/phase1/run_experiment.py \
    --config configs/experiments/EXP-P1-CIC2017-R10-001.yaml \
    --eval-only
```

---

## 5. Model Inspection & Inference Verification

To verify that model artifacts load correctly, validate feature contracts, and generate predictions:

```bash
.venv/bin/python -c "
from xrlids.models.manager import ModelManager
from xrlids.features.definitions import R10_FEATURES

mgr = ModelManager()
sample_flow = {
    'flow_duration_ms': 1250.0,
    'flow_packets_per_s': 25.0,
    'flow_bytes_per_s': 15000.0,
    'packet_length_mean': 600.0,
    'packet_length_std': 120.0,
    'syn_count': 1.0,
    'ack_count': 30.0,
    'rst_count': 0.0,
    'fin_count': 1.0,
    'syn_ack_ratio': 0.033,
}
res = mgr.predict_flow(sample_flow)
print('Prediction:', res.prediction_label)
print('Attack Score:', res.attack_score)
print('Family:', res.attack_family)
print('Latency:', f'{res.inference_time_ms:.3f} ms')
"
```

---

## 6. Automated Unit & Model Integrity Tests

Run the dedicated model test suite:

```bash
# Model registry integrity and hash verification
.venv/bin/pytest tests/model/test_model_registry_integrity.py -v

# Random Forest inference and contract verification
.venv/bin/pytest tests/model/test_models.py -v

# XGBoost detector wrapper and persistence tests
.venv/bin/pytest tests/unit/test_xgboost_detector.py -v

# Multiclass classifier and response executor unit tests
.venv/bin/pytest tests/unit/test_multiclass_and_executor.py -v

# DQN neural network and state representation tests
.venv/bin/pytest tests/unit/test_dqn.py tests/unit/test_dqn_response_service.py -v
```

---

## 7. Known Limitations, Failure Cases & Scientific Constraints

1. **Covariate Shift on Unadapted Datasets:** Models trained on CIC-IDS2017 exhibit performance degradation when transferred directly to UNSW-NB15 without domain adaptation due to differences in packet logging engines (CICFlowMeter vs Argus/Bro).
2. **Interactive Stealth Overlap (CSE-2018 Infiltration):** Summary flow statistics ($R_{10}$) for interactive Meterpreter and C2 command shells overlap 78%–98% with normal workstation web browsing. Application-layer payload inspection is required to disambiguate interactive shells.
3. **Completed Flow Dependency:** All flow models require completed flows (terminated via TCP FIN/RST or 120s timeout) and cannot classify isolated mid-stream packets without session context.
4. **Advisory Mode Enforcement:** All response recommendations generated from model predictions operate in simulated advisory mode (`advisory_mode=True`) to prevent unauthorized network disruption.
