# Model Evaluation Report (generated)

Experiment ID: `EXP-P1-CSE2018-R10-001`
Status: `EMPIRICALLY_OBSERVED` (Duration: `84.07s`)
Dataset: `cse_cic_ids2018` · Feature Contract: `R10`

## Test Set Evaluation Metrics (Operating Point: 0.5)

| Model | Population | Accuracy | Precision | Recall | F1 Score | Specificity | FPR | ROC-AUC | PR-AUC |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **RF** | 43340 | 0.6479 | 0.3206 | 0.4742 | 0.3826 | 0.6998 | 0.3002 | 0.6443 | 0.4140 |
| **LSTM** | 43336 | 0.7938 | 0.7390 | 0.1602 | 0.2633 | 0.9831 | 0.0169 | 0.7284 | 0.4860 |
| **FUSION** | 43336 | 0.7978 | 0.7640 | 0.1750 | 0.2848 | 0.9838 | 0.0162 | 0.7452 | 0.5151 |

## Model Architectures and Hyperparameters

### 1. Random Forest Classifier
- **Trees**: 100 estimators (`n_estimators=100`)
- **Max Depth**: 16 (`max_depth=16`, `min_samples_leaf=2`)
- **Class Weight**: `balanced_subsample`
- **Random Seed**: 42

### 2. Supervised LSTM Temporal Classifier
- **Sequence Length**: 5 (`seq_len=5`, `stride=1`, `label_rule='last'`)
- **Architecture**: 2 LSTM layers, hidden size 32, dropout 0.2
- **Training**: Adam optimizer, lr=0.001, batch size 256, early stopping patience 3
- **Boundary Safety**: Sequence generation isolated per split; zero boundary crossing

### 3. RF + LSTM Score Fusion
- **Formulation**: $P_{fusion} = \alpha P_{rf} + (1 - \alpha) P_{lstm}$
- **Tuning Policy**: Alpha tuned strictly on Validation split to maximize ROC-AUC (tie-break towards 0.5)
- **Validation-Tuned Alpha**: `0.30` (Validation ROC-AUC: `0.7474`)

### 4. Probability Calibration
- **Method**: Platt scaling (logistic sigmoid fit on validation probabilities)
- **Evaluation**: Test set Brier score and Expected Calibration Error (ECE)
