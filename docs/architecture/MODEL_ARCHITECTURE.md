# XRL-IDARS — Model Architecture & Machine Learning Contracts

**Document ID:** `DOC-ARCH-MODEL-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  
**Architect:** Principal Machine Learning Engineer  

---

## 1. Executive Summary

XRL-IDARS maintains a clean separation of concerns between its machine learning models:
1. **Primary Operational Detector**: **Random Forest (RF)** is the sole operational intrusion classifier, trained on tabular flow vectors ($X \in \mathbb{R}^{10}$) for sub-millisecond per-flow scoring.
2. **Experimental Sequence Detector**: **PyTorch LSTM** is an independent research model evaluating temporal multi-flow sequences ($X \in \mathbb{R}^{5 \times 11}$) for comparative academic analysis.
3. **Autonomous Response Policy**: **Dueling Deep Q-Network (DQN)** learns proactive mitigation strategies over a 6D causal state space.

---

## 2. Primary Operational Model: Random Forest (Scikit-Learn)

### Hyperparameters & Configuration:
- **Estimator**: `sklearn.ensemble.RandomForestClassifier`
- **Number of Estimators ($n_{\text{trees}}$)**: 100 trees
- **Split Criterion**: Gini Impurity ($\text{Gini} = 1 - \sum p_i^2$)
- **Maximum Depth**: Unconstrained (natural leaf stopping at pure node or minimum split)
- **Minimum Samples Split**: 2
- **Class Weighting**: Balanced (`class_weight='balanced'`) to adjust for class imbalance
- **Input Dimension**: $X \in \mathbb{R}^{10}$ (R10 Canonical Features)
- **Output**: Calibrated posterior probability $P(\text{Attack} \mid x) \in [0.0, 1.0]$

```mermaid
flowchart TD
    INPUT["Feature Vector x in R^10"] --> SCALER["StandardScaler Transform"]
    SCALER --> T1["Decision Tree 1"]
    SCALER --> T2["Decision Tree 2"]
    SCALER --> TDOTS["..."]
    SCALER --> T100["Decision Tree 100"]
    T1 --> VOTE["Ensemble Probability Aggregator"]
    T2 --> VOTE
    TDOTS --> VOTE
    T100 --> VOTE
    VOTE --> PROB["Attack Probability P(Attack | x)"]
    PROB --> DECISION{"P >= 0.50 ?"}
    DECISION -->|Yes| ATTACK["Class: ATTACK (1)"]
    DECISION -->|No| BENIGN["Class: BENIGN (0)"]
```

---

## 3. Experimental Research Model: Temporal PyTorch LSTM

### Network Architecture:
- **Input Shape**: $(B, T, F) = (B, 5, 11)$ where $B$ is batch size, $T=5$ consecutive flows, and $F=11$ features (R10 features + inter-flow arrival delta $\Delta t$).
- **Recurrent Backbone**: 2-layer stacked LSTM:
  - Layer 1: $\text{LSTM}(\text{input\_size}=11, \text{hidden\_size}=64, \text{batch\_first}=\text{True})$
  - Dropout: $p = 0.20$
  - Layer 2: $\text{LSTM}(\text{input\_size}=64, \text{hidden\_size}=64, \text{batch\_first}=\text{True})$
- **Dense Head**:
  - Linear layer: $\text{Linear}(64, 32)$ with $\text{ReLU}$ activation
  - Output projection: $\text{Linear}(32, 1)$ with $\text{Sigmoid}$ activation
- **Loss Function**: Binary Cross Entropy with Logits (`BCEWithLogitsLoss`)
- **Optimizer**: Adam ($\text{lr} = 0.001$, weight decay $10^{-4}$)

```mermaid
flowchart LR
    subgraph SEQUENCE_BUFFER["Host Sequence Buffer (T=5)"]
        F1["Flow t-4 (11-dim)"] --> S1["Sequence Step 1"]
        F2["Flow t-3 (11-dim)"] --> S2["Sequence Step 2"]
        F3["Flow t-2 (11-dim)"] --> S3["Sequence Step 3"]
        F4["Flow t-1 (11-dim)"] --> S4["Sequence Step 4"]
        F5["Flow t (11-dim)"]   --> S5["Sequence Step 5"]
    end

    subgraph PYTORCH_LSTM["PyTorch Recurrent Network"]
        S1 & S2 & S3 & S4 & S5 --> LSTM1["LSTM Layer 1 (Hidden=64)"]
        LSTM1 --> DROP["Dropout (p=0.20)"]
        DROP --> LSTM2["LSTM Layer 2 (Hidden=64)"]
        LSTM2 --> LAST["Final Hidden State h_5 in R^64"]
        LAST --> FC1["Dense Linear (64 -> 32) + ReLU"]
        FC1 --> FC2["Dense Linear (32 -> 1) + Sigmoid"]
        FC2 --> SCORE["Temporal Score P_LSTM in [0, 1]"]
    end
```

---

## 4. Autonomous Response Policy: Dueling Deep Q-Network (DQN)

### Architecture Formulation:
Standard Q-networks suffer from overestimating action values in states where action choice does not affect the outcome. The Dueling DQN architecture decouples state-value estimation from action-advantage estimation:
$$Q(s, a; \theta, \alpha, \beta) = V(s; \theta, \beta) + \left( A(s, a; \theta, \alpha) - \frac{1}{|\mathcal{A}|} \sum_{a' \in \mathcal{A}} A(s, a'; \theta, \alpha) \right)$$

### Network Specifications:
- **Input Dimension**: $s_t \in \mathbb{R}^6$
- **Feature Extractor**: Linear(6, 64) $\to$ LayerNorm $\to$ LeakyReLU(0.01)
- **Value Stream ($V$)**: Linear(64, 32) $\to$ LeakyReLU $\to$ Linear(32, 1)
- **Advantage Stream ($A$)**: Linear(64, 32) $\to$ LeakyReLU $\to$ Linear(32, $|\mathcal{A}|$)
- **Action Dimension ($|\mathcal{A}|$)**: 4 actions (3-action configuration also supported):
  - $a=0$: `NO_ACTION`
  - $a=1$: `RATE_LIMIT`
  - $a=2$: `QUARANTINE_IP`
  - $a=3$: `DEEP_INSPECTION`

```mermaid
flowchart TD
    STATE["6D State s_t in R^6"] --> SHARED["Shared Linear(6, 64) + LeakyReLU"]
    SHARED --> VAL_STREAM["Value Stream: Linear(64, 32) -> V(s) in R^1"]
    SHARED --> ADV_STREAM["Advantage Stream: Linear(64, 32) -> A(s, a) in R^4"]
    VAL_STREAM --> AGG["Dueling Aggregation: Q(s, a) = V(s) + (A(s, a) - mean(A))"]
    ADV_STREAM --> AGG
    AGG --> QVALS["Action Q-Values Q(s, a) in R^4"]
    QVALS --> ARGMAX["ArgMax Selection: a* = argmax_a Q(s, a)"]
```
