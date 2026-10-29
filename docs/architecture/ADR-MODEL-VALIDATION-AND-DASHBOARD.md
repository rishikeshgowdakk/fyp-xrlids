# Architecture Decision Record: Model Validation, Safe Pipeline Corrections, and Dashboard Workbench Redesign

**ADR Identifier**: `ADR-MODEL-VALIDATION-AND-DASHBOARD-001`  
**Status**: `ACCEPTED / ACTIVE`  
**Date**: `2026-10-28`  
**Author**: Antigravity AI & Senior ML Engineering Team  
**Scope**: Model Pipeline, Response Architecture, Dashboard Interface, Evaluation Workbench  

---

## 1. Context and Problem Statement

The XRL-IDARS platform was designed as an explainable intrusion detection and autonomous response architecture across three benchmark datasets (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15) with an RF detector, an LSTM sequence model, a linear fusion model, a Deep Q-Network response policy, and a web dashboard.

Forensic auditing revealed:
1. **Model Calibration**: Tree-vote scores in Random Forest deviate significantly from true empirical posterior probabilities in the $[0.1, 0.8]$ range, yet are fed into thresholding and response logic as if calibrated.
2. **LSTM Sequence Locality**: Shuffled-window ablation proves that LSTM performance is driven by spatial pooling across the 5-flow window rather than genuine chronological sequence dynamics ($\Delta \text{F1} = -0.0038$).
3. **Fusion Degeneracy**: On CSE-CIC-IDS2018, validation grid search yielded $\alpha = 0.00$, making the fusion model identical to the standalone LSTM detector.
4. **Reinforcement Learning Grounding**: Network flow arrivals are purely exogenous replay. Setting $\gamma = 0.95$ optimizes noise correlations across 20 steps of exogenous traffic. An analytic `CostOptimalThresholdPolicy` beats the DQN in 4 of 6 operational settings (up to 20.12% lower cost) and executes ~51x faster (1.95 µs vs 100.23 µs policy-only).
5. **Dashboard Workflow Misalignment**: The original dashboard defaulted to a live packet capture monitor and synthetic attack injection simulator rather than exposing genuine held-out benchmark evaluation evidence.

---

## 2. Component Decision Register

### Component 1: Random Forest Detector
- **Current Implementation**: `RandomForestDetector` in `src/xrlids/models/random_forest.py` wrapping `sklearn.ensemble.RandomForestClassifier` (200 estimators, max depth 16).
- **Evidence Inspected**: `models/rf/random_forest_*.joblib`, `results/experiments/*/test_metrics.json`, `calibration_report.json`.
- **Status**: **`VERIFIED_FOR_DEFINED_SCOPE`**
- **Confirmed Defects**: Raw scores overestimate attack likelihood in $[0.1, 0.8]$; severe collapse under temporal distribution shift on CSE-CIC-IDS2018 (F1 drops from 0.8861 to 0.0113).
- **Unverified Assumptions**: Raw tree votes represent true posterior probabilities $P(\text{Attack} \mid x)$.
- **Recommended Change**: Keep trained model weights intact. Clearly document scores as uncalibrated tree-vote confidence scores. In UI and documentation, distinguish raw scores from calibrated probabilities. Propose future isotonic calibration as a distinct experiment without touching canonical frozen checkpoints.
- **Retraining Required**: **NO**.

### Component 2: Supervised LSTM Sequence Classifier
- **Current Implementation**: 2-layer LSTM in `src/xrlids/models/lstm.py` over $T=5$ consecutive flows within capture files.
- **Evidence Inspected**: `models/lstm/lstm_*.pt`, `results/ablations/lstm_temporal_ablation.json`.
- **Status**: **`PARTIALLY_VERIFIED`**
- **Confirmed Defects**: Temporal ablation shows no order gain ($\Delta \text{F1} = -0.0038$). The model behaves as a 5-flow local feature aggregation filter, not a temporal sequence model.
- **Unverified Assumptions**: Consecutive flows in raw benchmark CSVs represent physical network time-series causality.
- **Recommended Change**: Keep trained checkpoints intact. Update documentation, UI, and viva materials to honestly report the ablation finding: the model provides spatial feature smoothing over flow bursts rather than causal temporal dynamics.
- **Retraining Required**: **NO**.

### Component 3: RF–LSTM Linear Fusion
- **Current Implementation**: `fuse_scores()` in `src/xrlids/models/fusion.py` implementing $\alpha P_{\text{rf}} + (1 - \alpha) P_{\text{lstm}}$.
- **Evidence Inspected**: `models/fusion/fusion_weights.json`, `test_metrics.json`.
- **Status**: **`PARTIALLY_VERIFIED`**
- **Confirmed Defects**: On CSE-CIC-IDS2018, $\alpha = 0.00$, collapsing fusion into an exact copy of the standalone LSTM.
- **Unverified Assumptions**: Fusion consistently improves over individual components across all domains.
- **Recommended Change**: Keep existing configurations. In UI and comparison tables, explicitly expose $\alpha$ and flag $\alpha = 0.00$ as a degenerate configuration where fusion equals standalone LSTM.
- **Retraining Required**: **NO**.

### Component 4: Response Environment & Reinforcement Learning
- **Current Implementation**: `OfflineResponseSimulator` in `src/xrlids/response/environment.py` and `DQNNetwork` in `src/xrlids/response/dqn.py`.
- **Evidence Inspected**: `results/phase2/EXP-P2A-COST-OPTIMAL-001/FINAL_REPORT.md`, `baseline_results.json`.
- **Status**: **`REQUIRES_REFORMULATION`**
- **Confirmed Defects**: Flow arrivals are exogenous; taking actions does not alter future flow arrivals or attack progression. Analytic `CostOptimalThresholdPolicy` beats DQN in 4 of 6 operational regimes (20.12% cost reduction in 4-action High Availability). DQN fails the 15% improvement target in all settings.
- **Unverified Assumptions**: Response selection is an unconstrained sequential Markov Decision Process justifying non-zero discount factors ($\gamma = 0.95$).
- **Recommended Change**: Preserve existing checkpoints and experiment records as historical evidence. Reformulate the problem statement in documentation as an **Asymmetric-Loss Contextual Decision Policy with Hysteresis Constraints**. Present the Cost-Optimal baseline alongside DQN on equal footing in the dashboard. Maintain the Deterministic Safety Gate as authoritative over all actions.
- **Retraining Required**: **NO** (preserve existing baseline; future $\gamma = 0$ work will be a separate experiment).

### Component 5: Web Dashboard
- **Current Implementation**: Single-page app with `Live Monitor` as default tab, featuring synthetic packet injection and sample PCAP streaming.
- **Evidence Inspected**: `dashboard/server.py`, `dashboard/index.html`, `dashboard/app.js`.
- **Status**: **`DEFECT_CONFIRMED`** (Architectural misalignment with research goals).
- **Confirmed Defects**: Obscures genuine held-out dataset evaluation; defaults to live capture without permissions; conflates sample PCAPs and synthetic attack scripts with empirical research evidence.
- **Recommended Change**: Complete redesign into a 7-page **Research Evaluation Workbench**:
  - Page A: Overview
  - Page B: Dataset Evaluation (Primary default page)
  - Page C: Model Comparison (with fusion weights & degenerate flags)
  - Page D: Flow Explorer (paginated browsing over 355k flows with separate ground truth)
  - Page E: Explainability (TreeSHAP for RF only)
  - Page F: Autonomous Response (DQN vs Cost-Optimal baseline, Q-values vs attack scores, safety gate)
  - Page G: Research Limitations (candid audit findings)
- **Retraining Required**: **NO**.

---

## 3. Consequences and Invariants

1. **Safety Invariant**: Autonomous production enforcement remains `NO-GO`. Zero real network mutations permitted.
2. **Data Integrity**: Canonical models and historical experiment records are preserved with 100% hash parity.
3. **Execution Mode Separation**: Five distinct execution modes are formally separated in the UI:
   - Mode 1: Offline Dataset Evaluation
   - Mode 2: Dataset Demonstration Stream
   - Mode 3: PCAP Replay
   - Mode 4: Synthetic Attack Simulation
   - Mode 5: Live Capture (read-only, explicit user opt-in, no silent fallback).
