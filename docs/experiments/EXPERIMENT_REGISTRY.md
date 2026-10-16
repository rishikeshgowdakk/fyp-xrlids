ate# EXPERIMENT REGISTRY

This registry is the authoritative index of all experimental investigations conducted within the XRLIDS research program.
Every experiment records its research questions (RQs), benchmark dataset, feature contract, model architectures, configurations, execution status, and primary empirical findings.

## ID Convention

```text
EXP-<PHASE>-<DATASET/DOMAIN>-<FEATURESET/SCOPE>-<NNN>
```

| Token | Values |
| --- | --- |
| PHASE | `P1` (Detection & Transfer), `P2` (Autonomous Response), `P3` (Live & Systems) |
| DATASET/DOMAIN | `CIC` · `CSE` · `UNSW` · `TRANSFER` · `DQN` · `ISOLATED-LAB` |
| FEATURESET/SCOPE | `R10` · `R4` · `BASELINES` · `SENSITIVITY` · `ROLLBACK` · `CONCURRENCY` |
| NNN | Three-digit sequence identifier (`001`, `002`, ...) |

---

## Completed Experiments Registry

| Experiment ID | RQ | Dataset(s) | Feature Contract | Model / System | Result Path | Status | Headline Metric |
| :--- | :---: | :--- | :---: | :--- | :--- | :---: | :--- |
| `EXP-P1-CIC2017-R10-001` | RQ1, RQ2 | CIC-IDS2017 | `R10` | Baseline Ladder (RF, LSTM, Fusion) | `results/experiments/EXP-P1-CIC2017-R10-001/` | `DONE` | **RF F1: 0.9512**, **LSTM F1: 0.9633**, **Fusion F1: 0.9745** |
| `EXP-P1-CSE2018-R10-MULTI-001` | RQ1, RQ2 | CSE-CIC-IDS2018 | `R10` | Baseline Ladder (RF, LSTM, Fusion) | `results/experiments/EXP-P1-CSE2018-R10-MULTI-001/` | `DONE` | **RF F1: 0.8861**, **LSTM F1: 0.9603**, **Fusion F1: 0.9603** |
| `EXP-P1-UNSWNB15-R10-MULTI-001` | RQ1, RQ2 | UNSW-NB15 | `R4` | Baseline Ladder (RF, LSTM, Fusion) | `results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001/` | `DONE` | **RF F1: 0.8548**, **LSTM F1: 0.8637**, **Fusion F1: 0.8970** |
| `EXP-P1-TRANSFER-CIC-TO-CSE-R10-001` | RQ3 | CIC-17 → CSE-18 | `R10` (10 feat) | RF, LSTM, Fusion Transfer | `results/experiments/EXP-P1-TRANSFER-CIC-TO-CSE-R10-001/` | `DONE` | Target RF F1: **0.3286** (Δ -0.6225) |
| `EXP-P1-TRANSFER-CSE-TO-CIC-R10-001` | RQ3 | CSE-18 → CIC-17 | `R10` (10 feat) | RF, LSTM, Fusion Transfer | `results/experiments/EXP-P1-TRANSFER-CSE-TO-CIC-R10-001/` | `DONE` | Target LSTM F1: **0.2601** (Δ -0.7003) |
| `EXP-P1-TRANSFER-UNSW-TO-CIC-R4-001` | RQ3 | UNSW → CIC-17 | `transfer_common_4` | RF, LSTM, Fusion Transfer | `results/experiments/EXP-P1-TRANSFER-UNSW-TO-CIC-R4-001/` | `DONE` | Target Fusion F1: **0.3664** (Δ -0.5306) |
| `EXP-P1-TRANSFER-UNSW-TO-CSE-R4-001` | RQ3 | UNSW → CSE-18 | `transfer_common_4` | RF, LSTM, Fusion Transfer | `results/experiments/EXP-P1-TRANSFER-UNSW-TO-CSE-R4-001/` | `DONE` | Target LSTM F1: **0.0380** (Δ -0.8258) |
| `EXP-P1-TRANSFER-CIC-TO-UNSW-R4-001` | RQ3 | CIC-17 → UNSW | `transfer_common_4` | RF, LSTM, Fusion Transfer | `results/experiments/EXP-P1-TRANSFER-CIC-TO-UNSW-R4-001/` | `DONE` | Target LSTM F1: **0.0051** (Δ -0.9004) |
| `EXP-P1-TRANSFER-CSE-TO-UNSW-R4-001` | RQ3 | CSE-18 → UNSW | `transfer_common_4` | RF, LSTM, Fusion Transfer | `results/experiments/EXP-P1-TRANSFER-CSE-TO-UNSW-R4-001/` | `DONE` | Target LSTM F1: **0.0048** (Δ -0.8872) |
| `EXP-P2A-BASELINES-001` | RQ4 | CIC-IDS2017 | `response_state_v1` | Static & Rule-Based Baselines | `results/phase2/EXP-P2A-BASELINES-001/` | `DONE` | Cost matrix established across 4 regimes |
| `EXP-P2B-DQN-001` | RQ4 | CIC-IDS2017 | `response_state_v1` | Dueling DQN + PER (3 & 4 Actions) | `results/phase2/EXP-P2B-DQN-001/` | `DONE` | Val Cost: **2.15** (3-action), **5.44** (4-action) |
| `EXP-P2C-SENSITIVITY-001` | RQ4, RQ5 | CIC-IDS2017 | State Ablations | DQN State Feature Ablation | `results/phase2/EXP-P2C-SENSITIVITY-001/` | `DONE` | Alert density & duration most critical |
| `EXP-P2D-ROBUSTNESS-001` | RQ4 | CIC-IDS2017 | `response_state_v1` | Noise & Adversarial Perturbation | `results/phase2/EXP-P2D-ROBUSTNESS-001/` | `DONE` | Policy stability verified under noise |
| `EXP-P2E-EXPLAINABILITY-001` | RQ5 | CIC-IDS2017 | `R10` | TreeSHAP Dual-Layer Explanations | `results/phase2/EXP-P2E-EXPLAINABILITY-001/` | `DONE` | 28,167 dual-layer audit cards generated |
| `EXP-P2-FINAL-TEST-001` | RQ4 | CIC-IDS2017 | `response_state_v1` | Held-Out 355k Flow Evaluation | `results/phase2/EXP-P2-FINAL-TEST-001/` | `DONE` | DQN cost **5.32** vs Baseline 1 **7.48** (4-action) |
| `EXP-P3G-ROLLBACK-001` | Systems | Live/Simulated | Transaction API | Atomic Rollback & Watchdog | `results/phase3/EXP-P3G-ROLLBACK-001/` | `DONE` | 100% rollback success on failure injection |
| `EXP-P3H-ENFORCEMENT-GATE-001` | Systems | Live/Simulated | Precondition Gate | Enforcement Readiness Harness | `results/phase3/EXP-P3H-ENFORCEMENT-GATE-001/` | `DONE` | 5/5 precondition gates strictly validated |
| `EXP-P3I-ISOLATED-LAB-001` | Systems | Netns Lab | Controlled Loop | Netns Isolation Loop Runner | `results/phase3/EXP-P3I-ISOLATED-LAB-001/` | `DONE` | Zero host network mutation observed |
| `EXP-P3J-CONCURRENCY-001` | Systems | Netns Lab | Transaction Queue | Concurrent Isolated Transactions | `results/phase3/EXP-P3J-CONCURRENCY-001/` | `DONE` | Deadlock-free under concurrent traffic load |
| `EXP-P3K-SECURITY-STRESS-001` | Systems | Netns Lab | Stress Matrix | Pre-Production Security Stress Audit | `results/phase3/EXP-P3K-SECURITY-STRESS-001/` | `DONE` | All safety invariants preserved under stress |

---

## Summary of Research Questions Addressed

1. **RQ1: Detection Efficacy & Baseline Ordering**
   - Verified on 3 benchmarks. The empirical ladder holds monotonically:
     $$\text{Majority (F1: 0.00)} < \text{Logistic Reg (F1: 0.76-0.89)} < \text{Decision Tree (F1: 0.85-0.93)} < \text{Random Forest (F1: 0.85-0.95)} < \text{LSTM (F1: 0.86-0.96)}$$
2. **RQ2: Score-Level Ensemble Fusion**
   - Fusion achieves peak F1 of **0.9745** (CICIDS2017) and **0.8970** (UNSW-NB15) with Platt probability calibration.
3. **RQ3: Cross-Dataset Domain Shift Collapse**
   - Detectors trained in one environment experience severe performance degradation when evaluated out-of-domain without re-training (F1 dropping by up to 0.95). Covariate shift and feature definition disparities between capture toolchains are the primary drivers.
4. **RQ4: Reinforcement Learning Autonomous Response**
   - Deep Q-Networks dynamically balance containment costs against operational availability, achieving lower cumulative penalty than static threshold baselines under asymmetric attack regimes.
5. **RQ5: Dual-Layer Explainability & Auditability**
   - TreeSHAP feature attributions combined with discrete action rationales provide transparent, inspectable justification for autonomous network actions.
