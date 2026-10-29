# XRL-IDARS — Single Research Evidence & Reproduction Index

> **Authoritative Research Evidence Index**  
> *Target System: XRL-IDARS (Intrusion Detection and Autonomous Response System)*  
> *Audit Standard: Forensic Evidence Reconciliation (EXP-P2B-READINESS-AUDIT-001)*  
> *Repository: `rishikeshgowdakk/fyp-xrlids`*

---

## 1. Evidentiary Taxonomy & Scientific Standards

All experimental findings and claims within XRL-IDARS are categorized strictly according to four evidentiary tiers:

1. **`VERIFIED & FROZEN`**: Mathematical proofs, verified software invariants, or deterministic metrics evaluated on committed, held-out test splits with exact reproduction scripts and matching cryptographic hashes.
2. **`EMPIRICALLY OBSERVED NEGATIVE FINDINGS`**: Rigorous empirical experiments proving the failure, collapse, or limitations of specific models or assumptions under realistic network conditions (e.g., temporal drift, cross-dataset transfer, RL vs heuristic cost).
3. **`HISTORICAL EVIDENCE`**: Early preliminary experiments (e.g., single-day runs) that formed early research stages but were formally superseded by comprehensive multi-day runs.
4. **`EXPLORATORY / DECISION OPEN`**: Governance frameworks or candidate thresholds (e.g., $\tau_{\text{ops}} = 0.40$) proposed as operational candidates pending real-world cost calibration.

---

## 2. Headline Metrics Master Index

| Research Topic / Finding | Claimed Metric / Result | Evidentiary Status | Source Artifact / Result File | Reproduction Command |
|:---|:---|:---:|:---|:---|
| **CIC-IDS2017 Primary Benchmark** | RF F1: **0.9512** · LSTM F1: **0.9633** · Fusion F1: **0.9745** (Acc: 0.9906) | `VERIFIED & FROZEN` | `results/experiments/EXP-P1-CIC2017-R10-001/metrics.json` | `python scripts/phase1/run_experiment.py --config configs/cicids2017.yaml` |
| **CSE-CIC-IDS2018 10-File Benchmark** | RF F1: **0.8861** · LSTM F1: **0.9603** · Fusion F1: **0.9603** (Acc: 0.9912) | `VERIFIED & FROZEN` | `results/experiments/EXP-P1-CSE2018-R10-MULTI-001/metrics.json` | `python scripts/phase1/run_experiment.py --config configs/cse2018.yaml` |
| **UNSW-NB15 2-File Benchmark** | RF F1: **0.8548** · LSTM F1: **0.8637** · Fusion F1: **0.8970** (Acc: 0.8996) | `VERIFIED & FROZEN` | `results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001/metrics.json` | `python scripts/phase1/run_experiment.py --config configs/unswnb15.yaml` |
| **Degenerate Fusion on CSE-2018** | Optimal grid weight **$\alpha = 0.00$** (Fusion identical to LSTM) | `EMPIRICALLY OBSERVED NEGATIVE FINDING` | `models/fusion/fusion_weights.json` | `python -m pytest tests/unit/test_phase2_audit_consistency.py` |
| **LSTM Shuffled-Window Ablation** | Shuffling flow order yields **$\Delta \text{F1} = -0.0038$** (no sequence gain) | `EMPIRICALLY OBSERVED NEGATIVE FINDING` | `results/experiments/EXP-P1-CIC2017-R10-001/ablation_shuffled.json` | `python scripts/phase1/run_ablation.py --type shuffle` |
| **Cross-Dataset Transfer Collapse** | F1 collapses by **52% to 95%** across all 6 out-of-domain directions | `EMPIRICALLY OBSERVED NEGATIVE FINDING` | `reports/generated/transfer_report.md` | `python -m pytest tests/integration/test_cross_dataset_transfer.py` |
| **Temporal Concept Drift Collapse** | CSE-2018 future-day test F1 collapses from **0.8861 down to 0.0113** | `EMPIRICALLY OBSERVED NEGATIVE FINDING` | `results/experiments/EXP-P1-CSE2018-TEMPORAL-R10-001/metrics.json` | `python scripts/phase1/run_temporal_experiment.py` |
| **TreeSHAP Feature Attributions** | `packet_length_std` and `flow_packets_per_s` drive >60% of RF decisions | `VERIFIED & FROZEN` | `reports/generated/shap_report.md` | `python -m pytest tests/unit/test_shap_analysis.py` |
| **Autonomous Response Cost Optimization** | Analytic `CostOptimal` beats DQN by **20.12% lower cost** in High Availability | `EMPIRICALLY OBSERVED NEGATIVE FINDING` | `results/phase2/EXP-P2-FINAL-TEST-001/final_test_metrics.json` | `python -m pytest tests/unit/test_response_baselines.py` |
| **Autonomous Response Latency** | `CostOptimal` runs in **1.95 µs** vs DQN **100.23 µs** (~51x faster) | `VERIFIED & FROZEN` | `results/phase2/EXP-P2B-READINESS-AUDIT-001/latency_benchmarks.json` | `python -m pytest tests/unit/test_response_baselines.py` |
| **Deterministic Safety Gate** | Zero unauthorized network mutations; blast radius capped at 5 hosts | `VERIFIED & FROZEN` | `configs/safety/response_safety_policy.yaml` | `python -m pytest tests/integration/test_safety_invariants.py` |
| **Test Suite Pass Rate** | **493 passed, 0 failed (100% pass rate)** | `VERIFIED & FROZEN` | `reports/generated/phase1_status.md` | `python -m pytest tests/ -q` |

---

## 3. Detailed Evidence Sections

### 3.1 Primary In-Domain Benchmark Evaluation

Direct comparisons across model architectures were conducted on identical aligned test splits post-Policy A deduplication.

#### CIC-IDS2017 Ladder Architecture (`EXP-P1-CIC2017-R10-001`)
- **Majority Class Baseline**: Accuracy = 0.8171, F1 = 0.0000.
- **Logistic Regression**: Accuracy = 0.9124, F1 = 0.7712, ROC-AUC = 0.9234.
- **Decision Tree**: Accuracy = 0.9784, F1 = 0.9419, ROC-AUC = 0.9681.
- **Random Forest**: Accuracy = **0.9815**, Precision = **0.9782**, Recall = **0.9256**, F1 = **0.9512**, ROC-AUC = **0.9968**.
- **Supervised LSTM ($T=5$)**: Accuracy = **0.9867**, Precision = **0.9810**, Recall = **0.9463**, F1 = **0.9633**, ROC-AUC = **0.9975**.
- **Score Fusion ($\alpha = 0.50$)**: Accuracy = **0.9906**, Precision = **0.9854**, Recall = **0.9638**, F1 = **0.9745**, ROC-AUC = **0.9982**.
- **Paired Bootstrap Significance**: Fusion vs RF: $\Delta \text{F1} = +0.0233$, 95% CI $[+0.0218, +0.0248]$, paired $p < 0.001$.

#### Population Boundary Proof (32-Flow Discrepancy)
The tabular test split contains **355,865 flows**, whereas the sequence test split contains **355,833 flows**.
- **Mathematical Boundary Proof**: With sequence context length $T=5$, exactly $T - 1 = 4$ initial flows at each capture file boundary cannot form a causal sequence without leaking context across independent file boundaries.
- Across $N_{\text{files}} = 8$ capture files:
  $$N_{\text{dropped}} = 8 \times 4 = 32 \text{ flows}$$
- Every one of the 32 dropped boundary flows was audited and verified to be a benign baseline flow (`BENIGN`), guaranteeing zero dropped attack instances.

---

### 3.2 Negative Findings: When Machine Learning Fails

#### 1. Degenerate Score Fusion on CSE-CIC-IDS2018
- **Finding**: On the 1.66-million flow test split of CSE-CIC-IDS2018, extensive validation grid search ($\alpha \in [0.00, 1.00]$, step 0.05) selected **$\alpha = 0.00$**.
- **Implication**: Convex blending of Random Forest with LSTM yields zero incremental accuracy over the standalone LSTM. At $\alpha = 0.00$, the fusion system reduces strictly to the LSTM detector.
- **Evidence**: `models/fusion/fusion_weights.json` explicitly assigns `{"cse2018": {"alpha": 0.0}}`.

#### 2. Shuffled-Window Ablation (LSTM Temporal Disconnect)
- **Finding**: When the flow ordering within each length-5 sequence is randomly shuffled, the resulting F1 score decreases by only **$0.0038$** ($\Delta \text{F1} = -0.0038$, from $0.9633$ to $0.9595$).
- **Implication**: The LSTM does not learn genuine sequential or syntactic causal chains across flows. Instead, it functions primarily as a spatial pooling filter that aggregates and smooths flow rate bursts over a 5-flow window.
- **Evidence**: `results/experiments/EXP-P1-CIC2017-R10-001/ablation_shuffled.json`.

#### 3. Cross-Dataset Transfer Collapse
- **Finding**: When models trained on one dataset are evaluated on another without domain adaptation, detection performance catastrophically collapses:
  - **`CIC → CSE` (R10)**: F1 drops from 0.9512 to **0.4439** (-53.3%).
  - **`CSE → CIC` (R10)**: F1 drops from 0.8861 to **0.3854** (-56.5%).
  - **`UNSW → CIC` (R4)**: F1 collapses to **0.3664**; false positive rate surges to **53.94%** on benign traffic.
  - **`UNSW → CSE` (R4)**: F1 collapses to **0.0380**; false positive rate surges to **50.70%**.
  - **`CIC → UNSW` & `CSE → UNSW` (R4)**: F1 collapses to **<0.01**.
- **Evidence**: Two-sample Kolmogorov-Smirnov tests confirm massive covariate shift ($D = 0.18 - 0.57, p < 0.001$). See [transfer_report.md](../reports/generated/transfer_report.md).

#### 4. Temporal Generalization Failure (Chronological Future-Day Holdout)
- **Finding**: In `EXP-P1-CSE2018-TEMPORAL-R10-001`, training was conducted on 14–20 Feb 2018, validation on 20–22 Feb, and testing on 22 Feb–2 Mar (using genuine timestamps).
- **Result**: The frozen Random Forest achieves **F1 = 0.0113** (Recall: 0.0068, ROC-AUC: 0.3905) on the future test partition, collapsing from 0.8861 on the random split.
- **Per-Attack Collapse**: Bot recall falls from 99.17% to 0.09%; Infiltration falls from 10.70% to 0.94%; Web, XSS, and SQL attacks drop to 0.00% recall.
- **Evidence**: `results/experiments/EXP-P1-CSE2018-TEMPORAL-R10-001/metrics.json` and [temporal_split_report.md](../reports/generated/temporal_split_report.md).

---

### 3.3 Autonomous Response: RL vs Cost-Optimal Baseline

In Phase 2, we conducted a controlled benchmark between trained Dueling Deep Q-Networks and a zero-parameter analytic `CostOptimalThresholdPolicy` across six operational loss regimes:

| Operational Regime | Action Space | DQN Total Cost | Cost-Optimal Cost | Winning Policy | Cost Advantage (%) |
|:---|:---:|---:|---:|:---:|:---:|
| **Standard Enterprise** | 3-Action | $505,610.5$ | $505,610.5$ | Tied | $0.00\%$ |
| **Standard Enterprise** | 4-Action | $1,895,196.5$ | $1,741,402.0$ | **Cost-Optimal** | **+8.11%** |
| **High Availability** | 3-Action | $391,240.0$ | $391,240.0$ | Tied | $0.00\%$ |
| **High Availability** | 4-Action | $1,937,476.5$ | $1,547,511.0$ | **Cost-Optimal** | **+20.12%** |
| **Aggressive Containment** | 3-Action | $612,180.0$ | $612,180.0$ | Tied | $0.00\%$ |
| **Aggressive Containment** | 4-Action | $1,811,290.0$ | $1,811,290.0$ | Tied | $0.00\%$ |

#### Key Insights for Viva Defense
1. **Cost-Optimal Outperforms DQN**: In the most critical regime (High Availability 4-Action), the simple zero-parameter threshold policy beats the deep reinforcement learning agent by **20.12% lower cost**.
2. **Inference Latency Advantage**: The analytic policy computes decisions in **1.95 µs**, compared to **100.23 µs** for the neural network—a **~51x speedup**.
3. **Environment Causal Reality**: The network simulation environment is an **Asymmetric-Loss Contextual Bandit with Hysteresis Constraints**, NOT a true sequential MDP. Arrival of network flows is exogenous; taking a mitigation action does not change which packets arrive in future time steps. Therefore, discount factor $\gamma = 0.95$ lacks physical grounding.

---

### 3.4 Low-Footprint Attack Failure Analysis

Our fine-grained per-attack family audit revealed that standard volumetric benchmarks hide massive blind spots for low-footprint attacks:
- **Infiltration**: Recall is **10.70%** on CSE-CIC-IDS2018 and **0.00%** on CIC-IDS2017.
- **Web Brute Force**: Recall is **15.89%**.
- **Cross-Site Scripting (XSS)**: Recall is **2.78%**.
- **SQL Injection**: Recall is **0.00%**.
- **Root Cause**: Volumetric statistical features (`flow_packets_per_s`, `flow_duration_ms`) easily detect DoS/DDoS floods, but fail completely on low-packet-rate application-layer exploits.

---

## 4. Full Reproduction Playbook

Execute the following commands in order to verify all research evidence from scratch:

```bash
# 1. Run full unit, data, integration, and model test suite (493 tests, ~48s)
.venv/bin/python -m pytest tests/ -q

# 2. Verify all 9 canonical model hashes and sizes against the registry
.venv/bin/python scripts/verify_fresh_clone_exhibition.py

# 3. Regenerate all 13 Phase 1 markdown reports from experiment records
.venv/bin/python scripts/phase1/generate_reports.py

# 4. Run cross-dataset transfer test suite (verifies 6-direction collapse)
.venv/bin/python -m pytest tests/integration/test_cross_dataset_transfer.py -v

# 5. Run autonomous response baseline tests (verifies DQN vs Cost-Optimal)
.venv/bin/python -m pytest tests/unit/test_response_baselines.py -v

# 6. Verify deterministic safety invariants and rollback constraints
.venv/bin/python -m pytest tests/integration/test_safety_invariants.py -v

# 7. Check all 226 local markdown links across documentation and reports
.venv/bin/python -c '
import os, re, pathlib
broken = []
for root, _, files in os.walk("."):
    if any(d in root for d in (".git", ".venv", "node_modules")): continue
    for f in files:
        if f.endswith(".md"):
            p = pathlib.Path(root) / f
            for _, link in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", p.read_text(encoding="utf-8", errors="ignore")):
                if link.startswith(("http", "#", "mailto:")): continue
                target = (p.parent / link.split("#")[0]).resolve()
                if not target.exists(): broken.append((str(p), link))
assert len(broken) == 0, f"Found {len(broken)} broken links: {broken}"
print("All markdown links verified: 0 broken.")
'
```
