# XRL-IDARS v1 — REPRODUCIBILITY MAP

> **Purpose:** Authoritative reproduction guide for researchers, auditors, and examination committees.  
> **Status:** AUDITED & FROZEN  
> **Repository Commit Baseline:** `f600bfb4c94665de4c94ce743b680d8bc25a33f9`

---

## 1. Execution Environment & Dependencies

All experiments were executed and verified under the following standardized software environment:

- **Operating System:** Linux 7.0.0-38-generic x86_64
- **Python Version:** 3.14.4
- **Virtual Environment:** `.venv` (located in repository root)
- **CUDA Available:** False (Deterministic CPU execution for full reproducibility)

### Key Pinned Package Dependencies:
- `numpy`: `2.5.3`
- `pandas`: `3.0.6`
- `scikit-learn`: `1.9.1`
- `scipy`: `1.18.1`
- `torch`: `2.14.0+cpu`
- `shap`: `0.52.0`
- `matplotlib`: `3.11.2`
- `PyYAML`: `6.0.3`
- `scapy`: `2.6.1`
- `pytest`: `8.3.4`

To restore the environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 2. Dataset Verification & Provenance

All raw datasets are registered with authoritative SHA-256 cryptographic digests in `data/manifests/dataset_registry.yaml`.

To verify physical file integrity:
```bash
.venv/bin/python scripts/phase1/01_verify_checksums.py
```

### Dataset Inventory:
1. **CIC-IDS2017:** 8 physical CSV files (2,830,743 raw rows)
2. **CSE-CIC-IDS2018:** 10 physical CSV files (16,233,002 raw rows)
3. **UNSW-NB15:** 2 physical CSV files (257,673 raw rows)

---

## 3. Test Suite Verification

To execute the complete 386-test verification suite:
```bash
.venv/bin/pytest -q
```
*Expected Result:* `386 passed in ~41s` (0 failures, 100% pass rate).

---

## 4. Master Reproduction Command Matrix

### Phase 1: Intrusion Detection Baselines, Transfer & Explainability

| Experiment ID | Description | Config Path | Reproduction Command | Primary Artifact Location |
|:---|:---|:---|:---|:---|
| `AUDIT-001` | Multi-file streaming dataset audit | `configs/datasets/` | `.venv/bin/python scripts/phase1/03_run_audit.py` | `results/audits/` |
| `EXP-P1-CIC2017-R10-001` | CIC-IDS2017 RF, LSTM, Fusion | `configs/experiments/cic_ids2017_r10.yaml` | `.venv/bin/python scripts/phase1/run_experiment.py --config configs/experiments/cic_ids2017_r10.yaml` | `results/experiments/EXP-P1-CIC2017-R10-001/` |
| `EXP-P1-CSE2018-R10-MULTI-001` | CSE-CIC-IDS2018 RF, LSTM, Fusion | `configs/experiments/cse_cic_ids2018_r10_multi.yaml` | `.venv/bin/python scripts/phase1/run_experiment.py --config configs/experiments/cse_cic_ids2018_r10_multi.yaml` | `results/experiments/EXP-P1-CSE2018-R10-MULTI-001/` |
| `EXP-P1-UNSWNB15-R10-MULTI-001` | UNSW-NB15 R4 Baselines | `configs/experiments/unsw_nb15_r10_multi.yaml` | `.venv/bin/python scripts/phase1/run_experiment.py --config configs/experiments/unsw_nb15_r10_multi.yaml` | `results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001/` |
| `EXP-P1-TRANSFER-*` | 6-Direction Cross-Dataset Transfer | `configs/experiments/transfer_*.yaml` | `.venv/bin/python scripts/phase1/run_transfer.py` | `results/cross_dataset/` |

---

### Phase 2: Autonomous Response Intelligence & Safety Layer

*Note: Phase 2 empirical artifacts are scientifically frozen (`11f32f658cde525300f8bc46088a0143e8329c21`). Do not overwrite committed results.*

| Experiment ID | Description | Primary Reproduction Command | Artifact Location |
|:---|:---|:---|:---|
| `EXP-P2A-BASELINES-001` | 4 Deterministic Heuristic Baselines | `.venv/bin/python scripts/phase2/run_phase2a_baselines.py` | `results/phase2/EXP-P2A-BASELINES-001/` |
| `EXP-P2B-DQN-001` | Dueling DQN Policy Training | `.venv/bin/python scripts/phase2/run_phase2b_dqn.py` | `results/phase2/EXP-P2B-DQN-001/` |
| `EXP-P2C-SENSITIVITY-001` | 6D State Sensitivity & Ablation | `.venv/bin/python scripts/phase2/run_phase2c_sensitivity.py` | `results/phase2/EXP-P2C-SENSITIVITY-001/` |
| `EXP-P2D-ROBUSTNESS-001` | Jitter & Out-of-Domain Stress | `.venv/bin/python scripts/phase2/run_phase2d_robustness.py` | `results/phase2/EXP-P2D-ROBUSTNESS-001/` |
| `EXP-P2E-EXPLAINABILITY-001` | Dual-Layer Audit Cards (28,167 cards) | `.venv/bin/python scripts/phase2/run_phase2e_explainability.py` | `results/phase2/EXP-P2E-EXPLAINABILITY-001/` |
| `EXP-P2-FINAL-TEST-001` | Authoritative Test on 355,865 Flows | `.venv/bin/python scripts/phase2/run_phase2_final_test.py` | `results/phase2/EXP-P2-FINAL-TEST-001/` |

---

### Phase 3: Live Network Validation & Controlled Enforcement

| Experiment ID | Description | Primary Reproduction Command | Artifact Location |
|:---|:---|:---|:---|
| `DEMO-REPLAY-001` | Deterministic PCAP Replay Demo | `.venv/bin/python scripts/demo/run_replay_demo.py` | `results/demo/` |
| `EXP-P3-BURST-1000-001` | 1,000-Packet Traffic Burst (DRY_RUN) | `.venv/bin/python scripts/phase3/run_burst_experiment.py` | `results/phase3/EXP-P3-BURST-1000-001/` |
| `EXP-P3F-OBSERVABILITY-001` | Observability & Backpressure Test | `.venv/bin/python scripts/phase3/run_observability_experiment.py` | `results/phase3/EXP-P3F-OBSERVABILITY-001/` |
| `EXP-P3G-ROLLBACK-001` | Atomic Rollback & Transaction Harness | `.venv/bin/python scripts/phase3/run_rollback_experiment.py` | `results/phase3/EXP-P3G-ROLLBACK-001/` |
| `EXP-P3H-ENFORCEMENT-GATE-001`| Activation Gate & Provenance Audit | `.venv/bin/python scripts/phase3/run_enforcement_gate_experiment.py` | `results/phase3/EXP-P3H-ENFORCEMENT-GATE-001/` |
| `EXP-P3I-ISOLATED-LAB-001` | Isolated Lab Netns Response Loop | `.venv/bin/python scripts/phase3/run_isolated_lab_experiment.py` | `results/phase3/EXP-P3I-ISOLATED-LAB-001/` |
| `EXP-P3J-CONCURRENCY-001` | Multi-Target Concurrency Stress | `.venv/bin/python scripts/phase3/run_concurrency_experiment.py` | `results/phase3/EXP-P3J-CONCURRENCY-001/` |
| `EXP-P3K-STRESS-SECURITY-001` | Pre-Production Security & Stress Audit | `.venv/bin/python scripts/phase3/run_security_stress_experiment.py` | `results/phase3/EXP-P3K-STRESS-SECURITY-001/` |

---

## 5. Key Commit History & Milestones

- `11f32f658cde525300f8bc46088a0143e8329c21`: Phase 1 & Phase 2 Scientific Freeze (Authoritative Offline Baseline).
- `724969ae24b17e6fc09d8a7646c2e81de4d46dc6`: Phase 3 Foundation (Live Feature Parity & Capture Engine).
- `09fc82822a7cb0bcf080ae0b69ab42991c01e3a4`: Phase 3E Controlled 1,000-Packet Burst Experiment.
- `8db56828a2a7aa8fb635a9f2ce54316d3e336b9e`: Phase 3F Observability & Health Harness.
- `05587f7300c0a59918b958cfa89f71cba83a8b47`: Phase 3G Atomic Rollback Transaction Harness.
- `3e62fba23f86e9275cb6b23f2f0174ca40026e64`: Phase 3H Enforcement Readiness & Provenance Gate.
- `ed9bd593dfa99f1faae757303c7336181ef80a37`: Phase 3I Isolated Lab Namespace Response Loop.
- `4e06e71b8ec244211ea389fdff137d0e67c70847`: Phase 3J Multi-Target Concurrency & Striped Locking.
- `f3cecb68cf7dce34f768afb5e8cb1c902229e415`: Phase 3J Reconciliation of Transaction Counts.
- `f600bfb4c94665de4c94ce743b680d8bc25a33f9`: Phase 3K Pre-Production Security & Stress Audit.
