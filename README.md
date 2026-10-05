# XRL-IDARS

**Explainable Reinforcement Learning Based Intrusion Detection and Autonomous Response System**

XRL-IDARS is an open-source cybersecurity research platform that couples high-throughput network flow intrusion detection, dual-layer explainability, and context-aware reinforcement learning with deterministic safety constraints and atomic rollback mechanisms. The system autonomously evaluates incoming network traffic, predicts security threats, computes associative feature attributions, proposes graduated mitigation responses, and enforces actions strictly through transaction-monitored, cryptographically verifiable state mutations.

---

## 1. Overview

XRL-IDARS is designed as a unified cyber-defense pipeline that bridges the gap between passive machine learning detection and responsible autonomous mitigation. Rather than treating detection and response as disconnected tools, the platform implements a closed-loop control architecture:

```text
Network traffic
→ flow construction
→ feature extraction
→ ML-based intrusion detection
→ threat score
→ explainability
→ reinforcement-learning response decision
→ deterministic safety constraints
→ controlled response transaction
→ verification
→ rollback
→ audit trail
```

The system integrates:
- **Random Forest**: Low-latency tabular flow-level detection.
- **Supervised LSTM**: Multi-flow temporal sequence modeling ($T=5$ consecutive flows).
- **RF + LSTM Score Fusion**: Calibrated convex score combination combining spatial and temporal features.
- **TreeSHAP**: Feature attribution identifying associative drivers of attack classifications.
- **Dueling Deep Q-Network (DQN)**: Context-aware response policy trained with Prioritized Experience Replay.
- **Deterministic Safety Gate**: Invariant enforcement, action cooldowns, blast-radius limits, and critical infrastructure exemptions.
- **Atomic Response Transactions**: Pre-action state snapshots, automated compensation rollbacks, and watchdog monitors.
- **Cryptographic State Verification**: Pre/post SHA-256 state hashing to mathematically guarantee zero host network mutations.
- **Isolated Linux Laboratory Enforcement**: Dual-namespace network topology (`10.200.1.0/24`) for safe, controlled evaluation.

---

## 2. Problem Being Solved

Traditional Intrusion Detection Systems (IDS) detect malicious traffic patterns but typically terminate their pipeline at passive alert generation. Modern high-rate attacks (such as automated brute force, volumetric flooding, and credential stuffing) inflict damage in seconds, while human security operations center (SOC) triage times average minutes to hours.

Conversely, naive autonomous response systems risk self-inflicted Denial of Service (DoS) when false positives trigger the isolation of critical infrastructure (such as domain controllers, DNS servers, or database gateways).

XRL-IDARS investigates whether:

```text
accurate detection
+
context-aware reinforcement learning
+
explainability
+
strict deterministic safety
+
atomic rollback
```

can provide an effective, auditable, and resilient autonomous cyber-defense architecture without granting unconstrained black-box models direct control over live networks.

---

## 3. Complete System Architecture

The end-to-end pipeline operates deterministically from raw network packets to auditable mitigation actions:

```text
Network Traffic / PCAP
          ↓
Packet Capture (Streaming / Replay)
          ↓
Bidirectional Flow Construction (TCP FIN/RST & 120s Idle Timeout)
          ↓
Canonical R10 Feature Extraction (atol ≤ 1e-4 Numerical Parity)
          ↓
Feature Validation / Preprocessing (Train-Fitted Standard Scaler)
          ↓
 ┌────────────────────────────────────────────────────────┐
 │ Intrusion Detection Subsystem                          │
 │                                                        │
 │ Random Forest (Flow)        Supervised LSTM (Sequence) │
 │         \                               /              │
 │          \                             /               │
 │           ▼                           ▼                │
 │               Convex Score Fusion                      │
 └──────────────────────────┬─────────────────────────────┘
                            ↓
                    Threat Score S_t ∈ [0, 1]
                            ↓
       ┌────────────────────┴─────────────────────┐
       ▼                                          ▼
Perceptual Attribution                    Causal 6D State
   (TreeSHAP)                        (S_t, ΔS_t, N_alert, a_t-1, c_t, v_t)
       │                                          │
       │                                          ▼
       │                                 Dueling DQN Policy
       │                                (Trained with PER)
       │                                          │
       │                                          ▼
       │                                  Proposed Action
       │                       (ALLOW / ALERT / RATE_LIMIT / ISOLATE)
       │                                          │
       │                                          ▼
       │                              Deterministic Safety Gate
       │                       (Cooldowns, Blast Radius, Critical Exempt)
       │                                          │
       │                                          ▼
       │                                   Enforced Action
       │                                          │
       │                        ┌─────────────────┴─────────────────┐
       │                        ▼                                   ▼
       │                  Safe Actions                    Mutating Actions
       │                 (ALLOW / ALERT)               (RATE_LIMIT / ISOLATE)
       │                        │                                   │
       │                        │                     Controlled Response Transaction
       │                        │                     (Pre-Snapshot → Apply → Verify)
       │                        │                                   │
       │                        │                         ┌─────────┴─────────┐
       │                        │                         ▼                   ▼
       │                        │                     Committed           Rollback
       │                        │                  (Digest Match)     (Failure/Timeout)
       │                        │                         │                   │
       │                        └────────────────┬────────┴───────────────────┘
       │                                         │
       ▼                                         ▼
 ┌────────────────────────────────────────────────────────────────────────┐
 │ Dual-Layer Explainability & Append-Only Audit Logging                  │
 │                                                                        │
 │ - Flow Feature Attributions (TreeSHAP)                                 │
 │ - Decision State & Q-Value Margins                                     │
 │ - Safety Gate Overrides & Invariant Audits                             │
 │ - Machine-Readable Run Summaries (JSON / Markdown)                     │
 └────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Detection Models

### Random Forest
The primary tabular flow detector. It operates on statistical flow summaries, handling non-linear feature interactions with low inference latency (~0.1 ms/flow). It serves as the primary detector in the live PCAP replay engine.

### Supervised LSTM
A recurrent neural sequence model conditioned on sequences of $T=5$ consecutive flows. It captures inter-flow temporal dependencies, progressive scanning patterns, and multi-stage infiltration behaviors, reducing false alarms by up to 66% on structured traffic.

### RF + LSTM Fusion
A calibrated convex score combination:
$$S_{\text{fusion}} = \alpha \cdot S_{\text{RF}} + (1 - \alpha) \cdot S_{\text{LSTM}}$$
The optimal weighting parameter $\alpha$ is dataset-dependent ($\alpha=0.50$ on CIC-IDS2017, $\alpha=0.00$ on CSE-CIC-IDS2018, and $\alpha=0.60$ on UNSW-NB15), allowing the system to balance tabular precision against sequence context.

### Canonical Feature Contract (R10)
All models evaluate a frozen, portable 10-feature transport contract:
1. `flow_duration_ms`: Total active flow duration in milliseconds
2. `flow_packets_per_s`: Flow packet transmission rate
3. `flow_bytes_per_s`: Flow byte throughput rate
4. `packet_length_mean`: Mean packet length across forward and backward directions
5. `packet_length_std`: Standard deviation of packet lengths
6. `syn_count`: Total TCP SYN flags observed
7. `ack_count`: Total TCP ACK flags observed
8. `rst_count`: Total TCP RST flags observed
9. `fin_count`: Total TCP FIN flags observed
10. `syn_ack_ratio`: Ratio of SYN flags to ACK flags

**Auxiliary Fallback (R4)**: On UNSW-NB15, Argus/Bro NetFlow logs physically lack 6 of the 10 R10 features (TCP flags and packet length standard deviations). To prevent data fabrication, UNSW-NB15 uses a verified 4-feature contract (`flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean`).

---

## 5. Reinforcement Learning Response

The autonomous response layer translates continuous detection scores and operational context into optimal mitigation decisions.

### Causal 6D State Vector
The agent observes an entity-level state vector:
$$\mathbf{s}_t = (S_t, \Delta S_t, N_{\text{alert}}, a_{t-1}, c_t, v_t)$$
- $S_t \in [0, 1]$: Continuous threat score from the detector.
- $\Delta S_t$: First-order threat score trajectory relative to recent history.
- $N_{\text{alert}}$: Windowed alert density count for the entity.
- $a_{t-1}$: Immediate previous response action applied.
- $c_t$: Active cooldown status flag / timer.
- $v_t$: Normalized volumetric packet rate context.

### Action Space
- `ALLOW`: Forward traffic unmodified.
- `ALERT`: Flag suspicious behavior for analyst inspection without network mutation.
- `RATE_LIMIT`: Apply token-bucket traffic shaping to constrain throughput.
- `ISOLATE`: Fully quarantine and block traffic from the target host.

### Policy & Optimization
- **Architecture**: Dueling DQN decoupling state-value $V(s)$ and action-advantage $A(s, a)$.
- **Replay**: Prioritized Experience Replay (PER) to efficiently learn from sparse attack episodes.
- **Reward Modeling**: Asymmetric cost matrices penalizing operational downtime, business disruption, and false isolation against security breach damage.

---

## 6. Explainability

XRL-IDARS provides dual-layer explainability across both perception and action:

1. **Detector Explainability (TreeSHAP)**: Explains why a flow was classified as malicious by attributing scores to underlying network flow features (e.g., anomalous packet length variance or TCP reset ratios).
2. **Response Explainability (Audit Cards)**: Explains why a specific mitigation action was taken. Every non-ALLOW intervention generates an immutable audit record containing:
   - Threat score and input state vector
   - Proposed action vs enforced action
   - Safety override flag and specific reason (if altered)
   - Top feature attributions
   - Policy Q-value distribution and decision margins

In held-out benchmarking across 28,167 non-ALLOW interventions, the system achieved **100.00% audit coverage** with zero missing attribution records.

---

## 7. Safety Architecture

Autonomous response mutations are wrapped in a strict safety and transaction harness:

```text
Preconditions
↓
Evidence verification
↓
Authorization
↓
Safety gate
↓
Snapshot
↓
Prepare
↓
Apply
↓
Verify
↓
Commit
      OR
Rollback
```

### Key Protections
- **Cooldown Enforcement**: Enforces minimum dwell times ($c_t$) to prevent high-frequency action chattering.
- **Blast Radius Circuit Breaker**: Restricts the maximum percentage of endpoints that can be throttled or isolated concurrently (e.g., cap of 2%–5%).
- **Critical Infrastructure Exemptions**: Default gateways, DNS resolvers, and core directory servers are permanently protected from automated isolation.
- **Fail-Closed Activation Gate**: Preconditions require cryptographic SHA-256 evidence verification and signed authorization tokens; invalid tokens immediately lock the gate.
- **Cryptographic Snapshots**: Pre-action SHA-256 state hashes are recorded prior to applying any network rule.
- **Watchdog / TTL Monitoring**: Transactions run with active heartbeats; expired time-to-live triggers automatic rollback.
- **Automatic Compensation Rollback**: Failed mutations or verification timeouts trigger deterministic compensation rules restoring pre-action state.
- **Permanent Safety Lock**: If a compensation rollback fails verification, the manager latches into `SAFETY_LOCKED`, halting all further actions until administrative clearance.

---

## 8. Laboratory Isolation

Actual network response actions were evaluated strictly inside an isolated Linux network namespace topology:
- **Topology**: Attacker namespace (`xrlids_att_01`) and victim namespace (`xrlids_vic_01`) connected via virtual Ethernet (`veth`) pairs on subnet `10.200.1.0/24`.
- **Host Protection Guarantee**: The host networking stack is strictly protected. Pre/post cryptographic SHA-256 hashing verifies that host firewall rules, routing tables, and physical interfaces experience **zero mutations**.
- **User-Space Safety**: The safe replay demonstration runs entirely in user-space and performs no system mutations.

---

## 9. Key Results

Authoritative empirical results obtained across the evaluation benchmark suite:

| Experiment / Evaluation Metric | Verified Value | Benchmark Reference |
|:---|---:|:---|
| CIC-IDS2017 Random Forest Test F1 | **0.9512** | Complete 8-file benchmark (`EXP-P1-CIC2017-R10-001`) |
| CIC-IDS2017 Supervised LSTM Test F1 | **0.9633** | $T=5$ sequence model (`EXP-P1-CIC2017-R10-001`) |
| CIC-IDS2017 Score Fusion Test F1 | **0.9745** | Calibrated convex fusion ($\alpha=0.50$) |
| CSE-CIC-IDS2018 Random Forest Test F1 | **0.8861** | Full 10-file benchmark (`EXP-P1-CSE2018-R10-MULTI-001`) |
| CSE-CIC-IDS2018 LSTM / Fusion Test F1 | **0.9603** | Full 10-file benchmark ($\alpha=0.00$) |
| UNSW-NB15 Score Fusion Test F1 | **0.8970** | Full 2-file benchmark under R4 contract ($\alpha=0.60$) |
| DQN Cost Reduction (Balanced Regime) | **+11.29%** | Held-out test evaluation vs Baseline 2 ($p < 0.001$) |
| DQN Cost Reduction (Aggressive Regime) | **+14.10%** | Held-out test evaluation vs Baseline 2 ($p < 0.001$) |
| DQN Practical Criterion ($\ge 15.0\%$) | **NOT MET** | Pre-registered practical effect-size target |
| Live Feature Extraction Parity | **$\text{atol} \le 10^{-4}$** | Strict parity with offline mathematical definitions |
| Controlled Rollback Success Rate | **100.0%** | 100/100 rollback stress transactions (`EXP-P3K-STRESS-SECURITY-001`) |
| Host Network Mutations | **0** | Verified by SHA-256 baseline state comparison |
| Repository Test Suite | **386 passed** | 386 tests passed, 0 failures, 100% pass rate in 40.11s |

---

## 10. Important Scientific Findings

### Positive Findings
- **Complementary Ensembles**: Tabular decision trees and recurrent sequence models exhibit complementary inductive biases; score fusion delivers statistically significant F1 improvements across all datasets.
- **Leakage Elimination**: Policy A feature deduplication and label-conflict rejection completely eliminate the duplicate-row leakage (up to 34.5% duplicate vectors) prevalent in published IDS benchmarks.
- **Complete Response Auditability**: Dual-layer explainability successfully captured 100% of non-ALLOW response decisions with perceptual and policy justifications.
- **Deterministic Safety Containment**: The safety gate prevented 100% of unauthorized critical infrastructure isolations across all stress workloads.
- **Reliable Compensation Rollbacks**: The transaction harness achieved 100% verified state restorations under simulated mutation failures and watchdog timeouts.

### Negative and Scoped Findings
- **Severe Cross-Dataset Degradation**: Detectors evaluated across 6 unadapted cross-dataset transfer directions suffered catastrophic degradation (52% to 95% F1 drop) due to differences in network topologies, MTUs, and flow exporter implementations (RQ5).
- **Stealth Attack Limitations**: Low-rate infiltration and slow brute-force attacks exhibiting low per-flow threat scores can bypass immediate response thresholds.
- **DQN Practical Target Not Met**: While DQN achieved statistically significant cost reductions (+11.29% and +14.10%, $p < 0.001$), it failed to achieve the pre-registered practical significance target ($\ge 15.0\%$).
- **Inference Latency Bottleneck**: Neural detector inference (~47.6 ms/flow) represents the primary pipeline bottleneck, requiring application-level backpressure shedding during line-speed packet bursts.
- **Live Accuracy Unproven Without Ground Truth**: Detection accuracy cannot be claimed on unmanaged live network traffic in the absence of independent ground-truth annotations.
- **Production Deployment Unvalidated**: Network response mechanisms have been validated only in virtualized Linux namespaces, not physical enterprise networks.

---

## 11. Running the Project

### Environment Setup

```bash
# 1. Clone and enter repository
cd fyp-xrlids

# 2. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install pinned dependencies
pip install -r requirements.txt
```

### Verify Installation

```bash
.venv/bin/python -m xrlids.cli info
```

### Run Test Suite

Execute the complete 386-test verification suite:

```bash
.venv/bin/pytest -q
```
*Expected output: `386 passed in ~40s` (0 failures).*

### Run Safe End-to-End Replay Demonstration

Execute the real packet-to-prediction replay demonstration:

```bash
.venv/bin/python scripts/demo/run_replay_demo.py
```

This command executes the real end-to-end data flow:
```text
PCAP
→ flow construction
→ R10 features
→ preprocessing
→ real trained RF inference
→ predictions
→ demo artifacts
```

The demonstration ingests `data/demo/sample_traffic.pcap`, constructs 6 bidirectional flows under the D-006 policy, computes 10 canonical features, loads the actual 26 MB trained Random Forest model from:
```text
results/experiments/EXP-P1-CIC2017-R10-001/random_forest.joblib
```
and evaluates predictions with zero heuristic fallbacks.

### Synthetic Smoke Test

To verify code plumbing on synthetic test fixtures:

```bash
.venv/bin/python -m xrlids.cli smoke --rung R10
```
*(Note: Smoke tests execute on synthetic fixtures and do not evaluate research evidence).*

### Datasets and Model Binaries Note

In accordance with standard repository practices and `.gitignore`, the full raw benchmark datasets (comprising 19,321,418 rows across 20 CSV files, ~8.7 GB) and large intermediate model binaries (`*.pt`, `*.joblib`) are excluded from Git tracking to preserve repository portability. The repository includes:
- A real packet capture trace (`data/demo/sample_traffic.pcap`) and the primary 26 MB demonstrator Random Forest model (`results/experiments/EXP-P1-CIC2017-R10-001/random_forest.joblib`) for immediate out-of-the-box local execution.
- All configuration YAMLs, cryptographic manifests (`data/manifests/dataset_registry.yaml`), dataset schemas, label contracts, and feature extractors.
- For full benchmark retraining, raw CSV files should be placed into `data/raw/{cicids2017,cse_cic_ids2018,unsw_nb15}/` as documented in [`docs/DATASETS.md`](docs/DATASETS.md).

---

## 12. Demo Outputs

Running the replay demonstration produces machine-readable and human-readable audit artifacts in `results/demo/`:
- `results/demo/replay_summary.json`: Detailed execution metadata, flow counts, timing metrics, confusion matrices, and per-flow prediction logs.
- `results/demo/demo_report.md`: Formatted Markdown summary showing per-flow classifications, research baseline ($\tau=0.50$) performance, and proposed operational candidate ($\tau=0.40$) metrics.

---

## 13. Repository Structure

```text
fyp-xrlids/
├── configs/          # Experiment, label, and feature configuration YAMLs
├── data/             # Raw dataset CSVs, manifests, and sample PCAP traces
├── docs/             # Technical architecture, decision log, research reports, and viva guide
├── models/           # Top-level model placeholders (binaries stored in results/)
├── reports/          # Generated human-readable markdown summaries and figures
├── results/          # Trained model binaries, evaluation metrics, and audit cards
├── scripts/          # Runnable demonstration, baseline, and experiment scripts
├── src/              # Python source code package (`xrlids`)
├── tests/            # Unit, integration, and security verification test suite (386 tests)
├── README.md         # Repository documentation and system overview
├── REPRODUCIBILITY.md# Quick reproduction instructions
├── pyproject.toml    # Python package configuration and build metadata
└── requirements.txt  # Pinned dependency specification
```

- **`src/xrlids/`**: Core library containing feature calculation, models, DQN agents, safety gate, transaction manager, and live pipeline.
- **`scripts/`**: Executable scripts for dataset audits, baseline training, replay demonstration, and security stress tests.
- **`results/`**: Authoritative experiment results, trained model binaries (`.joblib`, `.pt`), and audit cards.
- **`docs/`**: Complete research documentation, viva guide, and experiment indexes.

---

## 14. Reproducibility

Authoritative documentation and evidence resources:
- [`docs/DATASETS.md`](docs/DATASETS.md): Authoritative dataset overview, acquisition environments, R10 feature selection rationale, and UNSW R4 fallback explanation.
- [`REPRODUCIBILITY.md`](REPRODUCIBILITY.md): Quickstart reproduction guide.
- [`docs/final/REPRODUCIBILITY_MAP.md`](docs/final/REPRODUCIBILITY_MAP.md): Complete environment configuration, dependency pins, and reproduction commands.
- [`docs/final/FINAL_RESEARCH_REPORT.md`](docs/final/FINAL_RESEARCH_REPORT.md): Comprehensive 10-section final research synthesis.
- [`docs/final/EXPERIMENT_INDEX.md`](docs/final/EXPERIMENT_INDEX.md): Index of all major empirical experiments and artifact locations.
- [`docs/final/DECISION_INDEX.md`](docs/final/DECISION_INDEX.md): Architecture and governance decision log (D-001 through D-006).
- [`docs/final/RELEASE_AUDIT.md`](docs/final/RELEASE_AUDIT.md): Final release audit and governance verification checklist.
- [`docs/viva/FINAL_VIVA_GUIDE.md`](docs/viva/FINAL_VIVA_GUIDE.md): Technical viva defense questions, methodology justifications, and empirical answers.
- [`docs/03_DECISIONS/CLAIMS_REGISTRY.md`](docs/03_DECISIONS/CLAIMS_REGISTRY.md): Registry of 34 verified research claims (CLAIM-001 through CLAIM-034).

---

## 15. Safety and Operational Scope

```text
Validated:
✓ Offline benchmark research across 20 dataset files
✓ PCAP replay and real binary Random Forest inference
✓ Safe dry-run pipeline with zero network mutations
✓ Isolated laboratory response in Linux network namespaces (10.200.1.0/24)
✓ Rollback, watchdog TTL, and cryptographic snapshot verification

Not validated:
✗ Enterprise production deployment
✗ Uncontrolled campus-network enforcement
✗ Universal cross-network generalization without adaptation
✗ Production-grade hardware ASIC / eBPF / XDP inline filtering
```

---

## 16. Limitations

1. **Domain Shift**: Supervised models learn network-specific statistical distributions; unadapted cross-network transfer results in severe F1 degradation (52% to 95%).
2. **Feature Portability**: The canonical R10 feature set requires bidirectional flow statistics that cannot be extracted from netflow-style logs missing TCP flags or packet size variance.
3. **Stealth Attack Blind Spots**: Low-rate stealth attacks produce subtle per-flow statistical changes that evade single-flow and short-sequence detection thresholds.
4. **Single-Seed Final Benchmarks**: Due to computational constraints across 27 million raw records, full multi-file training runs were executed with a single seed (seed=42).
5. **Detector Latency**: Deep neural sequence inference introduces processing latency (~47.6 ms/flow) that requires backpressure packet-shedding during high-throughput bursts.
6. **Lack of Live Ground Truth**: Operational detection accuracy cannot be assessed on live unlabelled network traffic without independent packet-level annotations.
7. **Namespace-Bound Enforcement**: Response transactions have been evaluated strictly within virtualized Linux network namespaces, not physical production network hardware.
8. **Production Deployment Unvalidated**: The system is not certified or approved for live deployment on unmanaged enterprise infrastructure.

---

## 17. Final Status

XRL-IDARS is a completed and audited research system for explainable intrusion detection and controlled autonomous response.

The repository contains the complete implementation, trained research model artifacts, reproducible experiments, machine-readable results, reproducibility guides, deterministic safety mechanisms, laboratory validation, and final research synthesis.

Its validated scope ends at controlled isolated-laboratory operation; production deployment is explicitly outside the validated scope.
