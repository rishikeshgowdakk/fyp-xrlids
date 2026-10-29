# XRL-IDARS — Research Evaluation Workbench Guide & Viva Presentation Script

> **Comprehensive Technical Guide & Presentation Script for Demonstrations, Viva Voce, and Examination**  
> *Target System: XRL-IDARS (Explainable Reinforcement Learning Intrusion Detection and Autonomous Response System)*  
> *Repository: `fyp-xrlids`*  
> *Audit Status: Forensic Readiness Verified (EXP-P2B-READINESS-AUDIT-001)*  

---

## 1. System Architecture & Frontend Overview

The XRL-IDARS console is engineered as a **zero-dependency, high-performance Research Evaluation Workbench**:
- **No Node.js / NPM build pipeline**: Served directly by Python's standard library `ThreadingHTTPServer` (`dashboard/server.py`).
- **Styling (`dashboard/index.html`)**: Built with responsive CSS3 custom design tokens, dark mode aesthetic (`#0b0e14` background, `#151922` cards), monospace metric displays, and accessible visual badges.
- **Client Logic (`dashboard/app.js`)**: Pure vanilla ES6 JavaScript handling asynchronous state polling, tab switching, and dynamic DOM rendering.
- **Backend Communication**: RESTful JSON API endpoints communicating with frozen model inference outputs, research manifests, and flow aggregators.

---

## 2. Research Workbench Structure (2 Modes & 5 Core Research Sections)

The primary user experience is structured as an authoritative **Research Evaluation Workbench**, prioritizing held-out dataset evaluation and scientific transparency over synthetic demonstrations:

| Mode | Section / View | Primary Research Function | Key Components |
|:---:|:---|:---|:---|
| **Research** | **📊 1. Dataset Explorer (Default)** | Primary evaluation view over held-out benchmark splits | Accuracy/Precision/Recall/F1 tiles, Confusion Matrix, Slice selector (Tabular 355k vs Aligned 355k), Per-class & family metrics, Multi-Model Engine (Mode B 200 demo), Custom CSV upload. |
| **Research** | **⚖️ 2. Model Comparison** | Rigorous head-to-head model comparison | RF vs LSTM vs Fusion table, 95% bootstrap CIs, fusion weights (&alpha;), degenerate flags (&alpha;=0.00 on CSE-2018), shuffled-window temporal ablation (&Delta;F1=-0.0038). |
| **Research** | **⏱️ 3. Performance Benchmarks** | Dual-scope latency & resource reconciliation | Microbenchmark (~3.53 ms RF) vs Burst Queue (~35.42 ms P50); Quiescent RAM (123.2 MB) vs Peak Flood Stress RSS (1,049.45 MiB); 10 canonical artifacts dynamically loaded. |
| **Research** | **💡 4. Explainability & Attacks** | TreeSHAP feature attributions on Random Forest | Global feature importance rankings, mean \|SHAP\| values, Critical Attack Blind Spots (Infiltration, SQLi, XSS), strict notice that SHAP explains RF only (not LSTM or DQN). |
| **Research** | **🛡️ 5. Autonomous Response** | Controlled RL vs Cost-Optimal benchmark | 3-action & 4-action comparison, CostOptimal baseline beating DQN by up to 20.12%, 1.95 µs vs 100.23 µs policy latency, safety gate invariants, atomic rollback evidence. |
| **Research** | **📋 Platform Overview** | Research status & component verification matrix | Commit hash, environment details, component verification statuses, benchmark inventory. |
| **Research** | **🔍 Flow Explorer** | Verifiable flow record browsing & reproducible export | Paginated flow table, ground truth held in isolated container, prediction vs truth status, CSV export with provenance header. |
| **Research** | **⚠️ Research Limitations** | Candid review of 9 verified research findings | Temporal concept drift collapse (0.8861 -> 0.0113), RF calibration gap, LSTM spatial pooling, degenerate fusion, production NO-GO. |
| **Live** | **⚡ Live Exhibition Demo** | Separated secondary observational monitor | Strictly separates Mode 1 (Offline), Mode 2 (Dataset Stream), Mode 3 (PCAP Replay), Mode 4 (Simulation), Mode 5 (Live Capture), Detected Sources, WiFi devices. |

---

## 3. Step-by-Step Viva Presentation Script

### Act 1: The Research Problem & Baseline Rigor
- "Examiners, XRL-IDARS addresses two core challenges in network intrusion detection: first, evaluating whether deep sequence models and multi-model fusion actually provide measurable value over tuned tree ensembles under real capture constraints; and second, whether reinforcement learning provides an advantage over cost-sensitive decision rules for autonomous response."
- *Click on `📋 Overview`:* "Here we see our formal component verification matrix. We do not assume all models are perfect or that high random-split numbers mean a model is production-ready. We audit every claim against held-out evidence."

### Act 2: Demonstrating Held-Out Dataset Evaluation (Section 1: Dataset Explorer)
- *Click on `📊 1. Dataset Explorer` (Default landing view):*
- "On our primary benchmark, CIC-IDS2017, the Random Forest detector achieves an F1-score of 0.9512 with 98.15% accuracy on 355,865 tabular flows. When evaluated on the sequence-aligned slice of 355,833 flows, the LSTM achieves an F1 of 0.9633, and RF+LSTM fusion reaches 0.9745."
- "Notice the population derivation note: the 32-flow difference between tabular (355,865) and sequence (355,833) is mathematically proven: for sequence length $T=5$, the first 4 boundary flows of each of the 8 capture files cannot form a causal sequence without crossing file boundaries ($8 \times 4 = 32$ dropped benign flows)."

### Act 3: Demonstrating Model Comparison, Fusion Weights, and Ablation (Section 2: Model Comparison)
- *Click on `⚖️ 2. Model Comparison`:*
- "On CIC-IDS2017, fusion weight $\alpha = 0.50$ yields a balanced ensemble. However, look at CSE-CIC-IDS2018:"
- *Select CSE-CIC-IDS2018 in the dropdown:*
- "Our audit revealed a critical finding: on CSE-2018, validation grid search yielded $\alpha = 0.00$. The interface explicitly flags this with an amber warning: $\alpha = 0.00$ makes the fusion model mathematically identical to the standalone LSTM detector. We do not claim an ensemble improvement where none exists."
- "Next, look at our LSTM Shuffled-Window Ablation box: when we randomly permute flow order within each length-5 sequence, the order gain is $\Delta \text{F1} = -0.0038$. This proves empirically that the LSTM acts as a spatial burst-smoothing filter across 5 flows rather than learning temporal sequence causality."

### Act 4: Performance Benchmarks & Measurement Scope Reconciliation (Section 3: Performance Benchmarks)
- *Click on `⏱️ 3. Performance Benchmarks`:*
- "Examiners, a major defect in published network intrusion detection research is conflating different measurement scopes. Here, every figure is dynamically loaded from 10 canonical result artifacts on disk."
- "Look at our explicit Scope Reconciliation panels:
  - *Latency Scopes*: Pure 100-tree RF traversal on a pre-extracted vector is **3,525.08 µs (~3.53 ms)** single-thread (53.87 µs/flow in vectorized batches of 100). The analytic Cost-Optimal policy evaluates in **1.95 µs**, which is **~51.4x faster** than neural DQN forward passes (100.23 µs). In contrast, under a real 1,000-packet burst stream (`EXP-P3-BURST-1000-001`), end-to-end packet capture (0.50 µs), flow assembly (12.89 µs), feature extraction (763.72 µs), dual-model sequence queuing with thread contention (**~35.42 ms P50**), and safety verification yield an end-to-end flow latency of **37.51 ms P50**.
  - *Memory Scopes*: Quiescent model weight RAM is **123.2 MB** (RF 117.4M, LSTM 1.2M, DQN 0.4M, hash table 4.2M). Under intense socket stress (`EXP-P3K-STRESS-SECURITY-001`), transient flood buffers cause peak RSS to reach **1,049.45 MiB (~1.05 GiB)**, safely dropping back to **175.74 MiB** post-soak with only **12.05 MiB (7.36%)** net permanent growth over 10,000 soak flows."
- "Notice the Canonical Artifacts Registry table: 10 verified JSON files dynamically loaded, parsed, and validated directly from disk."

### Act 5: Demonstrating Explainable AI & Critical Attack Blind Spots (Section 4: Explainability & Attacks)
- *Click on `💡 4. Explainability & Attacks`:*
- "We use TreeSHAP for explainability on our Random Forest detector. Features like `packet_length_std`, `packet_length_mean`, and `flow_packets_per_s` dominate the attributions."
- "However, look at our Critical Attack Blind Spots panel: low-footprint application attacks suffer catastrophic detection failure (Infiltration recall 0.00%, SQL Injection recall 0.00%, XSS recall 2.78%). Attack payloads reside inside HTTP URIs or single packets, leaving statistical flow features completely indistinguishable from normal web surfing."
- "Notice our explicit scientific notice: TreeSHAP explains tree decisions for Random Forest ONLY. It does not explain the LSTM, the Fusion model, or the DQN Q-values, and feature importance is not causal proof."

### Act 6: Autonomous Response — DQN vs Analytic Cost-Optimal Baseline (Section 5: Autonomous Response)
- *Click on `🛡️ 5. Autonomous Response`:*
- "In Phase 2, we evaluated whether Deep Q-Networks justify their complexity for autonomous response. We benchmarked our trained Dueling DQN against a zero-parameter `CostOptimalThresholdPolicy` across six operational regimes on held-out 355k test flows."
- *Select High Availability (4-Action):*
- "Look at the result: in High Availability 4-action, the analytic baseline achieves a **20.12% lower cost than the trained DQN** ($1,547,511$ vs $1,937,476$) while executing in **1.95 µs**—a **~51x latency advantage** over neural inference (1.95 µs vs 100.23 µs policy-only)."
- "Furthermore, tracing the environment proves traffic arrivals are strictly exogenous replay. Response actions do not alter future packet arrivals. Therefore, non-zero discount factors ($\gamma = 0.95$) lack physical grounding."
- "Our Deterministic Safety Gate remains 100% authoritative over all actions, and autonomous production enforcement is strictly **NO-GO**."

### Act 7: Demonstrating Flow Record Provenance & Ground Truth Isolation (Flow Explorer)
- *Click on `🔍 Flow Explorer`:*
- "In our Flow Explorer, examiners can inspect individual held-out flows directly from our frozen predictions. Crucially, notice how Ground Truth is visually and structurally quarantined in its own isolated container. It is never fed into inference."
- "We can filter by False Positives or Missed Attacks, and click 'Export Filtered Flows' to download a cryptographically auditable CSV with complete research metadata headers."

### Act 8: Research Limitations & Candid Viva Defense (Research Limitations)
- *Click on `⚠️ Research Limitations`:*
- "Finally, our Limitations view details our nine audited limitations in plain language. For example, on CSE-CIC-IDS2018, when tested on genuine chronological future days, Random Forest F1 collapses from **0.8861 down to 0.0113**. We present these limitations honestly because rigorous negative results are fundamental to credible computer science research."

### Act 9: Demonstrating the Multi-Model Inference Engine & Exhibition Sample
- *Return to `📊 1. Dataset Explorer` and scroll to the Multi-Model Inference Engine card:*
- "Examiners, we also provide an interactive Multi-Model Verification Engine supporting three distinct modes:
  1. **Mode B (200 Exhibition Demo):** Evaluates a deterministic, held-out sample of 200 real network flows (166 Benign, 34 Attack) across any of our three benchmark datasets (CIC-IDS2017, CSE-CIC-IDS2018, or UNSW-NB15). Displays side-by-side metric cards and 3 confusion matrices for Random Forest, Supervised LSTM ($T=5$, causal sequences), and Score Fusion.
  2. **Mode A (Full Held-Out Test):** Allows instant verification of our complete authoritative held-out splits (355k CIC-IDS2017, 1.66M CSE-2018, or 24.5k UNSW-NB15 flows).
  3. **Mode C (Custom CSV Upload):** Allows uploading external CSV flow records matching the R10 or R4 contract, with strict non-finite row accounting."
- *Click `🔍 Inspect` on an attack flow:*
  - "Notice our drill-down modal: examiners can inspect on-demand TreeSHAP feature attributions explaining why the Random Forest classified this flow as an attack, alongside the Dueling DQN's simulated action recommendation."


---

## 4. Live Wi-Fi Demonstration vs Offline Benchmark Evaluation

> [!WARNING]
> **Scientific Separation Invariant — Live Wi-Fi Demonstration**:
> The live Wi-Fi demonstration uses the same verified model pipeline (`random_forest_cicids2017.joblib` and `lstm_cicids2017.pt`) **only because the live Scapy/AF_PACKET feature extractor outputs a compatible R10 feature vector**.
> 
> **Critical Scientific Disclaimers for Examiners**:
> 1. **Zero Production Mutation:** Live network capture is strictly observational. No packets are dropped, no live firewall rules are mutated, and no host network connections are disrupted.
> 2. **No Claim of Live Benchmark Equivalence:** Benchmark test results (e.g., 99.06% accuracy on CIC-IDS2017) are offline, held-out upper bounds. They **do not prove or imply equivalent detection performance on live unlabelled Wi-Fi traffic**, due to environmental concept drift, consumer application diversity, and missing ground truth.
> 3. **Isolation Invariant:** CSV evaluations and live monitoring operate on strictly decoupled execution paths; CSV evaluations never feed back into live detection.

