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

## 2. Research Workbench Structure (7 Specialized Pages)

The primary user experience is **Held-Out Dataset Evaluation**, not a synthetic demonstration.

| Tab | Page Name | Primary Research Function | Key Components |
|:---:|:---|:---|:---|
| **Page B** | **Dataset Evaluation (Default)** | Primary evaluation view over held-out benchmark splits | Accuracy/Precision/Recall/F1 tiles, Confusion Matrix, Slice selector (Tabular 355k vs Aligned 355k), Per-class & family metrics. |
| **Page A** | **Overview** | Research status & component verification matrix | Commit hash, environment details, component verification statuses, benchmark inventory. |
| **Page C** | **Model Comparison** | Rigorous head-to-head model comparison | RF vs LSTM vs Fusion table, 95% bootstrap CIs, fusion weights (&alpha;), degenerate flags, shuffled-window temporal ablation. |
| **Page D** | **Flow Explorer** | Verifiable flow record browsing & reproducible export | Paginated flow table, ground truth held in isolated container, prediction vs truth status, CSV export with provenance header. |
| **Page E** | **Explainability** | TreeSHAP feature attributions on Random Forest | Global feature importance rankings, mean \|SHAP\| values, strict notice that SHAP explains RF only (not LSTM or DQN). |
| **Page F** | **Autonomous Response** | Controlled RL vs Cost-Optimal benchmark | 3-action & 4-action comparison, CostOptimal baseline beating DQN in 4/6 regimes, Q-values vs attack probabilities, safety gate invariants. |
| **Page G** | **Research Limitations** | Candid review of 9 verified research findings | Temporal concept drift collapse, RF calibration gap, LSTM spatial pooling vs temporal dynamics, degenerate fusion, production NO-GO. |
| **Live** | **Traffic & Live Modes** | Separated secondary observational monitor | Strictly separates Mode 1 (Offline), Mode 2 (Dataset Stream), Mode 3 (PCAP Replay), Mode 4 (Simulation), Mode 5 (Live Capture). |

---

## 3. Step-by-Step Viva Presentation Script

### Act 1: The Research Problem & Baseline Rigor
- "Examiners, XRL-IDARS addresses two core challenges in network intrusion detection: first, evaluating whether deep sequence models and multi-model fusion actually provide measurable value over tuned tree ensembles under real capture constraints; and second, whether reinforcement learning provides an advantage over cost-sensitive decision rules for autonomous response."
- *Click on `📋 Overview`:* "Here we see our formal component verification matrix. We do not assume all models are perfect or that high random-split numbers mean a model is production-ready. We audit every claim against held-out evidence."

### Act 2: Demonstrating Held-Out Dataset Evaluation (Page B)
- *Click on `📊 Dataset Evaluation` (Default page):*
- "On our primary benchmark, CIC-IDS2017, the Random Forest detector achieves an F1-score of 0.9512 with 98.15% accuracy on 355,865 tabular flows. When evaluated on the sequence-aligned slice of 355,833 flows, the LSTM achieves an F1 of 0.9633, and RF+LSTM fusion reaches 0.9745."
- "Notice the population derivation box: the 32-flow difference between tabular (355,865) and sequence (355,833) is mathematically proven: for sequence length $T=5$, the first 4 boundary flows of each of the 8 capture files cannot form a causal sequence without crossing file boundaries. All 32 dropped flows are benign baseline flows."

### Act 3: Demonstrating Model Comparison, Fusion Weights, and Ablation (Page C)
- *Click on `⚖️ Model Comparison`:*
- "On CIC-IDS2017, fusion weight $\alpha = 0.50$ yields a balanced ensemble. However, look at CSE-CIC-IDS2018:"
- *Select CSE-CIC-IDS2018 in the dropdown:*
- "Our audit revealed a critical finding: on CSE-2018, validation grid search yielded $\alpha = 0.00$. The interface explicitly flags this with an amber warning: $\alpha = 0.00$ makes the fusion model mathematically identical to the standalone LSTM detector. We do not claim an ensemble improvement where none exists."
- "Next, look at our LSTM Shuffled-Window Ablation box: when we randomly permute flow order within each length-5 sequence, the order gain is $\Delta \text{F1} = -0.0038$. This proves empirically that the LSTM acts as a spatial burst-smoothing filter across 5 flows rather than learning temporal sequence causality."

### Act 4: Demonstrating Flow Record Provenance & Ground Truth Isolation (Page D)
- *Click on `🔍 Flow Explorer`:*
- "In our Flow Explorer, examiners can inspect individual held-out flows directly from our frozen predictions. Crucially, notice how Ground Truth is visually and structurally quarantined in its own isolated container. It is never fed into inference."
- "We can filter by False Positives or Missed Attacks, and click 'Export Filtered Flows' to download a cryptographically auditable CSV with complete research metadata headers."

### Act 5: Demonstrating Explainable AI & Scope Boundaries (Page E)
- *Click on `💡 Explainability`:*
- "We use TreeSHAP for explainability on our Random Forest detector. Features like `packet_length_std`, `packet_length_mean`, and `flow_packets_per_s` dominate the attributions."
- "Notice our explicit scientific notice: TreeSHAP explains tree decisions for Random Forest ONLY. It does not explain the LSTM, the Fusion model, or the DQN Q-values, and feature importance is not causal proof."

### Act 6: Autonomous Response — DQN vs Analytic Cost-Optimal Baseline (Page F)
- *Click on `🛡️ Autonomous Response`:*
- "In Phase 2, we evaluated whether Deep Q-Networks justify their complexity for autonomous response. We benchmarked our trained Dueling DQN against a zero-parameter `CostOptimalThresholdPolicy` across six operational regimes."
- *Select High Availability (4-Action):*
- "Look at the result: in High Availability 4-action, the analytic baseline achieves a **20.12% lower cost than the trained DQN** ($1,547,511$ vs $1,937,476$) while executing in **0.40 µs**—a **53x latency advantage** over neural inference."
- "Furthermore, tracing the environment proves traffic arrivals are strictly exogenous replay. Response actions do not alter future packet arrivals. Therefore, non-zero discount factors ($\gamma = 0.95$) lack physical grounding."
- "Our Deterministic Safety Gate remains 100% authoritative over all actions, and autonomous production enforcement is strictly **NO-GO**."

### Act 7: Research Limitations & Candid Viva Defense (Page G)
- *Click on `⚠️ Research Limitations`:*
- "Finally, Page G details our nine audited limitations in plain language. For example, on CSE-CIC-IDS2018, when tested on genuine chronological future days, Random Forest F1 collapses from **0.8861 down to 0.0113**. We present these limitations honestly because rigorous negative results are fundamental to credible computer science research."
