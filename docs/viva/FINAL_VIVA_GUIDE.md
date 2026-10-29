# XRL-IDARS v1 — COMPREHENSIVE VIVA & DEFENSE GUIDE

> **Target Audience:** Academic Examiners, Viva Defense Committees, and Technical Reviewers.  
> **Repository:** `rishikeshgowdakk/fyp-xrlids`  
> **Status:** AUDITED, COMPLETED & FROZEN

---

## 1. Problem & Motivation

### Q: Why do we need ML-based Intrusion Detection Systems (IDS)?
**A:** Traditional signature-based IDSs (e.g., Snort) rely on matching known attack strings. They fail against zero-day exploits, polymorphism, and behavioral anomalies. Flow-level machine learning models learn statistical and transport dynamics (e.g., packet size distributions, flow inter-arrival rates), enabling detection of novel attack variants that lack pre-existing byte-level signatures.

### Q: Why autonomous response? Why not keep a human analyst in the loop?
**A:** Modern volumetric and automated cyber-attacks (e.g., high-rate DDoS, automated brute force, credential stuffing) propagate and cause damage within milliseconds to seconds. Human triage times in enterprise SOCs average minutes to hours. Autonomous response is necessary to mitigate active attacks at line speed. However, unconstrained automated response risks self-inflicted Denial of Service (DoS) if false positives isolate critical infrastructure, which is why XRL-IDARS pairs RL with a deterministic safety gate and atomic rollback transactions.

---

## 2. Benchmark Datasets & Feature Contracts

### Q: Why choose CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15?
**A:** These represent the most widely cited benchmark datasets in IDS literature:
- **CIC-IDS2017 & CSE-CIC-IDS2018:** Created by the Canadian Institute for Cybersecurity, containing multi-day realistic traffic profiles, diverse attack families (DDoS, PortScan, Brute Force, Web Attacks, Infiltration), and generated using CICFlowMeter.
- **UNSW-NB15:** Created by the Australian Centre for Cyber Security, featuring modern synthetic low-footprint attack traffic extracted via Argus and Bro/Zeek.

### Q: Why did you create the R10 feature contract?
**A:** The raw CICFlowMeter CSVs contain 78 to 83 features, many of which suffer from data leakage (e.g., IP addresses, socket ports, absolute flow timestamps) or extreme collinearity. R10 freezes 10 portable, statistical, and transport features (`flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean`, `packet_length_std`, `syn_count`, `ack_count`, `rst_count`, `fin_count`, `syn_ack_ratio`) that capture flow dynamics without leaking environment-specific network topology.

### Q: Why does UNSW-NB15 use a 4-feature contract (R4) instead of R10?
**A:** UNSW-NB15 was generated using Argus and Bro/Zeek, not CICFlowMeter. It physically lacks 6 of the 10 R10 features (e.g., standard deviation of packet lengths and specific TCP flag counts are omitted from Argus logs). Fabricating or imputing these features would violate scientific integrity. Under Decision D-002, UNSW-NB15 was quarantined as an auxiliary 4-feature benchmark (R4) rather than contaminating the main R10 evaluation with synthesized data.

---

## 3. Modeling & Detection Architecture

### Q: Why Random Forest?
**A:** Random Forest is an ensemble of axis-aligned decision trees. It handles non-linear tabular feature interactions, is invariant to monotonic feature scaling, provides built-in feature importance rankings, and exhibits low inference latency (~0.1 ms/flow) compared to deep neural networks.

### Q: Why Supervised LSTM?
**A:** Network intrusions often occur as temporal multi-flow campaigns (e.g., sequential port scans, progressive brute-force authentication, multi-stage infiltration). A sequence model ($T=5$ consecutive flows) captures inter-flow temporal dependencies that independent tabular classifiers miss, reducing false alarms by up to 66% on structured traffic.

### Q: Why Score Fusion?
**A:** Tabular trees and recurrent neural networks make complementary errors. A validation-tuned convex score fusion ($S_{\text{fusion}} = \alpha \cdot S_{\text{RF}} + (1 - \alpha) \cdot S_{\text{LSTM}}$; the blended score is not a calibrated probability) leverages the high precision of the RF with the temporal context of the LSTM, achieving statistically significant F1 improvements across all evaluated benchmarks (e.g., CIC-IDS2017 F1 = 0.9745 vs RF 0.9512).

---

## 4. Experimental Rigor & Leakage Prevention

### Q: How did you prevent data leakage in your evaluation?
**A:** We discovered that up to 34.5% of raw flows in IDS datasets share identical feature vectors. Standard random train/test splitting leaks identical vectors across splits (`L-01` leakage). We enforced **Policy A Feature Deduplication with Conflict Rejection**: all duplicate vectors and label-conflicting rows were removed prior to splitting, guaranteeing zero shared vectors between train, validation, and test sets. For the CSE-CIC-IDS2018 benchmark we additionally executed a strict future-period temporal holdout (`EXP-P1-CSE2018-TEMPORAL-R10-001`), so the headline random-split numbers are not the only evidence.

### Q: How uncertain are the reported detector metrics?
**A:** We report two separate sources of uncertainty. First, a 3-seed sweep (42/123/456) gives training-seed mean ± std (`reports/generated/multi_seed_report.md`). Second, per-seed 95% bootstrap intervals are computed from the saved held-out predictions (B=1000; threshold metrics on the full test set, ROC-AUC on a fixed 100k stratified sample) in `reports/generated/bootstrap_ci_report.md`. For example, CSE seed-42 RF F1 is 0.8861 [0.8851, 0.8872], and CIC fusion F1 is 0.9745 [0.9737, 0.9754]. The bootstrap intervals quantify test-set sampling uncertainty, not seed variance; neither replaces the temporal holdout.

### Q: What did the future-day temporal holdout show?
**A:** It shows a severe generalization failure. `EXP-P1-CSE2018-TEMPORAL-R10-001` trains on 14–20 Feb 2018, validates on 20–22 Feb, and tests on 22 Feb–2 Mar, using the real CSE `Timestamp`; L-01/L-02/L-05 pass. The frozen RF gets F1 **0.0113** (recall 0.0068, ROC-AUC 0.3905) on the future test, versus 0.8861 on the random split. Bot recall falls from 99.17% to 0.09%, infiltration from 10.70% to 0.94%, and web/XSS/SQL to 0%. The temporal test contains 50,306 attacks (3.08%) after Policy A dedup; these are the unique, conflict-free future flows, not the raw prevalence.

### Q: Does that invalidate your 99% accuracy claim?
**A:** It invalidates using 99% as a future-day performance claim. The 99% figures are **in-domain random-split upper bounds**: the test rows come from the same capture days as training, and near-duplicate structure inflates them. The defensible claim is: the detector separates deduplicated same-day flows well, but it does not generalize to later unseen attack families. We report both results, and the dashboard displays a temporal-holdout caveat next to the model-comparison table. We do **not** claim production or future-day readiness.

### Q: Why did cross-dataset transfer fail so severely (52% to 95% F1 drop)?
**A:** Unadapted transfer exposes severe covariate shift and concept drift. Different networks have different background traffic distributions, bandwidths, MTU sizes, and flow timeout configurations. Supervised models learn sharp decision boundaries tailored to the training network; without target domain adaptation, their probabilistic calibration collapses.

### Q: What is the meaning of your H0 / H1 hypothesis test result?
**A:** On 355,865 held-out test flows:
- **Null Hypothesis ($H_0$):** The DQN autonomous response policy produces equal or higher operational cost compared to the best deterministic baseline.
- **Alternative Hypothesis ($H_1$):** The DQN policy produces lower operational cost.
- **Statistical Result:** $H_0$ was rejected ($p < 0.001$, paired bootstrap) in Balanced and Aggressive regimes, supporting $H_1$ (cost was reduced by 11.29% and 14.10%).
- **Practical Criterion:** However, our pre-registered practical significance criterion ($\ge 15.0\%$ cost reduction) was **NOT MET**. We report both results transparently.

---

## 5. Reinforcement Learning & Autonomous Response

### Q: Why use a 6D causal state representation?
**A:** The RL state vector $\langle S_{\text{det}}, C_{\text{family}}, P_{\text{conf}}, R_{\text{flow}}, H_{\text{crit}}, A_{\text{current}} \rangle$ provides the minimal sufficient statistic for response decision-making:
- Detector probability and confidence indicate threat likelihood.
- Attack family dictates remediation strategy (e.g., DoS requires rate limiting; brute force requires host isolation).
- Flow rate captures volumetric intensity.
- Critical host flag and active action state prevent disruption loops and protect infrastructure.

### Q: Why Dueling DQN?
**A:** Dueling DQN decomposes the state-action value $Q(s, a)$ into a state value $V(s)$ and action advantage $A(s, a)$. In autonomous response, many states are clearly benign regardless of action; the dueling architecture learns the value of being in a safe state without needing to learn the value of every disruptive action in that state, speeding convergence and improving policy stability.

### Q: Why is a Deterministic Safety Gate necessary if you have an RL policy?
**A:** RL policies are stochastic function approximators that can fail under out-of-distribution inputs, adversarial perturbations, or exploratory actions. A deterministic safety gate provides an algorithmic safety envelope that cannot be bypassed: it deterministically overrides any action that violates physical operational invariants (cooldowns, blast radius limits, critical host exemptions).

---

## 6. Explainability

### Q: Why use TreeSHAP?
**A:** TreeSHAP computes exact Shapley values in polynomial time for tree ensembles, satisfying mathematical axioms of efficiency, symmetry, dummy, and additivity. It explains *why* the detector flagged a flow by attributing positive or negative contributions to specific traffic features.

### Q: How are autonomous decisions explained to security analysts?
**A:** Via **Dual-Layer Decision Audit Cards**. Every non-ALLOW action generates a structured JSON and markdown card containing:
1. Perceptual attribution (TreeSHAP feature contributions).
2. Policy attribution (DQN Q-value decomposition across candidate actions).
3. Safety compliance (whether the action passed the safety gate or was overridden, with exact reason codes).

---

## 7. Live Validation & Network Engineering

### Q: How does your packet capture and flow builder work?
**A:** The engine uses pure-Python raw sockets (`AF_PACKET`) and Scapy to ingest Ethernet frames. Flows are tracked bidirectionally by 5-tuple (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`). Under Decision D-006, TCP flows close immediately upon observing `FIN` or `RST` flags, while connectionless/inactive flows expire after a 120.0-second idle timeout.

### Q: What is live feature parity, and why does it matter?
**A:** Live feature parity verifies that features computed from raw streaming packets match the mathematical definitions in the offline training datasets. If feature calculations drift, trained models receive garbage inputs. We proved that our streaming engine matches offline feature definitions within $\text{atol} \le 10^{-4}$.

### Q: Can the dashboard list every device connected to the WiFi, like the router login?
**A:** No, and it does not claim to. The router is the access point and knows every associated station; the dashboard runs on a WiFi **client**, so it only receives frames addressed to this laptop plus broadcast/multicast traffic. The **Devices Observed on WiFi** panel therefore combines passive ARP, DHCP, mDNS, SSDP, and the local neighbour cache, labels `SEEN` vs `CACHED`, and states the limitation in the UI. It sends no ARP scans, pings, or probes. Idle, IPv6-only, or AP-isolated clients may be absent; the router's admin page/API or an AP-side collector is authoritative. This endpoint view is the honest scope of what an observational client can see.

### Q: What is the difference between Dry-Run and Controlled Enforcement?
**A:** 
- **Dry-Run Mode (Phases 3A–3F):** Ingests real packets, builds flows, runs detection, evaluates RL, logs audit cards, but executes **zero physical network changes**.
- **Controlled Enforcement (Phases 3G–3K):** Executes real iptables/tc mutations, but **strictly inside isolated Linux network namespaces** (`10.200.1.0/24`) behind atomic rollback harnesses.

---

## 8. Safety, Rollback & Containment

### Q: Did your experiments ever modify the host's actual network?
**A:** **NO. Exactly ZERO host network mutations occurred.** We captured cryptographic SHA-256 baselines of host routing tables, iptables, interfaces, and sockets before and after every test. In every run, `pre_hash == post_hash` was verified.

### Q: What happens if an automated mitigation fails or crashes mid-way?
**A:** Every transaction executes within [`ControlledResponseTransactionManager`](../../src/xrlids/response/transaction.py):
1. Pre-action state is captured in a SHA-256 snapshot.
2. If the mutation fails, times out, or fails post-action verification, an **automatic compensation rollback** is triggered immediately to restore baseline state.
3. If rollback itself fails, the system latches into a permanent `SAFETY_LOCKED` state, disabling all further autonomous mutations until manual administrative intervention.

---

## 9. Limitations & Future Work

### Q: What are the main limitations of XRL-IDARS v1?
**A:**
1. **Practical Cost Criterion Not Met:** Achieved 11.29% and 14.10% cost reduction, falling short of the pre-registered 15.0% practical target.
2. **CPU Inference Bottleneck:** Neural and RF scoring (median 47.6 ms/flow) limits throughput on general-purpose CPUs without FPGA/GPU acceleration.
3. **Namespace Isolation vs Production:** Enforcement was validated in Linux network namespaces, not on 100 Gbps enterprise switching fabrics (which require eBPF/XDP).
4. **Single-Node Architecture:** Concurrency is managed via local locks; multi-node enterprise deployments require distributed consensus.

### Q: What is required before this system can be deployed in production?
**A:** Production deployment requires:
- Kernel-bypass packet filtering (eBPF / XDP) instead of netns iptables.
- Hardware-assisted inference (TPU / FPGA) to achieve sub-millisecond line-rate classification.
- Continuous online domain adaptation to counter covariate shift.
- Distributed consensus (e.g., Raft) for multi-chassis coordination.
