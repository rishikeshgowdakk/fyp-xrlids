# XRL-IDARS — Open Day 2026 Demonstration Video Script

**Project Title:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Institution:** JSS Mahavidyapeetha, JSS Academy of Technical Education, Bengaluru  
**Department:** Department of Computer Science & Engineering  
**Event:** Open Day 2026 — Final Year Project Exhibition (Saturday, 31 October 2026)  
**Group Number:** Group 43 | **Lab Allotment:** Lab A 204  
**Project Guide:** Dr. P. B. Mallikarjuna, Professor, Department of Computer Science & Engineering  
**Student Team:**  
- Rishikesh Gowda K K (`1JS22CS136`)  
- Sharanya M (`1JS22CS153`)  
- Sudarshan (`1JS22CS173`)  
- Suraj Rao G (`1JS22CS174`)  

**Video Specifications:**
- **Total Duration:** 87.77 seconds (strictly within the 75–90 second window)
- **Resolution:** 1920 × 1080 (Full HD, 16:9 widescreen)
- **Frame Rate:** 30 FPS progressive
- **Video Codec:** H.264 (High Profile, yuv420p, CRF 18)
- **Audio Codec:** AAC stereo (169 kbps, 44.1 kHz)
- **Voiceover Artist:** `en-IN-PrabhatNeural` (Professional Indian-English Male Voice)
- **Audio Mixing:** Voiceover at 0 dB, Ambient Electronic Cyber Synth Pad at -22 dB with subtle speech ducking
- **Subtitles:** Synchronized burned captions with semi-transparent dark backing

---

## Storyboard & Scene-by-Scene Timings

### Scene 1 — Institutional Introduction & Team Title
- **Visual Window:** `00:00:00.000` &rarr; `00:00:10.500` (Duration: 10.50s)
- **Voiceover Window:** `00:00:00.500` &rarr; `00:00:08.680` (Duration: 8.18s)
- **Visual Description:**  
  Full-screen cinematic dark cyan/slate title card with high-tech grid overlay. Displays JSS Academy of Technical Education, Bengaluru; Department of Computer Science & Engineering; Open Day 2026 Exhibition; Group 43; Lab A 204; Project Guide Dr. P. B. Mallikarjuna; and student team members Rishikesh Gowda K K, Sharanya M, Sudarshan, and Suraj Rao G.
- **Narration (Verbatim):**  
  > *"Every second, computer networks face cyber threats that can compromise sensitive information and disrupt critical services. Introducing XRL-IDARS, an explainable AI-powered intrusion detection and response system developed at JSS Academy of Technical Education, Bengaluru."*

---

### Scene 2 — Problem Statement & Dual Defense Paradigm
- **Visual Window:** `00:00:10.500` &rarr; `00:00:20.000` (Duration: 9.50s)
- **Voiceover Window:** `00:00:10.900` &rarr; `00:00:18.310` (Duration: 7.41s)
- **Visual Description:**  
  Live screen recording of the running Streamlit SOC Command Center (`Overview` page at `http://localhost:8501`). Highlights the Executive Summary and the 4 Core Metrics Cards: Operational Classifier (Random Forest, $F_1 = 0.9512$, Latency $< 0.80\text{ ms}$), Explainability (TreeSHAP, $< 2.50\text{ ms}$), Autonomous Policy (Dueling DQN, 4 Actions), and Execution Guardrail (Advisory / Dry-Run, Zero kernel mutations).
- **Narration (Verbatim):**  
  > *"Traditional intrusion detection systems can struggle to explain their decisions and respond intelligently. XRL-IDARS combines machine learning, explainable AI, deterministic security rules and reinforcement-learning-based response recommendations."*

---

### Scene 3 — Operational Architecture & Pipeline Workflow
- **Visual Window:** `00:00:20.000` &rarr; `00:00:35.500` (Duration: 15.50s)
- **Voiceover Window:** `00:00:20.500` &rarr; `00:00:32.340` (Duration: 11.84s)
- **Visual Description:**  
  Smooth camera tracking on the live animated SVG Operational Pipeline. Real-time pulsating glowing flows trace packet ingestion from Wire / PCAP &rarr; Canonical FlowEngine ($R_{10}$ statistical moments) &rarr; Train-fitted StandardScaler &rarr; Random Forest Perception & RFC Rule Engine &rarr; TreeSHAP Attribution &rarr; Causal 6D StateBuilder &rarr; Dueling DQN Policy &rarr; Deterministic Safety Gate &rarr; Advisory Actuator &rarr; Decoupled Asynchronous PostgreSQL Persistence. Also displays the verified Subsystem Latency Table ($3.04\text{ ms}$ total budget).
- **Narration (Verbatim):**  
  > *"Network traffic is converted into flows and processed using the matching feature pipeline. A trained Random Forest identifies suspicious activity, while independent security rules detect additional threats. TreeSHAP explains the model's prediction, and a Dueling Deep Q-Network recommends a response. A deterministic safety gate checks every recommendation before it can proceed."*

---

### Scene 4 — Live Demonstration (Benign, Attack, SHAP & DQN Tabs)
- **Visual Window:** `00:00:35.500` &rarr; `00:00:57.770` (Duration: 22.27s)
- **Voiceover Window:** `00:00:36.000` &rarr; `00:00:52.150` (Duration: 16.15s)
- **Visual Description:**  
  Live screen recording of the `Live Demo` page.  
  1. *Normal Traffic:* Clicks "Benign Ping (ICMP)", triggering real-time flow evaluation with low attack score ($S_t = 0.1438$), `BENIGN` classification, and `ALLOW` response.  
  2. *Suspicious Attack:* Clicks "SYN Burst (TCP Port 80)", immediately flagging a severe anomaly ($S_t = 0.8500$), `HIGH` severity, and recommending `ISOLATE`.  
  3. *Deep-Dive Tabs:* Cycles smoothly through all 4 tabs:  
     - **Tab 1 (Perception & Rules):** Shows Random Forest multi-class probabilities (DDoS: 98%) and $< 0.1\text{ ms}$ inference.  
     - **Tab 2 (TreeSHAP Attribution):** Shows exact local Shapley waterfall rankings (`flow_packets_per_s`, `syn_ack_ratio` in red).  
     - **Tab 3 (Dueling DQN Response):** Shows Q-values across `ALLOW`, `ALERT`, `RATE_LIMIT`, `ISOLATE`, and the 6D Markov state vector.  
     - **Tab 4 (Safety & Verification):** Confirms deterministic allowlist validation, cooldown enforcement, and advisory dry-run execution report.
- **Narration (Verbatim):**  
  > *"Here is the live demonstration. First, normal traffic is processed. Next, we introduce suspicious traffic. The system evaluates the flow, identifies the threat, and displays the prediction with its feature-level explanation. The DQN then recommends an appropriate response, while the safety gate prevents unsafe actions. Every event can be inspected through the dashboard."*

---

### Scene 5 — Research Benchmarks & Multi-Model Evaluation
- **Visual Window:** `00:00:57.770` &rarr; `00:00:70.770` (Duration: 13.00s)
- **Voiceover Window:** `00:00:58.200` &rarr; `00:01:08.100` (Duration: 9.90s)
- **Visual Description:**  
  Live screen recording of the `Benchmarks` page. Displays the 10,000-record authoritative benchmark dataset ($5,000\text{ Benign} / 5,000\text{ Attack}$) with target leakage prevention badge. Highlights the Multi-Model Comparison Table identifying Random Forest as the Operational Champion (85.42% accuracy, 0.8334 Macro $F_1$, 0.9834 ROC-AUC, 0.07 ms latency) compared to the PyTorch LSTM Baseline (77.77% accuracy, 0.44 ms latency) and RF-LSTM Fusion (84.82% accuracy). Scrolls to display the 7x7 interactive confusion matrix and ROC-AUC curve.
- **Narration (Verbatim):**  
  > *"XRL-IDARS also includes a reproducible evaluation workbench. We compare Random Forest, LSTM and fusion models using a ten-thousand-record evaluation dataset. The results help us assess detection performance, explainability and computational efficiency."*

---

### Scene 6 — Real-World Operational Applications & Impact
- **Visual Window:** `00:00:70.770` &rarr; `00:00:81.770` (Duration: 11.00s)
- **Voiceover Window:** `00:01:11.200` &rarr; `00:01:19.860` (Duration: 8.66s)
- **Visual Description:**  
  Full-screen cyber grid graphic detailing 6 potential enterprise deployment domains:  
  1. **Enterprise Networks:** Perimeter line-rate flow inspection.  
  2. **Banking & Financial Systems:** High-frequency transaction monitoring with explainable compliance.  
  3. **Healthcare Infrastructure:** Medical IoT device protection with inviolable guardrails.  
  4. **Educational Institutions:** Campus network perimeter security and multi-tenant isolation.  
  5. **Cloud & Data Centers:** Scalable micro-segmentation advisory recommendations.  
  6. **Security Operations Centers (SOC):** Explainable decision support under human-in-the-loop oversight.
- **Narration (Verbatim):**  
  > *"This technology can support enterprise networks, banking systems, healthcare infrastructure, educational institutions and cloud environments. By combining explainable detection with safety-controlled response recommendations, XRL-IDARS aims to help security teams understand threats and make more informed decisions."*

---

### Scene 7 — Closing & Project Accreditation
- **Visual Window:** `00:00:81.770` &rarr; `00:00:87.770` (Duration: 6.00s)
- **Voiceover Window:** `00:01:22.200` &rarr; `00:01:25.800` (Duration: 3.60s)
- **Visual Description:**  
  Elegant closing title screen with glowing XRL-IDARS logo, JSS Academy of Technical Education, Bengaluru; Department of Computer Science & Engineering; Project Guide Dr. P. B. Mallikarjuna; Student Team (Group 43); and institutional motto: *"Code • Create • Innovate."*
- **Narration (Verbatim):**  
  > *"XRL-IDARS: making network security more intelligent, explainable and responsible. Thank you."*

---

## Technical Synchronization Summary

| Scene | Name | Visual Start | Visual End | Visual Dur | VO Start | VO End | VO Dur | Lead In | Tail Margin |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1** | Introduction | 00:00.00 | 00:10.50 | 10.50s | 00:00.50 | 00:08.68 | 8.18s | +0.50s | 1.82s |
| **2** | Problem & Solution | 00:10.50 | 00:20.00 | 9.50s | 00:10.90 | 00:18.31 | 7.41s | +0.40s | 1.69s |
| **3** | Architecture & Workflow | 00:20.00 | 00:35.50 | 15.50s | 00:20.50 | 00:32.34 | 11.84s | +0.50s | 3.16s |
| **4** | Live Demonstration | 00:35.50 | 00:57.77 | 22.27s | 00:36.00 | 00:52.15 | 16.15s | +0.50s | 5.62s |
| **5** | Benchmarks & Evaluation | 00:57.77 | 01:10.77 | 13.00s | 00:58.20 | 01:08.10 | 9.90s | +0.43s | 2.67s |
| **6** | Real-World Impact | 01:10.77 | 01:21.77 | 11.00s | 01:11.20 | 01:19.86 | 8.66s | +0.43s | 1.91s |
| **7** | Closing Accreditation | 01:21.77 | 01:27.77 | 6.00s | 01:22.20 | 01:25.80 | 3.60s | +0.43s | 1.97s |
| **Total** | **Full Feature Video** | **00:00.00** | **01:27.77** | **87.77s** | **00:00.50** | **01:25.80** | **70.04s** | — | — |
