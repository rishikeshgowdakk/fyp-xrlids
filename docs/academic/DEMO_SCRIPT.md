# XRL-IDARS — 5–10 Minute Viva Live Demonstration Script

**Document ID:** `DOC-ACAD-DEMO-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  
**Audience:** Viva Examiners, Project Reviewers, and Industry Evaluators  

---

## 1. Demonstration Setup & Pre-Flight Checklist

Before the examiners arrive, verify the local environment in two terminal windows:

### Terminal 1 (Dashboard Server):
```bash
cd ~/Desktop/fyp-xrlids
source .venv/bin/activate
.venv/bin/python scripts/demo/run_dashboard.py 8000
```
Open browser: **`http://localhost:8000`**

### Terminal 2 (Operator Control Terminal):
```bash
cd ~/Desktop/fyp-xrlids
source .venv/bin/activate
```

---

## 2. Timed Demonstration Walkthrough

### Phase 1 (0:00 – 1:30): System Overview & Architecture
- **Action**: Direct the examiner's attention to the running browser dashboard at `http://localhost:8000`.
- **Key Talking Points**:
  - Point to the top telemetry banner: *"Here we see XRL-IDARS running in real time. Notice the operational detector is certified as Random Forest using the canonical 10-feature R10 contract. The response safety mode is explicitly labeled 'ADVISORY / DRY_RUN', guaranteeing zero uncommanded host network disruption."*
  - Explain the 14-layer execution pipeline from packet ingestion to dashboard streaming.

### Phase 2 (1:30 – 3:30): Benign Traffic Flow & Control Run
- **Action**: In Terminal 2, execute the benign Scapy simulation:
  ```bash
  .venv/bin/python scripts/demo/run_scapy_simulation.py --scenario scenario_a_benign --explain
  ```
- **Key Talking Points**:
  - Show the terminal output and dashboard flow table updating with 4 reconstructed flows.
  - *"Notice that all flows score between 0.0006 and 0.0431—well below our 0.50 alert threshold. They are correctly classified as BENIGN (Green pill)."*
  - *"In the terminal, we see that the TreeSHAP local attributions identify normal packet length variance and standard flow duration as strong negative drivers reducing the threat score."*

### Phase 3 (3:30 – 5:30): Attack Injection & Real-Time Alert Trigger
- **Action**: In Terminal 2, inject a volumetric TCP SYN burst attack:
  ```bash
  .venv/bin/python scripts/demo/run_scapy_simulation.py --scenario scenario_c_syn_burst --explain
  ```
- **Key Talking Points**:
  - Show the dashboard immediately emitting red alert cards.
  - *"Here we inject genuine Scapy-generated TCP SYN packets directed at port 80. The flow builder reconstructs the bidirectional flow in 10 ms, detects extreme SYN/ACK asymmetry, and the pipeline triggers an immediate threat alert."*

### Phase 4 (5:30 – 7:30): TreeSHAP Local Feature Attribution
- **Action**: Click the "Explain" button on the attack flow in the dashboard to open the TreeSHAP waterfall modal.
- **Key Talking Points**:
  - *"This waterfall chart is computed using Lundberg's TreeSHAP algorithm. Unlike black-box neural networks, our system shows the human operator exactly why the attack was flagged."*
  - Point to the red bars: *"Notice the positive drivers pushing the score up: elevated packet arrival rate and extreme SYN/ACK asymmetry."*
  - Point to blue bars: *"Negative drivers pulling the score down. This gives security analysts immediate forensic confidence without manual packet decoding."*

### Phase 5 (7:30 – 9:00): Autonomous Response Advisory & Safety Shielding
- **Action**: Scroll to the Autonomous Response console on the dashboard.
- **Key Talking Points**:
  - *"Downstream from detection, our Dueling DQN policy receives a 6D causal state vector and proposes a cost-optimal mitigation action."*
  - Show the Safety Gate audit entry: *"Before any action is enacted, it passes through our Deterministic Safety Gate. The gate checks our Critical Host Allowlist, enforces a 30-step cooldown window, and applies a 5% blast-radius circuit breaker."*
  - *"All enforcement is executed in Advisory Dry-Run mode, providing proactive response recommendations without mutating kernel firewall tables."*

### Phase 6 (9:00 – 10:00): Anti-Mock Verification & Conclusion
- **Action**: In Terminal 2, execute the anti-mock verification script:
  ```bash
  .venv/bin/python scripts/demo/explain_score.py --scenario slow_http_dos
  ```
- **Key Talking Points**:
  - *"To prove that our system does not rely on hardcoded lookup tables or pre-recorded constants, this script feeds the exact same two packets into the model while varying the inter-packet arrival gap from 0.05s to 3.25s."*
  - Show the score dynamically shifting from 0.10 to 0.99: *"As the flow's temporal shape changes, the Random Forest model dynamically computes different scores in real time."*
  - Conclude: *"In summary, XRL-IDARS combines high-accuracy intrusion detection, sub-millisecond latency, explainable AI, and safe reinforcement learning into a fully integrated, academically defensible platform."*
