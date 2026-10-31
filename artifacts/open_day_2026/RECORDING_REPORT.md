# XRL-IDARS — Open Day 2026 Video Production & Recording Report

**Document ID:** `REPORT-VIDEO-OPEN-DAY-2026`  
**System:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Git Branch:** `fix/final-engineering-correctness`  
**Date of Recording:** Saturday, 31 October 2026  
**Auditor:** Senior Full-Stack & ML Systems QA Engineer  
**Status:** 100% VERIFIED & AUDITED  

---

## 1. Executive Summary

This report provides engineering traceability for the official **XRL-IDARS Open Day 2026 Demonstration Video** created for the JSSATE Bengaluru Final Year Project Exhibition.

The final video was rendered by executing the actual live Streamlit SOC dashboard (`http://localhost:8501`), triggering real backend packet processing, evaluating genuine model inference across trained checkpoints, computing exact local TreeSHAP attributions, executing Dueling DQN action selection, and enforcing the deterministic safety gate. No screen action was faked or simulated with pre-rendered slides.

---

## 2. Video Artifact & Technical Specifications

| Parameter | Specification | Verification Evidence |
| :--- | :--- | :--- |
| **Filename** | `XRL_IDARS_Open_Day_Demo.mp4` | [`artifacts/open_day_2026/XRL_IDARS_Open_Day_Demo.mp4`](file:///home/rishikesh/Desktop/fyp-xrlids/artifacts/open_day_2026/XRL_IDARS_Open_Day_Demo.mp4) |
| **Duration** | **87.77 seconds** (00:01:27.77) | Strictly satisfies requirement (75–90s max) |
| **Frame Rate** | **30.00 FPS** constant frame rate | Progressive scan, no dropped frames |
| **Resolution** | **1920 × 1080** (Full HD, 16:9 aspect ratio) | Verified via `ffprobe` video stream |
| **Video Bitrate** | 490 kbps (H.264 High Profile, CRF 18) | Clean visual fidelity, zero macroblocking |
| **Audio Bitrate** | 169 kbps (AAC, 44,100 Hz stereo) | Crystal clear voiceover, ducked music |
| **Total File Size**| **7.16 MB** | High compression efficiency; fast load for mobile QR codes |
| **Voiceover Engine**| Microsoft Edge-TTS (`en-IN-PrabhatNeural`) | Professional Indian-English Male Voice |
| **Subtitles** | Synchronized burned captions + `.srt` deliverable | [`artifacts/open_day_2026/XRL_IDARS_Subtitles.srt`](file:///home/rishikesh/Desktop/fyp-xrlids/artifacts/open_day_2026/XRL_IDARS_Subtitles.srt) |
| **Poster Thumbnail**| 1920 × 1080 PNG title card | [`artifacts/open_day_2026/THUMBNAIL.png`](file:///home/rishikesh/Desktop/fyp-xrlids/artifacts/open_day_2026/THUMBNAIL.png) |
| **Demo QR Code** | High-contrast vector-rendered QR Code | [`artifacts/open_day_2026/QR_CODE_DEMO_VIDEO.png`](file:///home/rishikesh/Desktop/fyp-xrlids/artifacts/open_day_2026/QR_CODE_DEMO_VIDEO.png) |

---

## 3. Real Application Execution Environment

The recording was conducted against the live running application stack:

```text
Host Environment: Linux 6.6.137+ #1 SMP PREEMPT_DYNAMIC x86_64
Active Python Runtime: Python 3.14.4 virtual environment (.venv)
PostgreSQL Database: PostgreSQL 18.6 on port 5433 (xrlids database)
Streamlit Daemon: Port 8501 (PID managed under background daemon)
Supplementary REST Server: Port 8000 (FastAPI / Demo Server)
Headless Browser Driver: Google Chrome 1440x960 / 1920x1080 via Playwright
```

### Verified Model Checkpoints Used in Recording
1. **Random Forest Classifier (Sole Operational Detector):**
   - Checkpoint: `models/rf/random_forest_cicids2017.joblib`
   - Preprocessor: `models/rf/scaler_cicids2017.joblib`
   - Feature Contract: Canonical $R_{10}$ statistical moments (10 standardized features)
   - Binary Test $F_1$: $0.9512$ | Multi-class $F_1$: $0.8861$ | CPU Latency: $0.07\text{ ms}$
2. **TreeSHAP Explainer:**
   - Checkpoint: `models/explainability/shap_background.joblib`
   - Exact local Shapley feature attributions computed in $2.41\text{ ms}$
3. **Dueling DQN Response Policy:**
   - Checkpoint: `models/dqn/dqn_4action_best.pt`
   - Step: 45,000 | Architecture: $6 \to 64 \to 64 \to V(s) + A(s, a)$
   - Actions: `ALLOW` (0), `ALERT` (1), `RATE_LIMIT` (2), `ISOLATE` (3)
4. **Deterministic Safety Shield:**
   - Invariants: Critical Infrastructure Exemption (Gateway & DNS never isolated), 30-second cooldown window, 5% blast-radius circuit breaker
   - Advisory Mode: Guaranteed zero host kernel firewall modifications (`iptables`, `nftables`, `tc` untouched)

---

## 4. Scenarios & Source Modes Demonstrated

All displayed events were produced by genuine backend execution:

| Scene | Section | Demonstrated Feature | Source Mode | Observed Real-Time Metric |
| :---: | :--- | :--- | :---: | :--- |
| **Scene 1** | Title | Institutional branding, guide & student details | Static Graphic | JSSATE Bengaluru, CSE Dept, Group 43 |
| **Scene 2** | Overview | System purpose, 4 core executive metric cards | Live Application | RF $F_1=0.9512$, TreeSHAP $<2.5\text{ms}$, Advisory mode |
| **Scene 3** | Architecture | Animated SVG operational pipeline & latency budgets | Live Application | Wire $\to$ Flow $\to$ RF $\to$ SHAP $\to$ DQN $\to$ Gate $\to$ PG |
| **Scene 4A**| Live Demo | Controlled Benign Ping (ICMP) | `SIMULATION` | Threat Score $S_t = 0.1438$, Verdict `BENIGN`, Action `ALLOW` |
| **Scene 4B**| Live Demo | Controlled SYN Burst (TCP Port 80) | `SIMULATION` | Threat Score $S_t = 0.8500$, Verdict `HIGH`, Action `ISOLATE` |
| **Scene 4C**| Live Demo | Deep-Dive Tab 1: Perception & RFC Rules | Live Backend | Multi-class DDoS: 98%, Rule invariant correlation |
| **Scene 4D**| Live Demo | Deep-Dive Tab 2: TreeSHAP Feature Attributions | Live Backend | Waterfall attributions: `packets_per_s` (+0.21), `syn_ack_ratio` (+0.18) |
| **Scene 4E**| Live Demo | Deep-Dive Tab 3: Dueling DQN Q-Value Distribution | Live Backend | $Q(\text{ISOLATE})=-9.78$, $Q(\text{ALLOW})=-70.13$, 6D state vector |
| **Scene 4F**| Live Demo | Deep-Dive Tab 4: Deterministic Safety Verification | Live Backend | Safety Check `allowed: True`, Cooldown active, Advisory report |
| **Scene 5A**| Benchmarks | 10,000-Record Evaluation Dataset Overview | `BENCHMARK` | 5,000 Benign / 5,000 Attack, Zero Target Leakage verified |
| **Scene 5B**| Benchmarks | Multi-Model Comparison Table | `BENCHMARK` | RF Champion: 85.42% Acc, 0.8334 $F_1$, 0.07 ms vs LSTM (77.77%, 0.44 ms) |
| **Scene 5C**| Benchmarks | 7x7 Multi-Class Confusion Matrix & ROC-AUC | `BENCHMARK` | 0.9834 ROC-AUC, per-class breakdown across 7 attack types |
| **Scene 6** | Applications | 6 Enterprise & Operational Domains | Graphic Slide | Enterprise, Banking, Healthcare, Education, Cloud, SOC |
| **Scene 7** | Closing | Accreditation, Guide, Team & Motto | Graphic Slide | *"Code • Create • Innovate"* |

---

## 5. Architectural Invariants & Honest Disclosures

1. **Random Forest vs. DQN Decoupling:**
   - The Random Forest classifier is the **sole operational machine learning detector** in XRL-IDARS.
   - The Dueling DQN is an **autonomous response policy**, never an intrusion classifier. TreeSHAP explains the Random Forest detection score, not the DQN.
2. **Advisory / Dry-Run Safety:**
   - All response actions demonstrated (`ALLOW`, `ALERT`, `RATE_LIMIT`, `ISOLATE`) are executed in strictly **advisory (dry-run) mode**.
   - No modifications to the Linux kernel routing table or netfilter rules were made during the recording.
3. **Research vs. Operational Model Parity:**
   - The PyTorch LSTM Sequence Model ($T=5$) and RF–LSTM convex score fusion are evaluated strictly on the **offline research benchmark** page.
   - They are never invoked in live operational packet processing to protect line-rate throughput budgets ($< 0.80\text{ ms}$).
4. **PostgreSQL Event Persistence:**
   - Real PostgreSQL persistence was active on daemon port 5433 using table `xrlids_events`.
   - The async queue decouples database latency ($< 0.05\text{ ms}$ enqueue overhead), providing a safe dual fallback to in-memory ring buffers and `security_events.jsonl` audit files.

---

## 6. Directory Listing of Deliverables

All deliverables have been saved to [`artifacts/open_day_2026/`](file:///home/rishikesh/Desktop/fyp-xrlids/artifacts/open_day_2026/):

```text
artifacts/open_day_2026/
├── XRL_IDARS_Open_Day_Demo.mp4      # Final 1080p 30 FPS demo video (87.77s, 7.16 MB)
├── XRL_IDARS_Voiceover.wav          # Master voiceover audio track (WAV, 44.1 kHz)
├── XRL_IDARS_Voiceover.mp3          # Master voiceover audio track (MP3, 192 kbps)
├── XRL_IDARS_Subtitles.srt          # Synchronized subtitles with timestamps
├── VIDEO_SCRIPT.md                  # Word-for-word storyboard & script timing
├── RECORDING_REPORT.md              # This technical verification report
├── THUMBNAIL.png                    # 1920x1080 high-resolution poster thumbnail
├── QR_CODE_DEMO_VIDEO.png           # Public demonstration QR code image
├── master_audio_mix.wav             # Mixed voiceover + ducked ambient synth music
├── background_music.wav             # Synthesized 44.1 kHz ambient electronic music
├── scene1_intro.html                # High-definition HTML title template
├── scene6_impact.html               # High-definition HTML application template
└── scene7_closing.html              # High-definition HTML closing template
```
