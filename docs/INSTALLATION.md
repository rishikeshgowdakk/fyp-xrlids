# XRL-IDARS — Installation and Setup Guide

**Document ID:** `DOC-OPS-INSTALLATION-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. System Requirements & Prerequisites

### Supported Operating Systems:
- Ubuntu Linux 22.04 LTS / 24.04 LTS (x86_64) (Tested on Linux 7.0.0 x86_64)
- Debian 12 (Bookworm)
- Red Hat Enterprise Linux 9 / Fedora 39+

### Hardware Requirements:
- **Processor**: 4-core 64-bit x86_64 CPU (Intel Core i5/i7/Xeon or AMD Ryzen/EPYC)
- **Memory (RAM)**: Minimum 8 GB (16 GB recommended for full raw dataset processing)
- **Storage**: Minimum 10 GB free space on SSD (50 GB if downloading raw benchmark PCAPs/CSVs)

### Software Dependencies:
- **Python**: Version `3.10` to `3.14` (Verified on Python `3.14.4`)
- **Node.js**: Not required for production! The dashboard frontend uses standard ES6 Vanilla JavaScript served directly by the built-in pure-Python server (`dashboard/server.py`).
- **Packet Capture Utilities**: `libpcap-dev`, `tcpdump`, `ethtool` (optional, for live interface capture).

---

## 2. Step-by-Step Installation

### Step 1: Clone Repository
```bash
git clone https://github.com/rishikeshgowdakk/fyp-xrlids.git
cd fyp-xrlids
```

### Step 2: Set Up Python Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Python Dependencies
```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -e .
```

*Key Libraries Installed*:
- `torch>=2.6.0` (PyTorch CPU / CUDA)
- `scikit-learn>=1.6.0` (Random Forest, Preprocessors)
- `shap>=0.46.0` (TreeSHAP Attributions)
- `scapy>=2.6.0` (Packet Dissection and Injection)
- `pandas>=2.2.0`, `pyarrow>=18.0.0` (Data Parsing)
- `pytest>=9.0.0` (Automated Testing)

---

## 3. Verifying Installation & Model Artifacts

Run the verification script to confirm that all model checkpoints and preprocessors exist and load cleanly:

```bash
.venv/bin/python -c "
import joblib, torch
from xrlids.models.rf import RandomForestDetector

rf = joblib.load('models/rf/random_forest_cicids2017.joblib')
print('✓ Random Forest CIC-IDS2017 Loaded successfully')

dqn = torch.load('models/dqn/dqn_4action_best.pt', map_location='cpu', weights_only=False)
print('✓ Dueling DQN Policy Loaded successfully')
"
```

Execute the unit and integration test suite to verify system integrity:
```bash
.venv/bin/pytest tests/
```
*Expected Result*: `605 passed in ~48s`.

---

## 4. Starting the Application

### Option A: Interactive Web Dashboard (Recommended)
Launch the pure-Python dashboard server on port `8000`:
```bash
.venv/bin/python scripts/demo/run_dashboard.py 8000
```
Open your browser and navigate to: `http://localhost:8000`

### Option B: Scapy Live Packet Simulation CLI
Run the Scapy packet generator and pipeline evaluator in advisory mode:
```bash
.venv/bin/python scripts/demo/run_scapy_simulation.py --scenario scenario_a_benign --explain
```

### Option C: Replay Lab CLI
Replay a recorded PCAP stream:
```bash
.venv/bin/python scripts/demo/run_replay_demo.py
```

---

## 5. Common Troubleshooting & FAQs

1. **Permission Denied on Raw Socket Capture**:
   - *Cause*: Capturing live packets on a physical NIC (`eth0`) requires Linux network capabilities.
   - *Solution*: Either run with `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)` or use the built-in offline PCAP replay mode.
2. **Missing Parquet Flow Cache**:
   - *Cause*: Re-running `run_valid_lstm_experiment.py` requires `data/processed/cse2018_flowseq/`.
   - *Solution*: The cache is pre-extracted. If missing, generate it via `scripts/experiments/run_valid_lstm_experiment.py`.
