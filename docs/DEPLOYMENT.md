# XRL-IDARS — Deployment Architecture & Operational Modes

**Document ID:** `DOC-OPS-DEPLOYMENT-001`  
**Version:** 2.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 31, 2026  

---

## 1. Supported Deployment Topologies

XRL-IDARS is engineered with a strict decoupled architecture supporting three primary operational topologies:

```
[Topology A: Cloud & Remote Demonstration (Streamlit Community Cloud)]
  Simulated Lab Packets / PCAP Replay --> CanonicalFlowBuilder --> R10 Extraction -->
  Random Forest (<0.8ms) + Rules --> Hybrid Arbiter --> TreeSHAP Explainer -->
  Dueling DQN (6D State) --> Deterministic Safety Gate --> In-Memory / PostgreSQL Store --> Streamlit SOC UI

[Topology B: Controlled Local Lab / On-Premises Simulation]
  Scapy Packet Simulator --> Loopback / veth0 --> CanonicalFlowBuilder -->
  ActiveInferencePipeline --> Asynchronous Queue Worker (Bounded 10k) -->
  Local PostgreSQL 18+ DB (Table: security_events) + JSONL Audit --> SOC Dashboard (Port 8501)

[Topology C: Enterprise Passive TAP / Mirror Port Deployment]
  Switch Mirror Port (SPAN / TAP) --> Promiscuous NIC (eth1) [CAP_NET_RAW] -->
  ScapyCaptureService --> Non-blocking Thread-Safe Ring Buffer -->
  Operational Pipeline --> Advisory Actuator (Zero Host Mutations) --> SIEM / SOC Feeds
```

---

## 2. Platform Requirements & Pre-requisites

| Component | Minimum Specification | Recommended Specification |
| :--- | :--- | :--- |
| **Operating System** | Linux (Ubuntu 22.04+, Debian 12+) or macOS | Linux (Ubuntu 24.04 LTS x86_64) |
| **Python Runtime** | Python 3.10 - 3.14 | Python 3.11+ |
| **Memory (RAM)** | 2 GB Available | 4 GB+ |
| **CPU** | 2 Virtual Cores | 4 Cores @ 2.5 GHz+ |
| **PostgreSQL** | PostgreSQL 14+ (Optional; auto-fallback) | PostgreSQL 16+ or 18+ |
| **Network Capabilities** | Unprivileged loopback / simulation | `CAP_NET_RAW` for promiscuous wire capture |

---

## 3. Environment Variables & Configuration

Configuration is purely environment-driven. No passwords or sensitive connection strings are hardcoded in the codebase.

| Variable Name | Default Value | Allowed Values | Description |
| :--- | :--- | :--- | :--- |
| `POSTGRES_HOST` | `localhost` | Hostname / IP | PostgreSQL database host address. |
| `POSTGRES_PORT` | `5432` | Integer (1-65535) | PostgreSQL database server port. |
| `POSTGRES_DB` | `xrlids` | String | Target database name. |
| `POSTGRES_USER` | `xrlids_user` | String | Database authentication username. |
| `POSTGRES_PASSWORD` | *(empty)* | String | Database authentication password. |
| `XRLIDS_STORAGE_MODE` | `auto` | `auto`, `postgres`, `memory` | Event store mode (`auto` connects to PG if available, else falls back to memory). |
| `XRLIDS_PERSISTENCE_QUEUE_SIZE` | `10000` | Integer | Maximum capacity of the non-blocking asynchronous database queue. |
| `XRLIDS_PERSISTENCE_BATCH_SIZE` | `100` | Integer | Micro-batch size for multi-row database insertions. |
| `XRLIDS_PERSISTENCE_FLUSH_INTERVAL` | `0.50` | Float (seconds) | Flush interval timer for asynchronous persistence worker. |

---

## 4. Deployment Option 1: Streamlit Community Cloud

Streamlit Community Cloud provides instant public hosting of the XRL-IDARS SOC Command Center:

1. **Repository Structure**:
   - Entrypoint file: `dashboard/streamlit_app.py`
   - Navigation pages: `dashboard/pages/01_Overview.py`, `dashboard/pages/02_Live_Demo.py`, `dashboard/pages/03_Benchmarks.py`
   - Dependencies: `requirements.txt`
   - Configuration: `.streamlit/config.toml`

2. **Streamlit Cloud Dashboard Setup**:
   - **Repository:** `rishikeshgowdakk/fyp-xrlids`
   - **Branch:** `main` (or active release branch)
   - **Main file path:** `dashboard/streamlit_app.py`

3. **Secrets Configuration (Optional PostgreSQL Connection)**:
   In the Streamlit Cloud App Settings under **Secrets**, paste:
   ```toml
   POSTGRES_HOST = "your-managed-db.region.postgres.render.com"
   POSTGRES_PORT = "5432"
   POSTGRES_DB = "xrlids"
   POSTGRES_USER = "xrlids_admin"
   POSTGRES_PASSWORD = "your-secure-password"
   XRLIDS_STORAGE_MODE = "auto"
   ```
   *Note: If no external database is configured, XRL-IDARS automatically operates in In-Memory Ring Buffer + JSONL audit mode with 100% functionality preserved.*

---

## 5. Deployment Option 2: Docker & Docker Compose

Deploy the complete application and PostgreSQL database with one command:

```bash
# 1. Clone repository
git clone https://github.com/rishikeshgowdakk/fyp-xrlids.git
cd fyp-xrlids

# 2. Copy environment template
cp .env.example .env
# Edit .env with your desired POSTGRES_PASSWORD

# 3. Launch database and application containers
docker compose up -d

# 4. Access Command Center
# Open browser at: http://localhost:8501
```

---

## 6. Deployment Option 3: Local / Bare-Metal Production

```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Run PostgreSQL daemon
sudo systemctl start postgresql

# 4. Start the Streamlit Command Center
streamlit run dashboard/streamlit_app.py --server.port 8501
```

---

## 7. Security Invariants & Privileges

1. **Advisory Actuation Invariant**:
   - All response execution recommendations generated by the Dueling DQN policy are rendered strictly in **Advisory / Dry-Run** mode.
   - Zero modifications (`0 mutations`) are performed on the host operating system's kernel firewall (`iptables` / `nftables`).

2. **Strict IP Isolation Invariant**:
   - Calibrated packet simulations are strictly restricted to the isolated lab subnet (`10.200.1.0/24`) and loopback (`127.0.0.1`).
   - Generation against public IP addresses or WAN ranges is programmatically rejected by `validate_target_safety()`.

3. **Non-Root Raw Socket Fallback**:
   - Promiscuous network packet capture requires `CAP_NET_RAW` Linux capabilities:
     ```bash
     sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)
     ```
   - In unprivileged environments, the system falls back safely to loopback processing, PCAP stream replay, and calibrated simulation with full observability.
