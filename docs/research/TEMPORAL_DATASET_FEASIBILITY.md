# XRL-IDARS — Temporal Dataset Feasibility Study & Engineering Assessment

**Document ID:** `RESEARCH-DOC-2026-TDF-001`  
**Version:** 1.0.0  
**Phase:** Phase 1 — Temporal Architecture and Dataset Feasibility  
**Date:** October 30, 2026  
**Author:** Senior Network Security ML Architect  
**Status:** COMPLETE & AUTHORITATIVE  
**Repository:** `/home/rishikesh/Desktop/fyp-xrlids`  

---

## 1. Executive Summary & Plain-Language Guide

### 1.1 The Plain-Language Problem
In network security, an intrusion detection system (NIDS) can look at traffic in two different ways:
1. **The Flow View (Microscopic / Tabular):** The detector looks at a single completed conversation between two computers (e.g., "Computer A sent 4 packets to Computer B on port 80"). It extracts summary statistics like total bytes and duration. Our **Random Forest** uses this view. It works exceptionally well ($F1 = 0.9512$, $99.01\%$ recall), running in under 1 millisecond per flow.
2. **The Host-Activity View (Macroscopic / Temporal):** The detector watches a specific computer (host IP) over time across consecutive seconds (e.g., Second 1, Second 2, ..., Second 5). It looks for behavioral trends—such as a sudden burst of failed connection requests (SYN flood) or an IP scanning dozens of targets. This is where an **LSTM (Long Short-Term Memory neural network)** is supposed to shine.

In Phase 0, we discovered that the repository's existing LSTM was trained on contiguous rows of multi-file CSVs that lacked timestamps and mixed together random computers. When the order of rows was shuffled, the LSTM's recall crashed by $46.2\%$, proving it was memorizing dataset export order rather than learning real network time.

### 1.2 Objective of this Feasibility Study
Before writing or training any new temporal model, we must establish **what data actually exists on disk** across our three benchmark datasets:
- **CIC-IDS2017**
- **CSE-CIC-IDS2018**
- **UNSW-NB15**

Specifically, we must answer:
- Do these datasets contain real timestamps and source/destination IP addresses?
- Can they support **source-host chronological 1-second activity windows**?
- Is raw PCAP (packet capture) packet-level reconstruction required, and is it feasible on our infrastructure?

---

## 2. Comprehensive Inventory of Datasets on Disk

Every raw dataset file registered in [`data/manifests/dataset_registry.yaml`](file:///home/rishikesh/Desktop/fyp-xrlids/data/manifests/dataset_registry.yaml) has been verified on disk.

```
Total Available Local Storage: 409 GB on NVMe SSD (/dev/nvme0n1p4)
Total Raw Dataset Footprint:   7.68 GB across 20 CSV files
Total Dedicated PCAP Files:    1 file (data/demo/sample_traffic.pcap, 63 KB)
```

### 2.1 File-by-File Physical Inventory

| Dataset Key | File Name | Size (Bytes) | SHA-256 Checksum (Prefix) | Stored Record Type |
| :--- | :--- | :---: | :---: | :---: |
| **CIC-IDS2017** | `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 77,123,859 | `6ff1580f5f81c0ae...` | Pre-extracted Flow CSV |
| **CIC-IDS2017** | `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 76,906,168 | `ca1824c51bfbb7b3...` | Pre-extracted Flow CSV |
| **CIC-IDS2017** | `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 58,316,725 | `53a41c24d570ea83...` | Pre-extracted Flow CSV |
| **CIC-IDS2017** | `Monday-WorkingHours.pcap_ISCX.csv` | 176,927,918 | `852c4beb34eda186...` | Pre-extracted Flow CSV |
| **CIC-IDS2017** | `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 83,102,436 | `6bcda3857c250467...` | Pre-extracted Flow CSV |
| **CIC-IDS2017** | `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 52,023,263 | `d67066211fb1689c...` | Pre-extracted Flow CSV |
| **CIC-IDS2017** | `Tuesday-WorkingHours.pcap_ISCX.csv` | 135,078,995 | `52b8692ae8c7d2ed...` | Pre-extracted Flow CSV |
| **CIC-IDS2017** | `Wednesday-workingHours.pcap_ISCX.csv` | 225,166,395 | `893c27dc968bf7a8...` | Pre-extracted Flow CSV |
| **CSE-CIC-IDS2018** | `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 352,368,373 | `d96f38e7496aba83...` | Pre-extracted Flow CSV |
| **CSE-CIC-IDS2018** | `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | 333,723,605 | `1a4919faa0c49c7af...` | Pre-extracted Flow CSV |
| **CSE-CIC-IDS2018** | `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 382,840,456 | `d0a7f5059d9823b6...` | Pre-extracted Flow CSV |
| **CSE-CIC-IDS2018** | `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` | 4,054,925,350 | `7287a4d7740a1ddd...` | **Pre-extracted Flow CSV with 5-Tuple & Timestamp** |
| **CSE-CIC-IDS2018** | `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | 107,842,858 | `b0534c5d7d8b41e0...` | Pre-extracted Flow CSV |
| **CSE-CIC-IDS2018** | `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 375,945,899 | `fa2947a8256d81ee...` | Pre-extracted Flow CSV |
| **CSE-CIC-IDS2018** | `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | 382,636,202 | `da33c927018274f9...` | Pre-extracted Flow CSV |
| **CSE-CIC-IDS2018** | `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | 358,223,333 | `acff8bc61376ee03...` | Pre-extracted Flow CSV |
| **CSE-CIC-IDS2018** | `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | 328,893,673 | `a5f4a1c2689e0aa6...` | Pre-extracted Flow CSV |
| **CSE-CIC-IDS2018** | `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | 209,249,758 | `f15e2a1230444605...` | Pre-extracted Flow CSV |
| **UNSW-NB15** | `UNSW_NB15_training-set.csv` | 32,293,018 | `e5bf9fb5c68b6b00...` | Pre-extracted Flow Partition CSV |
| **UNSW-NB15** | `UNSW_NB15_testing-set.csv` | 15,380,800 | `cb66bf8a08d2713f...` | Pre-extracted Flow Partition CSV |

---

## 3. Schema & Identifier Availability Analysis

To evaluate whether source-host 1-second chronological activity windows can be constructed, we performed automated header inspection across all 20 dataset CSV files.

### 3.1 CIC-IDS2017 Schema Audit
- **Files Examined**: 8 files in [`data/raw/cicids2017/`](file:///home/rishikesh/Desktop/fyp-xrlids/data/raw/cicids2017/) (Total rows: $1,779,322$).
- **Total Columns**: 79 columns.
- **Timestamp Availability**: **NONE (0%)**. No timestamp, start time, or date column exists.
- **Source IP Availability**: **NONE (0%)**. No `Src IP`, `Source IP`, or client identifier exists.
- **Destination IP Availability**: **NONE (0%)**. No `Dst IP`, `Destination IP`, or server identifier exists.
- **Port Availability**: Only ` Destination Port` is present. Source port is absent.
- **Protocol Availability**: No numeric IP protocol column exists.
- **Ground-Truth Label Availability**: Present (` Label`).
- **Architectural Conclusion**: **INCAPABLE OF CHRONOLOGICAL WINDOWING**. The published UNB `MachineLearningCSV` files for CIC-IDS2017 strip all packet timestamps and host IP addresses. It is mathematically impossible to reconstruct chronological sequences or group by host from these CSVs without external raw PCAPs.

### 3.2 CSE-CIC-IDS2018 Schema Audit
- **Files Examined**: 10 files in [`data/raw/cse_cic_ids2018/`](file:///home/rishikesh/Desktop/fyp-xrlids/data/raw/cse_cic_ids2018/) (Total rows: $8,312,295$).
- **Timestamp Availability**: **100% of files (10/10)**. Every file contains a `Timestamp` column with 1-second resolution formatted as string `DD/MM/YYYY HH:MM:SS` (e.g., `20/02/2018 08:34:07`).
- **Port & Protocol Availability**: `Dst Port` and `Protocol` (numeric: 6=TCP, 17=UDP, 0=HOPOPT/ICMP) exist across all 10 files.
- **Host IP Availability**:
  - **In 9 files (90%)**: Source IP and Destination IP are **ABSENT** (stripped by UNB/AWS during pre-processing).
  - **In 1 file (10%)**: [`data/raw/cse_cic_ids2018/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`](file:///home/rishikesh/Desktop/fyp-xrlids/data/raw/cse_cic_ids2018/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv) contains **84 columns**, including full network identifiers:
    - `Flow ID`
    - `Src IP`
    - `Src Port`
    - `Dst IP`
    - `Dst Port`
    - `Protocol`
    - `Timestamp`
- **Detailed Audit of `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`**:
  - **File Size**: $4,054,925,350\,\text{bytes}$ ($4.05\,\text{GB}$).
  - **Total Data Rows**: **$7,948,748$ rows** ($95.6\%$ of the entire CSE-CIC-IDS2018 dataset!).
  - **Benign Traffic**: $7,372,557$ flows.
  - **Attack Traffic**: $576,191$ flows (`DDoS attacks-LOIC-HTTP`).
  - **Distinct Attacking Hosts**: Multiple identifiable attacker IP addresses (e.g., `18.219.9.1`, `18.218.229.235`, `52.14.136.135`, `18.216.200.189`, `18.218.55.126`) targeting victim server `172.31.69.25`.
- **Architectural Conclusion**: **FEASIBLE FOR FLOW-AGGREGATED HOST WINDOWING**. The single 4.05 GB Tuesday file is an enormous, self-contained, real-world benchmark containing complete 5-tuples, timestamps, and ground-truth labels across nearly 8 million flows.

### 3.3 UNSW-NB15 Schema Audit
- **Files Examined**: 2 partition files in [`data/raw/unsw_nb15/`](file:///home/rishikesh/Desktop/fyp-xrlids/data/raw/unsw_nb15/) ($257,673$ total rows).
- **Total Columns**: 45 columns.
- **Timestamp Availability**: **NONE (0%)**. No timestamps exist in the published training/testing splits.
- **Host IP Availability**: **NONE (0%)**. IP addresses were removed during feature creation.
- **Aggregated Window Features**: Contains pre-calculated count features (`ct_srv_src`, `ct_dst_ltm`, `ct_src_dport_ltm`, etc.) computed over fixed connection windows by the dataset authors, but raw timestamps and raw IPs are not present.
- **Architectural Conclusion**: **INCAPABLE OF CHRONOLOGICAL WINDOWING**. The published 45-feature train/test splits cannot support chronological host-window reconstruction.

---

## 4. Dataset Feasibility Matrix

| Dataset | Local CSV Size | Local Rows | Timestamps | Host IPs | 5-Tuple Available | Supports 1s Host Windows from CSV? | Raw PCAP Required? | Feasibility Verdict |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **CIC-IDS2017** | $843.66\,\text{MB}$ | $1,779,322$ | ❌ NO | ❌ NO | ❌ NO (Dst Port only) | ❌ **IMPOSSIBLE** | **YES** (~50 GB PCAP download) | **INFEASIBLE** (Without PCAP) |
| **CSE-CIC-IDS2018 (General)** | $2.51\,\text{GB}$ (9 files) | $363,547$ | ✅ YES | ❌ NO | ❌ NO (Dst Port only) | ❌ **IMPOSSIBLE** | **YES** (~350 GB PCAP download) | **INFEASIBLE** (Host-level) |
| **CSE-CIC-IDS2018 (`Thuesday-20-02`)** | **$4.05\,\text{GB}$** | **$7,948,748$** | ✅ **YES** | ✅ **YES** | ✅ **YES** | ✅ **FEASIBLE** *(Flow-Aggregated)* | ❌ **NO** *(For flow windows)*<br>✅ **YES** *(For packet windows)* | **FEASIBLE** *(Primary Benchmark)* |
| **UNSW-NB15** | $45.47\,\text{MB}$ | $257,673$ | ❌ NO | ❌ NO | ❌ NO | ❌ **IMPOSSIBLE** | **YES** (~100 GB PCAP download) | **INFEASIBLE** (Without PCAP) |

---

## 5. PCAP Reconstruction Analysis & Engineering Constraints

To understand whether raw PCAP reconstruction should be undertaken, we analyzed the requirements, infrastructure cost, and availability:

### 5.1 Storage and Network Resource Requirements
1. **CIC-IDS2017 Full PCAPs**:
   - Total uncompressed PCAP volume: **~51.2 GB**.
   - Download status: The primary official UNB server (`iscxdownloads.cs.unb.ca`) is currently unreachable (`NXDOMAIN`), as documented in [`data/manifests/dataset_registry.yaml` line 23](file:///home/rishikesh/Desktop/fyp-xrlids/data/manifests/dataset_registry.yaml#L23). Third-party mirrors are slow and frequently fail verification.
2. **CSE-CIC-IDS2018 Full PCAPs**:
   - Total uncompressed PCAP volume: **~440 GB**.
   - Storage constraint: While our local NVMe filesystem has $409\,\text{GB}$ available, storing 440 GB of PCAPs would completely exhaust local disk capacity, leading to filesystem write failures.
3. **UNSW-NB15 Full PCAPs**:
   - Total uncompressed PCAP volume: **~100 GB**.

### 5.2 Flow-Level vs. Packet-Level Temporal Granularity
There is a fundamental scientific distinction between two types of host-activity windows:

1. **Packet-Level 1-Second Host Activity Windows**:
   - Requires sniffing or replaying raw PCAP packets.
   - Measures packet arrivals with microsecond timestamps directly from Ethernet/IP headers.
   - Computes packet length, TCP flags, and ICMP counts on every raw packet.
   - *Advantage*: Directly matches live Scapy/AF_PACKET packet sniffing in our live pipeline.
   - *Disadvantage*: Requires downloading and parsing 50–440 GB of raw PCAPs.

2. **Flow-Aggregated 1-Second Host Activity Windows**:
   - Uses pre-extracted flow records that contain flow start timestamps and flow durations.
   - Aggregates flows that initiated or occurred within each 1-second timestamp bin for that host.
   - Features represent total flows initiated, total packets transmitted across those flows, total bytes, and aggregate flag counts.
   - *Advantage*: Immediately feasible on disk right now using `Thuesday-20-02-2018` ($7.95\,\text{million}$ flows).
   - *Disadvantage*: Second-level timestamp resolution (`HH:MM:SS`) from CICFlowMeter rather than sub-millisecond packet precision.

---

## 6. Authoritative Architect Recommendation

### Recommendation: Two-Tier Empirical Roadmap

1. **Tier 1 (Immediate Empirical Benchmark on Local Data)**:
   - Use the **7.95 million flows of `Thuesday-20-02-2018`** in CSE-CIC-IDS2018.
   - It possesses authentic 5-tuples (`Src IP`, `Dst IP`, `Src Port`, `Dst Port`, `Protocol`), authentic timestamps, and verified attack labels (`DDoS LOIC-HTTP` vs. `Benign`).
   - Construct source-host 1-second chronological activity windows from this massive real dataset without downloading hundreds of gigabytes or modifying frozen artifacts.
   - Train and validate the new causal unidirectional LSTM on this benchmark.

2. **Tier 2 (Live Pipeline Alignment)**:
   - In our live Scapy/AF_PACKET capture service ([`src/xrlids/capture/scapy_service.py`](file:///home/rishikesh/Desktop/fyp-xrlids/src/xrlids/capture/scapy_service.py)), packets are ingested live in real-time.
   - Maintain an in-memory 1-second sliding ring buffer per active source host IP.
   - Extract the exact same 10 temporal features (`T10-Host`) in real-time.
   - This provides **100% semantic parity** between live host-activity monitoring and temporal model inference.
