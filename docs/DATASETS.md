# XRL-IDARS — Authoritative Dataset Overview & Feature Contract Specification

> **Scope:** Authoritative reference for dataset provenance, capture environments, schemas, class distributions, data-quality audits, and feature contract specifications (R10 and R4).  
> **Status:** AUDITED, COMPLETED & FROZEN  
> **Total Raw Records:** 19,321,418 rows across 20 physical files  
> **Verified Modeling Population:** 10,214,137 deduplicated rows with zero cross-split vector leakage  

---

## 1. Overview and Dataset Selection Rationale

XRL-IDARS evaluates three established network intrusion detection benchmarks: **CIC-IDS2017**, **CSE-CIC-IDS2018**, and **UNSW-NB15**. These datasets were selected to address complementary research questions regarding modern network attack detection, temporal modeling, and cross-network generalizability:

| Dataset | Primary Role in XRL-IDARS | Key Architectural Rationale |
|:---|:---|:---|
| **CIC-IDS2017** | **Primary In-Domain Baseline & Demonstration Foundation** | Gold-standard modern benchmark with full multi-day diversity, realistic background traffic (B-Profile), and direct compatibility with the pure-Python streaming flow extractor. Used for primary Random Forest, LSTM, and score fusion training (`EXP-P1-CIC2017-R10-001`). |
| **CSE-CIC-IDS2018** | **Enterprise Cloud Scale & Cross-Dataset Target** | Massive enterprise-scale AWS cloud dataset (16.2M rows) testing pipeline scalability, memory-bounded streaming ingestion, and out-of-domain transfer robustness (`EXP-P1-CSE2018-R10-MULTI-001`). |
| **UNSW-NB15** | **Heterogeneous Exporter & Auxiliary Benchmark** | Contemporary low-footprint attack profiles generated via Argus and Bro/Zeek (non-CICFlowMeter). Explicitly tests model transfer when underlying flow generation tools differ fundamentally (`EXP-P1-UNSWNB15-R10-MULTI-001`). |

---

## 2. Dataset & Model Exclusion Policy from Version Control

> [!IMPORTANT]
> **Git Storage & Redistribution Policy:**
> - **Raw Datasets Excluded:** Due to GitHub file size limits and academic redistribution terms, raw dataset CSV files (`data/raw/*`) are tracked in `.gitignore` and **not** committed to the Git repository.
> - **Large Model Binaries Excluded:** Trained model binaries (`.joblib`, `.pt`, `.pth`) exceeding 25 MB are stored in local `results/` directories and excluded from standard Git tracking.
> - **Reconstitution Protocol:** Anyone cloning the repository can verify or acquire the datasets using the authoritative cryptographic hashes stored in `data/manifests/dataset_registry.yaml`. To verify existing local files:
>   ```bash
>   .venv/bin/python scripts/phase1/prepare_dataset.py verify --dataset cicids2017
>   .venv/bin/python scripts/phase1/prepare_dataset.py verify --dataset cse_cic_ids2018
>   .venv/bin/python scripts/phase1/prepare_dataset.py verify --dataset unsw_nb15
>   ```

---

## 3. Comprehensive Dataset Specifications

### 3.1. CIC-IDS2017

- **Provider:** Canadian Institute for Cybersecurity (CIC), University of New Brunswick (UNB), Canada.
- **Official URL:** `https://www.unb.ca/cic/datasets/ids-2017.html`
- **Acquisition Source:** `MachineLearningCSV.zip` mirror, verified via SHA-256 (`third_party_mirror`).
- **Capture Environment:** A physical testbed comprising a victim network (servers, domain controllers, firewalls, and 25 user workstations running Windows and Linux) and an external attacker network. Background traffic was generated using the **B-Profile system**, simulating realistic human user behavior (HTTP, HTTPS, FTP, SSH, and email).
- **Capture Period:** 5 consecutive working days (Monday July 3, 2017 to Friday July 7, 2017).
- **Extraction Tool:** CICFlowMeter (Java-based flow generator extracting bidirectional statistical summaries from raw PCAPs).
- **Files Present:** 8 physical CSV files in `data/raw/cicids2017/`.
- **Columns per File:** 79 columns (78 bidirectional flow metrics + 1 label column ` Label`).
- **Total Raw Rows:** **2,830,743**.

#### Per-File Breakdown & Class Distribution

| File Name | Size (Bytes) | Rows | Cols | Attack Classes & Support | Benign Support | Primary SHA-256 Digest |
|:---|---:|---:|:---:|:---|---:|:---|
| `Monday-WorkingHours.pcap_ISCX.csv` | 150,915,084 | 529,918 | 79 | *None (Benign baseline day)* | 529,918 | `a9b400780211f5619196d4981fe972e2cf3ab8a29906d4e51147055ec0319409` |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 129,567,118 | 445,909 | 79 | `FTP-Patator`: 7,938<br>`SSH-Patator`: 5,897 | 432,074 | `a3fec02c1144901f4c78161f3d64c0628e4fe66b8b0e60805fa60799ea48f95c` |
| `Wednesday-workingHours.pcap_ISCX.csv` | 197,294,668 | 692,703 | 79 | `DoS Hulk`: 231,073<br>`DoS GoldenEye`: 10,293<br>`DoS Slowloris`: 5,796<br>`DoS Slowhttptest`: 5,499<br>`Heartbleed`: 11 | 440,031 | `ea5447a16e7dd787ec38c4149fa89481229a8a7226db263889166f2ae9b4c022` |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 48,154,643 | 170,366 | 79 | `Web Attack – Brute Force`: 1,507<br>`Web Attack – XSS`: 652<br>`Web Attack – Sql Injection`: 21 | 168,186 | `955ae25178fc0480a4231b26543265ef25154378f895fb42a61ee48bc2109559` |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 83,439,788 | 288,602 | 79 | `Infiltration`: 36 | 288,566 | `4f7b60ea262c5a0fb76b9e289bf65d8365215c0e1ae5b184ef4fa682e0dfbc26` |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 64,078,574 | 191,033 | 79 | `Bot`: 1,966 | 189,067 | `b6770f5e1ad87bfd078ba1c3f914979e2c66ee6eb2e62eb747e70498eb18a7b9` |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 76,906,168 | 286,467 | 79 | `PortScan`: 158,930 | 127,537 | `ca1824c51bfbb7b3c72290a11be04366ba8815878c6a1cc5c44cb1cee269e99b` |
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 77,123,859 | 225,745 | 79 | `DDoS`: 128,027 | 97,718 | `6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee` |
| **Total / Summary** | **828,479,892** | **2,830,743** | **79** | **557,646 attacks (19.7%)** | **2,273,097 (80.3%)** | *All 8 files SHA-256 verified* |

#### Known Data-Quality Issues & Cleaning Protocol
1. **Missing & Infinite Values:** 287 cells with `NaN` in `Flow Bytes/s`; 2,878 cells with `+Inf` across `Flow Bytes/s` and `Flow Packets/s`. Handled deterministically by imputing training-set medians.
2. **Duplicate Rows:** 256,479 identical rows in raw CSVs (9.06%).
3. **Cross-Split Duplicate Leakage:** Under naive random splitting, 34.5% of raw flows leak identical feature vectors into the test set (`L-01` leakage). **Policy A Feature Deduplication** drops 1,051,421 redundant rows, yielding a strictly leakage-free modeling population of **1,779,322 rows** with zero cross-split duplicate vectors.

---

### 3.2. CSE-CIC-IDS2018

- **Provider:** Communications Security Establishment (CSE) & Canadian Institute for Cybersecurity (CIC).
- **Official URL:** `https://www.unb.ca/cic/datasets/ids-2018.html`
- **Acquisition Source:** AWS Open Data mirror (`s3://cse-cic-ids2018/`), verified via SHA-256 (`recognized_mirror`).
- **Capture Environment:** An enterprise AWS cloud architecture comprising 50 victim machines across 5 functional departments (Finance, HR, Development, Management, IT), 30 server instances, and a botnet of 500 attacking nodes generating traffic over 10 capture days in February/March 2018.
- **Extraction Tool:** CICFlowMeter-V3.
- **Files Present:** 10 physical CSV files in `data/raw/cse_cic_ids2018/`.
- **Columns per File:** 80 columns (except `Thuesday-20-02-2018` which has 84 columns due to exporter metadata).
- **Total Raw Rows:** **16,233,002**.

#### Per-File Breakdown & Class Distribution

| File Name | Size (Bytes) | Rows | Cols | Attack Classes & Support | Benign Support | Primary SHA-256 Digest |
|:---|---:|---:|:---:|:---|---:|:---|
| `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` | 358,223,333 | 1,048,575 | 80 | `FTP-BruteForce`: 193,360<br>`SSH-BruteForce`: 187,589 | 667,626 | `d4e565ad0c406c57f2bb1797c55c862bc2b56e6d19335f60fcbb65d564fa0570` |
| `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` | 375,945,899 | 1,048,575 | 80 | `DoS-attacks-GoldenEye`: 41,508<br>`DoS-attacks-Slowloris`: 10,990 | 996,077 | `26da25a228fa48c08401340156ceeb03ce1cfd4218ebaf6b48529d3feea1cf99` |
| `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` | 333,723,605 | 1,048,575 | 80 | `DoS-attacks-SlowHTTPTest`: 139,890<br>`DoS-attacks-Hulk`: 461,912 | 446,773 | `9dc64a66a6a57c58850ce4ad0681ae80cf098fb58ea2874139e8020e9834ea27` |
| `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` | 4,054,925,350 | 7,948,748 | 84 | `DDoS attacks-LOIC-HTTP`: 576,191 | 7,372,557 | `9be910903328eef6004944ec7df2e2ffbc3b418a1a36fdcf2896c34538562723` |
| `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` | 328,893,673 | 1,048,575 | 80 | `DDOS attack-HOIC`: 686,012<br>`DDOS attack-LOIC-UDP`: 1,730 | 360,833 | `1b1380963f47e27300c0f6551b942e6120deae4dfeb098e9b62c1bd7e4112c3f` |
| `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` | 382,636,202 | 1,048,575 | 80 | `Brute Force -Web`: 249<br>`Brute Force -XSS`: 79<br>`SQL Injection`: 34 | 1,048,213 | `d8ff7ddf6bc7dcfcfb120be8e56214c72a818cbe7b8a78e71887e49fa37b1d4c` |
| `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` | 382,840,456 | 1,048,575 | 80 | `Brute Force -Web`: 362<br>`Brute Force -XSS`: 151<br>`SQL Injection`: 53 | 1,048,009 | `09fc34997157833075c2e3532726359f422eb7858c148ae8be63fa54bdf16410` |
| `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` | 209,249,758 | 613,104 | 80 | `Infilteration`: 68,871 | 544,233 | `5cf49581898aa2495d4653e0d8f7ceca2aa39265f2a1b9c97b82f64580bf39a6` |
| `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` | 107,842,858 | 331,125 | 80 | `Infilteration`: 93,063 | 238,037 | `e4b370605177aeb07be8feaa3c106cc0a74ea8e77a28cf1bc7c6888d3f78fb2a` |
| `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` | 352,368,373 | 1,048,575 | 80 | `Bot`: 286,191 | 762,384 | `d96f38e7496aba83475031e6fb8c6fdf1abf6aa1b71325a917798f3c7de93de1` |
| **Total / Summary** | **6,886,670,578** | **16,233,002** | **80–84** | **3,109,241 attacks (19.2%)** | **13,123,702 (80.8%)** | *All 10 files SHA-256 verified* |

#### Known Data-Quality Issues & Cleaning Protocol
1. **Memory & File Size:** The dataset spans 6.89 GB uncompressed, with `Thuesday-20-02-2018` alone reaching 4.05 GB (7,948,748 rows). Ingestion requires strict chunked streaming (`chunk_size=100_000`) and float32 downcasting to prevent Out-Of-Memory (OOM) failures.
2. **Missing & Infinite Values:** 49,085 cells with `NaN` in `Flow Byts/s`; 116,315 cells with `+Inf` across `Flow Byts/s` and `Flow Pkts/s`. Imputed using training-set medians.
3. **Repeated Header Rows:** String literal `"Label"` is embedded mid-file as data rows in several files (e.g., 59 rows total). These are rejected and dropped as `UNKNOWN`.
4. **Conflicting Feature Vectors:** 122,481 identical feature vectors across 4,496,789 rows share conflicting ground-truth labels (`BENIGN` vs `ATTACK`). Applying `reject_conflicts` eliminated all ambiguity.
5. **Deduplication:** Dropping duplicate vectors (2,944,601) and conflicts produces an audited modeling population of **8,312,295 rows** with zero cross-split vector leakage.

---

### 3.3. UNSW-NB15

- **Provider:** Cyber Range Lab of the Australian Centre for Cyber Security (ACCS), UNSW Canberra.
- **Official URL:** `https://research.unsw.edu.au/projects/unsw-nb15-dataset`
- **Acquisition Source:** Recognized mirror of UNSW Canberra Cyber, verified via SHA-256 (`recognized_mirror`).
- **Capture Environment:** An IXIA PerfectStorm testbed simulating realistic normal user traffic mixed with contemporary synthetic CVE exploits across a hybrid synthetic/real test network.
- **Extraction Tools:** Argus and Bro/Zeek network analysis tools.
- **Files Present:** 2 modeling CSV files in `data/raw/unsw_nb15/`.
- **Columns per File:** 45 columns (42 features + `attack_cat`, `label`, `id`).
- **Total Raw Rows:** **257,673**.

#### Per-File Breakdown & Class Distribution

| File Name | Size (Bytes) | Rows | Cols | Attack Classes & Support | Normal Support | Primary SHA-256 Digest |
|:---|---:|---:|:---:|:---|---:|:---|
| `UNSW_NB15_training-set.csv` | 32,293,018 | 175,341 | 45 | `Generic`: 40,000<br>`Exploits`: 33,393<br>`Fuzzers`: 18,184<br>`DoS`: 12,264<br>`Reconnaissance`: 10,491<br>`Analysis`: 2,000<br>`Backdoor`: 1,746<br>`Shellcode`: 1,133<br>`Worms`: 130 | 56,000 | `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa` |
| `UNSW_NB15_testing-set.csv` | 15,380,800 | 82,332 | 45 | `Generic`: 18,871<br>`Exploits`: 11,132<br>`Fuzzers`: 6,062<br>`DoS`: 4,089<br>`Reconnaissance`: 3,496<br>`Analysis`: 677<br>`Backdoor`: 583<br>`Shellcode`: 378<br>`Worms`: 44 | 37,000 | `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559` |
| **Total / Summary** | **47,673,818** | **257,673** | **45** | **164,673 attacks (63.9%)** | **93,000 (36.1%)** | *Both files SHA-256 verified* |

#### Known Data-Quality Issues & Cleaning Protocol
1. **Auxiliary Metadata:** `UNSW-NB15_LIST_EVENTS.csv` is absent (`DATA_NOT_AVAILABLE`). This is an event-level description file not required for flow modeling.
2. **Conflicting Vectors:** 558 conflicting feature vectors across 29,410 rows exhibit contradictory labels.
3. **Deduplication:** Dropping duplicate vectors (102,136) and conflicts produces an audited modeling population of **122,520 rows** with zero cross-split duplicate leakage.
4. **Missing Transport Columns:** Argus logs omit granular TCP flag counts and packet size standard deviations, requiring the R4 contract fallback.

---

## 4. The Canonical R10 Feature Contract (Decision D-002)

To prevent models from memorizing environment-specific network topology (such as IP addresses, MAC addresses, socket port numbers, or absolute capture timestamps), Decision D-002 established the **Canonical 10-Feature R10 Contract**.

Each of the 10 features was selected based on strict mathematical defensibility, empirical importance, and real-time computability:

| # | Feature Name | Canonical Mathematical Definition | Cybersecurity Rationale & Attack Discriminability |
|:---:|:---|:---|:---|
| **1** | `flow_duration_ms` | $T_{\text{last}} - T_{\text{first}}$ (milliseconds) | Distinguishes transient, high-rate events (port scans, SYN floods lasting <10 ms) from sustained sessions (interactive shells, data exfiltration, slowloris). |
| **2** | `flow_packets_per_s` | $N_{\text{packets}} / (D_{\text{sec}} + \epsilon)$ | Primary volumetric metric. Detects high-rate volumetric DoS/DDoS, brute-force automation, and rapid scanning activity. |
| **3** | `flow_bytes_per_s` | $B_{\text{total}} / (D_{\text{sec}} + \epsilon)$ | Measures data throughput intensity. Identifies large-volume data exfiltration, buffer overflow payloads, and bandwidth exhaustion attacks. |
| **4** | `packet_length_mean` | $\frac{1}{N} \sum_{i=1}^N L_i$ | Detects structural anomalies in protocol usage (e.g., oversized HTTP GET requests, uniform ICMP/UDP flood sizing). |
| **5** | `packet_length_std` | $\sqrt{\frac{1}{N-1} \sum_{i=1}^N (L_i - \bar{L})^2}$ | Crucial behavioral signature. Benign browsing exhibits high variance (mixed text, images, ACK headers); automated attack bots typically emit uniform packets (low variance) or bimodal floods. |
| **6** | `syn_count` | $\sum_{i=1}^N \mathbb{I}(\text{SYN} \in \text{Flags}_i)$ | Key transport metric for connection establishment. Detects TCP SYN flood DoS, TCP half-open stealth scans, and mass-connect attempts. |
| **7** | `ack_count` | $\sum_{i=1}^N \mathbb{I}(\text{ACK} \in \text{Flags}_i)$ | Reflects session progression. Distinguishes completed TCP handshakes and data flows from one-way unacknowledged probing. |
| **8** | `rst_count` | $\sum_{i=1}^N \mathbb{I}(\text{RST} \in \text{Flags}_i)$ | Immediate indicator of network rejection, closed-port scanning, connection resets, and evasion attempts. |
| **9** | `fin_count` | $\sum_{i=1}^N \mathbb{I}(\text{FIN} \in \text{Flags}_i)$ | Normal connection termination indicator. Absence or imbalance reveals abrupt session teardowns and unfinished connections. |
| **10** | `syn_ack_ratio` | $(\text{SYN} + 1) / (\text{ACK} + 1)$ | Invariant transport balance metric. Benign TCP sessions maintain balanced SYN/ACK ratios (~1.0); SYN flooding and scanning drive this ratio to extreme values (>10.0 to $\infty$). |

### Why R10 Over R15 / R20?
1. **Information Sufficiency:** TreeSHAP attribution and empirical feature ablation confirm that R10 captures >90% of the predictive variance across CIC-IDS2017 and CSE-CIC-IDS2018.
2. **Topological Invariance:** Excludes IP addresses, MAC addresses, port numbers, and timestamps, preventing data leakage across train and test partitions (`L-02` pass).
3. **Execution Parity:** All 10 features can be computed in pure Python from streaming packet captures under Decision D-006 with strict numerical parity ($\text{atol} \le 10^{-4}$).

---

## 5. The UNSW-NB15 R4 Fallback & Impossibility of Feature Fabrication

### The Structural Incompatibility
UNSW-NB15 was created using **Argus** and **Bro/Zeek**, not **CICFlowMeter**. Argus NetFlow records capture flow-level aggregates but omit packet-level flag sequences and sub-flow variance metrics.

Specifically, 6 of the 10 R10 features are **physically absent** from the UNSW-NB15 dataset:
1. `packet_length_std` (standard deviation of packet lengths)
2. `syn_count` (TCP SYN count)
3. `ack_count` (TCP ACK count)
4. `rst_count` (TCP RST count)
5. `fin_count` (TCP FIN count)
6. `syn_ack_ratio` (SYN to ACK ratio)

### Why Fabrication is Strictly Forbidden
- **Scientific Integrity:** Imputing missing flags (e.g. setting SYN=0 or median imputation) or synthesizing packet length standard deviations creates ungrounded mathematical artifacts. Models evaluated on fabricated features learn classifier boundaries on artificial numbers, not real network traffic.
- **Validating Tool Heterogeneity:** In real-world enterprise deployments, telemetry often originates from heterogeneous sensors (Zeek, NetFlow, IPFIX) that do not provide full packet flag inspections.
- **The R4 Contract:** Under Decision D-002, UNSW-NB15 is evaluated under the native **4-Feature Contract (R4)**:
  - `flow_duration_ms`
  - `flow_packets_per_s`
  - `flow_bytes_per_s`
  - `packet_length_mean`
- Evaluating UNSW-NB15 under R4 allows honest benchmarking of volumetric and duration features while demonstrating that lack of transport flag context degrades transfer performance (F1 collapse in cross-dataset transfer, answering RQ5).

---

## 6. Dataset Audit Summary Table

Summary across all audited benchmark populations:

| Metric / Audit Field | CIC-IDS2017 | CSE-CIC-IDS2018 | UNSW-NB15 | Combined Total |
|:---|---:|---:|---:|---:|
| **Physical Files** | 8 | 10 | 2 | **20 files** |
| **Columns per File** | 79 | 80–84 | 45 | **45–84 columns** |
| **Raw Records** | 2,830,743 | 16,233,002 | 257,673 | **19,321,418 rows** |
| **Duplicate Raw Rows** | 256,479 | 410,706 | 0 | **667,185 rows** |
| **Contradictory Label Rows** | 0 | 4,496,789 | 29,410 | **4,526,199 rows** |
| **Deduplicated Modeling Population** | **1,779,322** | **8,312,295** | **122,520** | **10,214,137 rows** |
| **Feature Contract Applied** | R10 (10 features) | R10 (10 features) | R4 (4 features) | — |
| **Split Leakage (`L-01` / `L-02`)** | **0 shared vectors (PASS)** | **0 shared vectors (PASS)** | **0 shared vectors (PASS)** | **100% Leakage-Free** |
| **Audit Artifact Path** | `results/audits/cicids2017_audit.json` | `results/audits/cse_cic_ids2018_audit.json` | `results/audits/unsw_nb15_audit.json` | `results/audits/dataset_summary.json` |
