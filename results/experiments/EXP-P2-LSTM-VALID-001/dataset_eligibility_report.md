# Dataset Eligibility Report: Sequence Modeling & Temporal Validation

**Experiment ID:** EXP-P2-LSTM-VALID-001  
**Project:** XRL-IDARS (Final Year Engineering Project)  
**Standard:** Senior Network Security ML Engineering Audit  
**Date:** 2026-10-30  

---

## 1. Executive Summary

A forensic dataset schema and capability audit was conducted across all benchmark datasets currently present in `data/raw/` (20 CSV files totaling 7.68 GB). The objective was to determine which datasets can legitimately support host-aware, chronological sequence construction ($K=5$ flows) without fabricating IP addresses, flow timestamps, or artificial sequence relationships.

**Key Finding:** Out of 20 benchmark CSV files, **only one single file** (`data/raw/cse_cic_ids2018/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`, 7,948,748 flows) contains the complete 5-tuple (`Src IP`, `Dst IP`, `Src Port`, `Dst Port`, `Protocol`), real chronological timestamps, and ground-truth attack labels. All other 19 CSV files lack IP addresses, timestamps, or full R10 features.

---

## 2. Comprehensive Dataset Eligibility Matrix

| Dataset | Raw File Path(s) | Features Available | Timestamps Available? | Host / IP Identifiers Available? | Genuine Chronological Sequences Possible? | Leakage-Resistant Splits Possible? | Eligibility Status | Detailed Engineering Rationale |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **CIC-IDS2017** | `data/raw/cicids2017/*.csv`<br>(8 files, 844 MB) | Full R10 Contract (10 features) | ❌ Non-viable (Strings like `07:02:00` without dates or ms precision; non-monotonic across files) | ❌ **ABSENT** (`Src IP`, `Dst IP`, `Src Port` stripped by ISCX) | ❌ **IMPOSSIBLE** (Cannot identify host continuity) | ❌ No temporal boundary possible | **INELIGIBLE** | Public ISCX CSVs lack source and destination IP addresses and ports. Sequences cannot be grouped by host or session. Forming sequences from row adjacency causes artificial clustering artifacts. |
| **UNSW-NB15** | `data/raw/unsw_nb15/*.csv`<br>(2 files, 46 MB) | ❌ R4 Contract only (4 features; lacks TCP flag counts) | ❌ **ABSENT** (No timestamp column in training/testing sets) | ❌ **ABSENT** (No IP columns in training/testing sets) | ❌ **IMPOSSIBLE** | ❌ Pre-split by dataset creators without temporal metadata | **INELIGIBLE** | Contains only connection statistics and service names. Missing individual TCP flag counts (SYN, ACK, RST, FIN), missing all IP addresses, and missing timestamps. Cannot be used for R10 or temporal sequence modeling. |
| **CSE-CIC-IDS2018 (Tuesday)** | `data/raw/cse_cic_ids2018/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`<br>(1 file, 3.8 GB) | Full R10 Contract (10 features) + temporal delta ($11\text{D}$) | ✅ **PRESENT** (`20/02/2018 08:34:07`, 1-second resolution, 08:30 to 14:00 UTC) | ✅ **PRESENT** (Complete 5-tuple: `Src IP`, `Dst IP`, `Src Port`, `Dst Port`, `Protocol`) | ✅ **GENUINE** ($K=5$ flows per `Src IP`, start-time ordered) | ✅ **STRICT** (Chronological time-splits + 300s purge buffers + unseen attacker IP holdout) | **ELIGIBLE** | Only dataset in repository with full 5-tuple network provenance and valid temporal resolution. Contains 7,948,748 genuine flow records with confirmed LOIC-HTTP volumetric attack bursts. |
| **CSE-CIC-IDS2018 (Other 9 Days)** | `data/raw/cse_cic_ids2018/*.csv`<br>(9 files, 2.7 GB) | Full R10 Contract (10 features) | ✅ String timestamps | ❌ **ABSENT** (`Src IP` and `Dst IP` stripped by CICFlowMeter in these 9 files) | ❌ **IMPOSSIBLE** (Cannot group by host) | 🟡 Time-based only | **INELIGIBLE** | Only `Dst Port` and `Protocol` were retained; IP addresses were omitted. While time-ordered splits are possible, host-level sequence buffering is mathematically impossible without IPs. |

---

## 3. Methodological Conclusion

1. **CIC-IDS2017 and UNSW-NB15 are strictly ineligible** for temporal sequence modeling. Any attempt to construct sequences from their CSV files relies on artificial row adjacency after random permutation, which does not represent real network traffic.
2. **Tuesday CSE-CIC-IDS2018 is the sole scientifically valid dataset** in the repository for training and evaluating an independent temporal LSTM detector against Random Forest.
