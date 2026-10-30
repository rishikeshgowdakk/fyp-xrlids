# XRL-IDARS — Benchmark Dataset Provenance & Taxonomy

**Document ID:** `DOC-ML-DATASETS-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Overview of Evaluated Benchmarks

XRL-IDARS evaluates three canonical network intrusion detection benchmarks:

```
data/raw/
├── cicids2017/          # 8 CSV files (ISCX 2017, Canadian Institute for Cybersecurity)
├── cse_cic_ids2018/     # 10 CSV files (AWS CSE-CIC-IDS2018)
└── unsw_nb15/           # 2 CSV files (UNSW-NB15 Training and Testing sets)
```

---

## 2. Benchmark Suite Descriptions

### 1. CIC-IDS2017 (Canadian Institute for Cybersecurity)
- **Files**: 8 raw CSV files covering 5 days of captured traffic (Monday through Friday).
- **Total Flow Count**: $\approx 2,830,743$ flows.
- **Key Characteristics**: Comprehensive multi-attack capture (DDoS, DoS, PortScan, Web Attacks, Infiltration, Botnet). 
- **Limitations**: Endpoint IP addresses were anonymized/stripped out in published CSVs; timestamps exhibit minor timezone drifts.

### 2. CSE-CIC-IDS2018 (Communications Security Establishment & CIC)
- **Files**: 10 raw CSV files captured on Amazon Web Services (AWS) infrastructure.
- **Total Flow Count**: $\approx 16,233,002$ flows.
- **Key Characteristics**: Large-scale enterprise cloud network capture.
- **Sequence Feasibility**: **Tuesday 20-02-2018** (`Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`, 3.86 GB, 7.94M flows) is the **only benchmark file containing valid source/destination IP addresses and parseable monotonic timestamps**. All other 9 files have stripped IPs.

### 3. UNSW-NB15 (Australian Cyber Security Centre)
- **Files**: Official pre-split `UNSW_NB15_training-set.csv` (175,341 flows) and `UNSW_NB15_testing-set.csv` (82,332 flows).
- **Key Characteristics**: Contains synthetic modern attack families (Fuzzers, Analysis, Backdoors, Exploits, Generic, Reconnaissance, Shellcode, Worms).
- **Limitations**: Lacks packet-level TCP flag counters; evaluated under the **R4 feature contract**.

---

## 3. Canonical 17-Family Attack Taxonomy

XRL-IDARS maps all benchmark labels into a unified 17-family taxonomy:
1. `BENIGN`
2. `DDoS-LOIC-HTTP`
3. `DDoS-LOIC-UDP`
4. `DDoS-HOIC`
5. `DoS-Slowloris`
6. `DoS-SlowHTTPTest`
7. `DoS-Hulk`
8. `DoS-GoldenEye`
9. `Heartbleed`
10. `FTP-BruteForce`
11. `SSH-Bruteforce`
12. `Web-BruteForce`
13. `Web-XSS`
14. `Web-SQL-Injection`
15. `Infiltration`
16. `Botnet`
17. `PortScan`
