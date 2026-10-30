# Unified Attack Taxonomy & Cross-Dataset Mapping
**Project:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Artifact ID:** `TAXONOMY-ATTACK-MAPPING-001`  
**Classification:** Scientific Classification Reference  
**Status:** COMPLETE & FROZEN  

---

## 1. Canonical Taxonomy Structure

To eliminate confusion between disparate vendor labels and academic datasets, XRL-IDARS establishes 8 canonical high-level attack families:

1. **`DoS` (Denial of Service):** Targeted resource exhaustion against an individual service daemon (Hulk, GoldenEye, Slowloris, SlowHTTPTest).
2. **`DDoS` (Distributed Denial of Service):** Volumetric bandwidth or reflection floods from multiple distributed agents (LOIC-HTTP, LOIC-UDP, HOIC).
3. **`PortScan`:** Systematic horizontal or vertical TCP/UDP port probing and reconnaissance.
4. **`BruteForce`:** High-frequency authentication credential guessing against administrative protocols (FTP-Patator, SSH-Patator, Telnet).
5. **`Bot`:** Command-and-control communication, infected bot beacons, and botnet coordination (ARES Botnet).
6. **`Web`:** Application-layer exploits including SQL Injection, Cross-Site Scripting (XSS), and Web Authentication Brute Force.
7. **`Infiltration`:** Post-exploitation interactive lateral movement, remote shell execution, and Dropbox/Meterpreter command sessions.
8. **`UNKNOWN`:** Sub-threshold confidence $(<0.40)$ or unmapped novel anomaly.

---

## 2. Multi-Dataset Attack Mapping Matrix

The mapping is formalized in `configs/labels/label_mapping.yaml` and applied deterministically during ingestion:

| Canonical Family | CIC-IDS2017 Raw Label | CSE-CIC-IDS2018 Raw Label | UNSW-NB15 Raw Category | Invariant Rule Safeguard |
|:---|:---|:---|:---|:---|
| **`DoS`** | `DOS HULK`<br>`DOS GOLDENEYE`<br>`DOS SLOWLORIS`<br>`DOS SLOWHTTPTEST` | `DOS ATTACKS-HULK`<br>`DOS ATTACKS-SLOWHTTPTEST`<br>`DOS ATTACKS-GOLDENEYE`<br>`DOS ATTACKS-SLOWLORIS` | `DoS` | Rate limit & half-open connection tracking |
| **`DDoS`** | `DDOS` | `DDOS ATTACK-HOIC`<br>`DDOS ATTACK-LOIC-UDP`<br>`DDOS ATTACKS-LOIC-HTTP` | `DoS` (Subset) | Volumetric threshold escalation |
| **`PortScan`** | `PORTSCAN` | Relegated to Recon / Background | `Reconnaissance` | TCP SYN-FIN / NULL / XMAS illegal flag rules |
| **`BruteForce`** | `FTP-PATATOR`<br>`SSH-PATATOR` | `FTP-BRUTEFORCE`<br>`SSH-BRUTEFORCE` | `Generic` / `Exploits` | Multi-flow Source Tracker escalation ($\ge 5$ flows) |
| **`Bot`** | `BOT` | `BOT` | `Backdoor` | Periodic inter-arrival timing analysis |
| **`Web`** | `WEB ATTACK - BRUTE FORCE`<br>`WEB ATTACK - XSS`<br>`WEB ATTACK - SQL INJECTION` | `BRUTE FORCE -WEB`<br>`BRUTE FORCE -XSS`<br>`SQL INJECTION` | `Exploits` | Application layer proxy inspection |
| **`Infiltration`**| `INFILTRATION` | `INFILTERATION` | `Backdoor` / `Shellcode` | Multi-flow Source Activity Tracker |
| **`Heartbleed`** | `HEARTBLEED` | Unrepresented | `Exploits` | Zero payload retention protocol rules |
| **`Other / Novel`**| Unmapped labels | Unmapped labels | `Fuzzers`, `Analysis`, `Worms` | Calibrated `UNKNOWN` fallback |
