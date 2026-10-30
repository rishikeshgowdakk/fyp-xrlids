# XRL-IDARS — Response Policy & Cost Optimization

**Document ID:** `DOC-RESP-POLICY-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Discrete Mitigation Action Space

| Action ID | Action Constant | Mitigation Description | Operational Cost | Intended Threat Scenario |
| :---: | :--- | :--- | :---: | :--- |
| **0** | `NO_ACTION` | Allow flow traffic without modification | $0.0$ | Benign flows or low-confidence noise |
| **1** | `RATE_LIMIT` | Token-bucket rate-limiting (100 pkts/s) | $2.0$ | Moderate scans or low-rate DoS bursts |
| **2** | `QUARANTINE_IP` | Drop all ingress packets from host IP | $10.0$ | Confirmed high-rate floods and brute force |
| **3** | `DEEP_INSPECTION`| Mirror host flows to PCAP/DPI queue | $0.5$ | Suspicious web attacks, SQLi, XSS |

---

## 2. Advisory Mode Mechanics

In standard operational deployment, the response system functions in **Advisory / Dry-Run Mode**:
1. When a threat is detected, the DQN policy evaluates $Q(s, a)$ and proposes action $a^*$.
2. The proposal passes through the `DeterministicSafetyGate`.
3. If approved, the action is logged as an `EnforcedActionRecord` and streamed to the telemetry dashboard.
4. **Zero kernel network rules (`iptables`, `nftables`) are altered**.
5. Network operators review the recommendations in real time with full contextual TreeSHAP explanations before approving permanent network ACL changes.
