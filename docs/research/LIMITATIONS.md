# XRL-IDARS — Research Limitations & Scope Boundaries

**Document ID:** `DOC-RES-LIMITATIONS-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Technical & Engineering Limitations

1. **Python Ingestion Throughput Ceiling**:
   - The packet capture layer utilizes Python Scapy and standard Linux AF_PACKET sockets.
   - Sustainable capture throughput is bounded at $\approx 2,000 \to 5,000\,\text{packets/sec}$ on standard x86_64 CPUs.
   - It is not designed to operate at 10 Gbps / 40 Gbps hardware line rates (which require kernel bypass frameworks like DPDK or eBPF/XDP).

2. **Payload Opacity under Modern TLS**:
   - The system intentionally restricts inspection to transport-layer metadata (IP, TCP/UDP headers, flow timing, and packet lengths).
   - It does not perform TLS decryption or deep packet inspection (DPI) into encrypted application payloads.

3. **Benchmark Dataset Temporal Incompleteness**:
   - As documented in `docs/evaluation/DATASET_ELIGIBILITY.md`, only 1 out of 20 benchmark files contains the network identifiers required for sequence modeling.
   - Consequently, temporal models cannot be validated across 16 of the 17 attack families.

4. **Reinforcement Learning Environment Scope**:
   - The Dueling DQN policy was trained within a simulated Markov Decision Process (MDP) parameterized by empirical traffic statistics rather than a live multi-tenant production enterprise network.
   - Hence, all enforcement actions must remain in **Advisory / Dry-Run Mode** in real network environments.
