# Experiment Artifact: EXP-P3-BURST-1000-001

**Experiment Identifier**: `EXP-P3-BURST-1000-001`  
**Git Commit**: `724969ae24b17e6fc09d8a7646c2e81de4d46dc6`  
**Date**: 2026-10-04  
**Operational Mode**: `LiveMode.DRY_RUN` (Zero System Mutation)  

## Purpose
Controlled stress test characterizing the component-level latency distributions and processing throughput of the end-to-end XRL-IDARS live pipeline under a 1000-packet traffic burst ("1000 packets from one click").

## Key Findings
- **Packets Processed**: 1000 / 1000 (100% consumed, 0 drops, 0 malformed)
- **Flows Processed**: 270 completed flows (40 benign + 10 attack)
- **Effective Throughput**: 73.3 pkts/s (19.8 flows/s)
- **Flow Pipeline Latency (P50)**: 49960.89 µs
- **Zero Network Mutation**: VERIFIED (no iptables, nftables, or route changes)
