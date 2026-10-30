# XRL-IDARS — Deployment Architecture & Operational Modes

**Document ID:** `DOC-OPS-DEPLOYMENT-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Supported Deployment Topologies

XRL-IDARS supports three primary operational topologies:

```
[Topology A: Offline PCAP & CSV Replay Workbench]
  Recorded PCAP / CSV --> ReplayEngine --> FlowBuilder --> RF Detector --> Dashboard

[Topology B: Controlled Lab Simulation]
  Scapy Packet Generator --> veth0/lo Socket --> IngestionQueue --> Pipeline --> Dashboard

[Topology C: Passive Network TAP / Mirror Port]
  Physical Switch Mirror Port --> Promiscuous NIC (eth1) --> AF_PACKET --> Pipeline --> Advisory Dashboard
```

---

## 2. Privileges & Network Capabilities

- **Passive Sniffing**: To capture packets without running the entire process as root, grant the Python binary raw socket capabilities:
  ```bash
  sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f .venv/bin/python)
  ```
- **Zero Firewall Mutation**: The application never runs destructive `sudo iptables` commands by default. All mitigations are rendered in `ADVISORY / DRY_RUN` mode.

---

## 3. Production Resource Footprint

- **CPU Utilization**: $\approx 15 \to 30\%$ on a single modern x86_64 CPU core during $1,000\,\text{pps}$ packet streams.
- **Memory (RAM)**: $\approx 250 \to 400\,\text{MB}$ resident set size (RSS) under continuous operation.
- **Disk I/O**: Zero ongoing disk writes when logging is set to in-memory ring buffers.
