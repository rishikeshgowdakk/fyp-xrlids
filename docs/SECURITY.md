# XRL-IDARS — Security Model & Threat Assessment

**Document ID:** `DOC-OPS-SECURITY-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Security Architecture Principles

1. **Advisory by Default**: All automated defensive actions execute in dry-run mode unless an explicit command-line override is supplied in an isolated testbed.
2. **Deterministic Fail-Safe**: When safety gates or model inferences encounter unexpected exceptions, the system defaults to `NO_ACTION` rather than unconstrained blocking.
3. **No Shell Invocations**: Linux network actuators use direct system APIs or explicit parameterized subprocess calls without `shell=True`.
4. **Zero Credentials**: The codebase contains zero API tokens, AWS secret keys, or private certificates.

---

## 2. Threat Analysis & Defensive Mitigations

| Threat Vector | Attack Scenario | System Defense Mechanism |
| :--- | :--- | :--- |
| **State Exhaustion** | Attacker floods network with randomized spoofed source IPs | Bounded flow tables with LRU eviction and 1.0s idle timeouts |
| **Queue Saturation** | Packet arrival exceeds Python processing capacity ($> 10\,\text{kpps}$) | Bounded `Queue(maxsize=10000)` with non-blocking packet drops |
| **Model Poisoning** | Attacker transmits crafted packets with NaN/Inf float payloads | Strict schema validation catches non-finite values before inference |
| **Collateral Outage** | Reinforcement learning policy attempts to isolate core DNS server | `Critical Host Allowlist` instantly overrides quarantine to `NO_ACTION` |
| **Response Flapping** | Rapid alternating blocking/unblocking degrades TCP sessions | `Host Cooldown Hysteresis` forces 30-step stabilization window |
| **Mass Blackout** | Distributed flood triggers policy to quarantine all local subnets | `Blast Radius Circuit Breaker` caps quarantined endpoints at $\le 5\%$ |
