# XRL-IDARS — Deterministic Safety Gate Model

**Document ID:** `DOC-RESP-SAFETY-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Safety Gate Architecture

The `DeterministicSafetyGate` acts as a non-bypassable policy firewall positioned between the reinforcement learning agent and the network actuators:

```
Proposed Action a* (from DQN)
              |
              v
[Invariant 1: Critical Host Allowlist]   --> Override: Force NO_ACTION
              | (Passed)
              v
[Invariant 2: Host Cooldown Check]       --> Override: Force NO_ACTION
              | (Passed)
              v
[Invariant 3: Blast Radius Breaker]      --> Override: Demote to RATE_LIMIT
              | (Passed)
              v
[Invariant 4: Dry-Run Actuation]         --> Log Advisory Event (Zero Kernel Mutation)
```

---

## 2. Mathematical Specification of Safety Invariants

### 1. Critical Host Allowlist
$$\text{If } \text{host\_ip} \in \mathcal{S}_{\text{critical}} \implies a_{\text{enforced}} = \text{NO\_ACTION}$$
Prevents disconnection of default gateways, DNS resolvers, and critical monitoring servers during spoofed attacks.

### 2. Host Cooldown Hysteresis
$$\text{If } (t_{\text{current}} - t_{\text{last\_mitigated}}) < T_{\text{cooldown}} \implies a_{\text{enforced}} = \text{NO\_ACTION}$$
Enforces a 30-step stabilization window to prevent flapping network sockets.

### 3. Blast-Radius Circuit Breaker
$$\text{If } \frac{|\mathcal{H}_{\text{quarantined}} \cup \{\text{host\_ip}\}|}{|\mathcal{H}_{\text{monitored}}|} > 0.05 \implies a_{\text{enforced}} = \text{RATE\_LIMIT}$$
Limits concurrently quarantined endpoints to $5\%$ of total monitored hosts, preventing mass self-inflicted Denial of Service.
