# The "1000 packets from one click" case

Status: **skeleton — experiment not yet run.**

## The professor's question

> If a user clicks once and 1000 packets go out, does the system call that an attack?

## The answer this document must demonstrate

> **Packet count ≠ maliciousness.**

A single legitimate browser click can produce a burst of many packets. A volume-only detector
would flag it. XRL-IDARS classifies **flow behaviour**, which is why the feature contract must
carry behavioural context, not just volume.

## What must be shown (with real measurements)

| Signal | Why it matters | Measured value |
| --- | --- | --- |
| Packet count | The naive signal | |
| Packet rate | Volume per time, not volume alone | |
| Byte rate | Distinguishes bulk transfer from many tiny packets | |
| Flow duration | A burst is short; a flood is sustained | |
| Packet size distribution | Legitimate bursts and floods differ in size mix | |
| TCP flags | SYN-only = scan shape; ACK/FIN pattern = connection lifecycle | |
| Directionality | Bidirectional request/response vs unidirectional flood | |
| Temporal behaviour | Inter-arrival regularity | |
| Model score | rf / lstm / fusion | |
| Action | what the DQN recommended and what the safety layer allowed | |

## Experiment plan

1. Generate a legitimate browser-like burst of ~1000 packets in the isolated lab.
2. Capture it, build flows, extract the canonical behavioural features.
3. Run the full detector chain and record scores.
4. Compare against a genuinely malicious high-volume flow (controlled, labelled).
5. Show which features separate them, and whether the model separates them.

## Evidence to record

- lab topology and traffic generator configuration
- packet capture (not committed if it contains environment addresses)
- extracted feature values for both bursts
- model scores and final action
- an explicit statement of what the experiment does **not** prove

## Status

⬜ Not run. Blocked on: feature contract (D-002), live capture (Phase 3), flow policy (D-006).
