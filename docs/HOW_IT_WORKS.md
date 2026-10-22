# How the XRL-IDARS System Works — End to End

*Written 2026-10-19. Audience: Part 1 is for anyone; Part 2 is the detailed engineering view.
Every claim below can be re-checked with the commands in Part 2.9.*

---

## 0. The one thing to know first: what is real and what is synthetic

The dashboard has **three different kinds of traffic**, and only one of them is real:

| Mode / feature | What it actually is | Does it touch the network? | IP addresses you see |
|---|---|---|---|
| **Sample stream** (default demo, `--sample`) | Replay of a bundled **synthetic** file: `data/demo/sample_traffic.pcap`, 42 packets, generated in code by `scripts/demo/run_replay_demo.py` | **No.** Nothing is sent or received; the file is read and restamped to "now" | Fictional demo LAN `192.168.1.50` / `192.168.1.10`, fake attacker `10.0.0.99`, and cosmetic public IPs `8.8.8.8`, `142.250.190.46`, `104.16.132.229` |
| **Attack Simulator** (button in the Live Monitor tab) | In-memory packet scripts from `src/xrlids/demo/attack_sim.py`, pushed straight into the detection pipeline | **No.** Packets are never transmitted — they are injected *inside* the program | RFC 5737 documentation range `203.0.113.x` on purpose, so they can never collide with real hosts |
| **Live capture** (opt-in: `sudo … --live --iface <name>`) | **REAL packets** from this machine's NIC via an AF_PACKET raw socket | **Read-only.** Captures real traffic; never sends, drops, or modifies anything | Your real network — on this laptop: WiFi `wlo1 = 192.168.0.109/24`, gateway `192.168.0.1` |
| **Devices Observed on WiFi** (live mode panel) | Passive ARP/DHCP/mDNS/SSDP metadata plus the local neighbour cache, from the same real frames | **Read-only.** No ARP scans, pings, probes, or router login | Real device IP/MAC/vendor/hostname where observable; **not** the access point's full association table |

Two independent proofs that the sample stream is synthetic, not captured:

1. It contains a **5,880-byte packet**. The largest possible Ethernet/WiFi frame is 1,514 bytes,
   so no real capture can contain it. (The file's packet lengths: `40, 66, 94, 96, 104, 170, 340,
   490, 840, 1240, 1500, 5880`.)
2. The addresses (`192.168.1.x`, `10.0.0.99`) belong to no real network here — this laptop's WiFi
   is `192.168.0.0/24`.

**So: if you saw IPs like `192.168.1.10` or `203.0.113.66` in the dashboard, those were demo/replay
addresses by design — none of them came from your WiFi. Real WiFi traffic appears only after you
start live capture yourself with `sudo` (Part 2.8).**

```bash
# Real WiFi capture (you run this — it needs root):
sudo .venv/bin/python dashboard/server.py --live --iface wlo1
```

---

## Part 1 — The simple version (60-second read)

The system watches network traffic and answers one question per conversation:
**"does this conversation look like an attack?"**

```
Real WiFi packets            (live mode, sudo)
      or                     ─────────────────►  ┌──────────────┐
42-packet synthetic replay   (sample mode)        │ 1. Capture   │  packets
      or                                          └──────┬───────┘
in-memory simulator packets  (simulator)                │
                                                        ▼
                                               ┌──────────────────┐
                                               │ 2. Flow assembly │  group packets into
                                               │    ("D-006")     │  bidirectional conversations
                                               └──────┬───────────┘
                                                      │ one row per finished conversation
                                                      ▼
                                               ┌──────────────────┐
                                               │ 3. Features      │  summarize each flow
                                               │    ("R10")       │  with 10 numbers
                                               └──────┬───────────┘
                                                      ▼
                                               ┌──────────────────┐
                                               │ 4. Frozen model  │  trained Random Forest
                                               │    (CIC-IDS2017) │  says: attack probability 0…1
                                               └──────┬───────────┘
                                                      ▼
                                               ┌──────────────────┐
                                               │ 5. Dashboard     │  flows, scores, alerts,
                                               │    (browser)     │  suggested action (display only)
                                               └──────────────────┘
```

1. **Capture** — packets arrive either from your real WiFi/Ethernet card (live mode), from the
   bundled demo file (sample mode), or from the attack simulator (button).
2. **Flow assembly** — packets are grouped into *flows*: one bidirectional "conversation" between
   two endpoints (e.g. your laptop ↔ a web server). A flow **finishes** when a TCP connection
   closes (FIN/RST packet) or when 120 seconds pass with no more packets.
3. **Features** — every finished flow is summarized by exactly **10 numbers** (duration, packets
   per second, bytes per second, mean/std packet size, and the counts of SYN/ACK/RST/FIN flags).
   These are the same 10 numbers ("R10") the models were trained on.
4. **Model** — a **frozen, already-trained** Random Forest (trained offline on CIC-IDS2017) reads
   the 10 numbers and outputs a probability between 0 and 1 that the flow is an attack. Nothing is
   re-trained while monitoring.
5. **Dashboard** — every finished flow appears in the "Live Flows" table with its score
   (e.g. `0.991 → ATTACK`). Flows scoring ≥ 0.50 additionally appear in "Alerts" with a level:
   **HIGH** (≥ 0.85), **MEDIUM** (≥ 0.65), **LOW** (≥ 0.50). A banner shows new alerts, the
   **Detected Attack Sources** panel aggregates alerting IPs, and the **features** button on each
   alert shows the exact 10 numbers the model received plus its output. The "Policy Suggestion
   (NOT enforced)" column is a *label for what a future response stage could do* — the dashboard
   itself never blocks anything.
6. **Speed** — scoring a flow takes milliseconds; the visible delay is only how long the
   conversation itself takes to finish (a slow attack that lasts 3 seconds appears after 3 seconds).

What the system **never** does: send packets, block traffic, change firewall/routing, or claim
accuracy on live traffic (live traffic has no ground-truth labels).

What "attack simulator injection" means: the simulator creates packet descriptions *inside memory*
and inserts them into step 2 of the pipeline as if they had been captured. The model then scores
them for real. The packets never exist on any wire — that is why they can use documentation IPs
(`203.0.113.x`) safely.

---

## Part 2 — The detailed version

### 2.1 Two pipelines: offline training vs. online monitoring

**Offline (done once, results frozen):** raw datasets → cleaning/audits → modeling populations →
model training → frozen artifacts. The dashboard consumes one frozen artifact set:

| Item | Value |
|---|---|
| Datasets (raw) | CIC-IDS2017: 2,830,743 rows / 8 files · CSE-CIC-IDS2018: 16,233,002 / 10 · UNSW-NB15: 257,673 / 2 |
| Final modeling populations | 1,779,322 (CIC) + 8,312,295 (CSE) + 122,520 (UNSW) = 10,214,137 rows |
| Model used live | Frozen CIC-IDS2017 Random Forest, `results/experiments/EXP-P1-CIC2017-R10-001/random_forest.joblib` |
| Preprocessing used live | Frozen preprocessor, `…/preprocessor.joblib` (same transform as at training time) |
| Feature contract | "R10" — the 10 flow features listed in 2.4 |

**Online (every monitoring session):**

```
src/xrlids/live/capture.py        PacketCaptureService
        │   live: AF_PACKET raw socket on <iface>       (needs root/CAP_NET_RAW)
        │   sample: paced replay of a .pcap file        (no privileges)
        ▼
dashboard/server.py               LiveSession merge queue
        │   capture-producer thread ──┐
        │   attack-injection thread ──┤─► queue ─► single consumer
        ▼                             (FlowBuilder is only ever touched by one thread)
src/xrlids/demo/flow.py           FlowBuilder (D-006 completion policy)
        ▼   completed flow (one per finished conversation)
src/xrlids/demo/live_lab.py       LiveLabMonitor._evaluate_and_alert()
        │   ReplayEngine._predict_flow(flow)
        ▼   preprocessor.transform → model.predict_proba → score ∈ [0,1]
dashboard/server.py               FlowObservation / AlertEvent → HTTP JSON API
        ▼
dashboard/app.js + index.html     browser UI, polls GET /api/live every 1 s
```

### 2.2 Capture layer (`src/xrlids/live/capture.py`)

- **Live mode** opens a Linux `AF_PACKET` raw socket (`ETH_P_ALL`, 0x0003), optionally bound to one
  interface (e.g. `wlo1`), polls with `select()` (never blocks the process), parses each frame with
  `parse_packet_bytes()`, and yields `PacketInfo` objects.
  Requires root / `CAP_NET_RAW`; `PacketCaptureService.check_permissions()` probes this and the UI
  shows *"raw sockets denied (sudo needed…)"* when unavailable.
- **Filter** (`--bpf`, UI text box) is a *simplified* matcher, not full BPF: it understands tokens
  `tcp`, `udp`, and `port <N>` — e.g. `"tcp port 443"`. Anything else is ignored.
- **Sample mode** (no privileges): reads the demo PCAP and paces it in real time. At each yield the
  packet's original timestamp is replaced by the current wall-clock time, and the inter-packet gaps
  are divided by the pace factor (default **2×**; `loop=True` restarts the file when it ends).
  A special case: the demo file's timestamps start at `1700000000.0` (Nov 2023) — restamping is why
  the dashboard shows today's times for a 2023 file.

### 2.3 Flow assembly — the D-006 completion policy (`src/xrlids/demo/flow.py`)

- **Grouping key:** canonical bidirectional 5-tuple — the two endpoints `(ip, port)` are sorted,
  plus the protocol. So both directions of a conversation land in one flow regardless of which side
  sent the first packet. The flow remembers which endpoint sent packet #1
  (`source_first_ip/port`) for display.
- **Accumulation:** packet lengths, total bytes, start/last timestamps, and TCP flag counts
  (SYN, ACK, RST, FIN).
- **Completion (D-006):** a TCP flow is *closed* the moment a packet carries **RST or FIN** (either
  direction). Independently, any flow that has been **idle for 120 s** is flushed as completed when
  the next packet of any flow is processed (and everything pending is flushed when the session
  stops). Consequence: **UDP conversations (like the demo DNS query) never complete on their own** —
  they appear only after the 120 s idle timeout or when you press Stop. This is expected, not a bug.
- Each completed flow is passed to `LiveLabMonitor._evaluate_and_alert()` which produces one
  `FlowObservation` (for the flows table) and, if the decision crosses the threshold, one
  `AlertEvent` (for the alerts table).

### 2.4 The R10 feature contract (exact formulas)

Computed from the flow's packet list (`n` = packet count, `L_i` = packet lengths in bytes,
`dur_s = max(0, last_ts − first_ts)`):

| # | Feature | Formula |
|---|---|---|
| 1 | `flow_duration_ms` | `dur_s × 1000` |
| 2 | `flow_packets_per_s` | `n / max(dur_s, 1e-6)` |
| 3 | `flow_bytes_per_s` | `sum(L_i) / max(dur_s, 1e-6)` |
| 4 | `packet_length_mean` | `mean(L_i)` (0 if no packets) |
| 5 | `packet_length_std` | population std of `L_i` (0 if fewer than 2 packets) |
| 6 | `syn_count` | number of packets with the TCP SYN flag |
| 7 | `ack_count` | number of packets with the TCP ACK flag |
| 8 | `rst_count` | number of packets with the TCP RST flag |
| 9 | `fin_count` | number of packets with the TCP FIN flag |
| 10 | `syn_ack_ratio` | `syn_count / max(ack_count, 1)` |

Note the guaranteed fallbacks: `dur_s` is floored at 1 µs (so instant flows don't divide by zero)
and `ack_count` is floored at 1 (so the ratio never divides by zero). This exact contract was
parity-verified against the training-time extraction.

### 2.5 Inference, thresholds, and alert levels (`live_lab.py`, `replay.py`)

For every completed flow, the score is computed in exactly four steps:

1. `Flow.to_features()` returns the 10 R10 values (section 2.4).
2. The frozen preprocessor standardises them: `x = preprocessor.transform([10 features])`.
3. The frozen Random Forest returns the positive-class probability:
   `score = random_forest.predict_proba(x)[0]` (the project's `RandomForestDetector` returns a 1-D
   array containing `P(attack)`).
4. `prediction = ATTACK if score >= 0.50 else BENIGN` (research τ = 0.50). If it is an attack, the
   alert band is **HIGH ≥ 0.85**, **MEDIUM ≥ 0.65**, **LOW ≥ 0.50**.

Concrete example — the `slow_http_dos` simulator flow:

```
flow_duration_ms   = 3250.000000
flow_packets_per_s =    0.615385
flow_bytes_per_s   =  219.076923
packet_length_mean =  356.000000
packet_length_std  =    0.000000
syn_count          =    1.000000
ack_count          =    1.000000
rst_count          =    1.000000
fin_count          =    0.000000
syn_ack_ratio      =    1.000000

score = random_forest.predict_proba(preprocessor.transform(R10))[0] = 0.991025
label = ATTACK   alert = HIGH
```

That exact feature vector and output are visible in the UI: click **features** on any alert row.

- **Operational candidate τ = 0.40** exists in the engine (decision D-003 candidates) and is used
  only in the policy-suggestion mapping; it is *not* used to declare attacks.
- **Policy Suggestion (NOT enforced)** column (display-only mapping in `app.js`): `≥0.50 BLOCK`,
  `≥0.40 THROTTLE`, `≥0.20 MONITOR`, else `ALLOW`. The dashboard labels these `(suggested)` and
  states **"No traffic is blocked."** It never actuates a firewall, routing, or traffic change.
- **Alert delivery in the frontend:** a banner shows new alerts (HIGH/MEDIUM hold for 15 s so a
  stream of low-score sample alerts cannot hide an injected detection); the **Alerts** table keeps
  the history; the **Detected Attack Sources** panel aggregates by source IP; the **features**
  dialog shows the exact 10 values and the model output.
- **No accuracy claims on live traffic** — there are no ground-truth labels for your network, so
  the UI deliberately shows scores and alerts, never accuracy numbers.

### 2.6 Dashboard server (`dashboard/server.py`)

Zero-dependency Python standard library HTTP server, bound to `127.0.0.1` only.

Threading model (important for correctness): the capture source and the attack simulator **never
touch the flow builder**. A capture-producer thread feeds a `queue.Queue`; injection threads feed
the same queue; one consumer (the monitor thread) drains it and is the only place `FlowBuilder`,
the model, and the counters are used. That removes any thread-safety question from the pipeline.

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | The dashboard page (Live Monitor + Replay & Evidence tabs) |
| GET | `/app.js` | Front-end logic |
| GET | `/api/data` | Replay & Evidence data (replay summary, SHAP, figures list) |
| GET | `/api/live` | Live session snapshot (status, counters, flows, alerts, injection state) |
| POST | `/api/live/start` | Start a session: `{"mode": "sample"}` or `{"mode": "live", "interface": "wlo1", "bpf_filter": "tcp port 443"}` |
| POST | `/api/live/stop` | Stop the session (flushes pending flows) |
| GET | `/api/live/interfaces` | Interface names + raw-socket permission status |
| GET | `/api/live/scenarios` | Attack-simulator catalogue with calibrated expectations |
| POST | `/api/live/inject-attack` | Inject a scenario: `{"scenario": "slow_http_dos"}` (requires a running session) |
| POST | `/api/run-replay` | Re-run the offline replay demo (evidence tab) |
| GET | `/figures/<name>.png` | Research figures |

The browser polls `/api/live` once per second (`LIVE_POLL_MS = 1000`) and appends new flows/alerts
to the tables (newest first). CLI autostart: `--sample` (paced demo stream, no root) or
`--live --iface <name>` (real capture, root required).

### 2.7 The Attack Simulator and its calibration (`src/xrlids/demo/attack_sim.py`)

Every scenario is a deterministic TCP packet script. Injection restamps each packet to wall-clock
time **at 1× speed** (the calibrated scores depend on the flow's time shape; injections are never
speed-scaled in the UI) and pushes it into the same queue as captured packets. At most one
injection runs at a time.

| Scenario | Packets | Duration | Flow(s) | Frozen-model score | Band |
|---|---|---|---|---|---|
| `slow_http_dos` (slowhttptest-style) | 2 | 3.25 s | 1 | **0.9910** | HIGH |
| `slow_http_dos_lite` (minimal headers) | 2 | 3.27 s | 1 | **0.9163** | HIGH |
| `slowloris_session` | 3 | 5.00 s | 1 | **0.7667** | MEDIUM |
| `low_rate_drip` | 3 | 8.00 s | 1 | **0.5476** | LOW |
| `syn_flood` *(evasion demo)* | 201 | 1.00 s | 1 | 0.0002 | not detected |
| `http_flood` *(evasion demo)* | 301 | 1.50 s | 1 | 0.0290 | not detected |
| `port_sweep` *(evasion demo)* | 80 | 1.96 s | 40 | 0.0169 | not detected |

**How the scores were obtained (and can be re-obtained):** the parameter space of physically
buildable scripts was probed (2–400 packets, 54–1500-byte lengths, 0.1 ms–8 s durations, flag
mixes), each candidate was pushed through the *real* pipeline (`FlowBuilder → frozen R10 → frozen
RF`), and only surviving scripts were kept. `scripts/demo/verify_attack_scenarios.py` re-runs every
scenario end-to-end and checks the recorded score (±0.05), the flow count, the packet count, and
band consistency. Run it with:

```bash
.venv/bin/python scripts/demo/verify_attack_scenarios.py
```

**Why three scenarios are "evasion demos" (deliberate non-detections):** the probing showed that
this frozen model's high-confidence region for *clean synthetic* traffic is the low-and-slow family
(2–4 packets, 3–8 s, small equal-size payloads). Classic fast floods and scans score near zero
because the model's learned flood/scan signatures lean on CIC FlowMeter artefacts — e.g.
`packet_length_std` values above the physical 1500-byte limit, or flows with thousands of packets —
that a clean capture cannot reproduce. Those scenarios ship labelled as non-detections so the
console shows the model's real behaviour instead of a staged detection.

### 2.7.1 Where is the deep-learning model? (LSTM / fusion)

The Live Monitor's score is the **Random Forest**, not the LSTM. This is deliberate:

- The **LSTM** is a supervised sequence classifier over **5 consecutive flows** (`seq_len = 5`),
  using the same R10 features. It is trained and frozen in
  `results/experiments/EXP-P1-CIC2017-R10-001/`: `lstm.pt` (top-level) and per-seed
  `seed_42/lstm.pt`, `seed_123/lstm.pt`, `seed_456/lstm.pt`. The 3-seed test metrics are
  **accuracy 0.9858 ± 0.0007, F1 0.9610 ± 0.0019, ROC-AUC 0.9973 ± 0.0002**
  (`multi_seed_metrics.json`).
- **Fusion** is the score-level weighted mean `0.5 × RF + 0.5 × LSTM` on the same aligned population.
  Its 3-seed metrics are **accuracy 0.9903 ± 0.0005, F1 0.9735 ± 0.0016, ROC-AUC 0.9986 ± 0.0002**.
  For reference, the 3-seed RF metrics are **0.9816 / 0.9515 / 0.9968**.
- **Why the live monitor uses RF only:** the LSTM needs a buffer of 5 consecutive flows and a
  sequence-boundary decision; the live console scores each completed flow independently. Fusion
  also requires aligning two score streams. The RF is used live for deterministic per-flow latency
  and exact parity with the frozen R10 contract. This is a deployment choice, not a claim that the
  LSTM does not work — the offline results above show it does.
- **Where to see the DL results:** Replay & Evidence tab → **Offline Model Comparison** table
  (3-seed RF / LSTM / fusion accuracy, F1, ROC-AUC) and the generated figures; raw artifacts are
  `experiment_record.json`, `multi_seed_metrics.json`, `model_comparisons.json`. The live notice
  states that LSTM/fusion are evaluated offline.

### 2.7.2 How uncertain are the detector numbers?

The per-seed 95% bootstrap intervals come directly from the saved held-out
predictions (`predictions_test.csv`), not from a retrained model. Threshold
metrics use an exact row-bootstrap of the full test confusion matrix
($B=1000$); ROC-AUC uses $B=1000$ stratified resamples of a fixed 100k sample,
with the point estimate on the full test set. The intervals quantify
**test-set sampling uncertainty**, not training-seed variance.

| Dataset | Model | F1 [95% CI] | ROC-AUC [95% CI] |
|:---|:---|:---:|:---:|
| CIC-IDS2017 | RF | 0.9512 [0.9500, 0.9524] | 0.9968 [0.9965, 0.9971] |
| CIC-IDS2017 | LSTM | 0.9633 [0.9622, 0.9643] | 0.9974 [0.9971, 0.9977] |
| CIC-IDS2017 | Fusion ($\alpha=0.50$) | 0.9745 [0.9737, 0.9754] | 0.9989 [0.9987, 0.9991] |
| CSE-CIC-IDS2018 | RF | 0.8861 [0.8851, 0.8872] | 0.9902 [0.9893, 0.9914] |
| CSE-CIC-IDS2018 | LSTM / Fusion ($\alpha=0.00$) | 0.9603 [0.9597, 0.9610] | 0.9966 [0.9962, 0.9972] |
| UNSW-NB15 | RF | 0.8548 [0.8502, 0.8599] | 0.9487 [0.9462, 0.9511] |
| UNSW-NB15 | Fusion ($\alpha=0.60$) | 0.8970 [0.8930, 0.9009] | 0.9674 [0.9654, 0.9693] |

Full table: `reports/generated/bootstrap_ci_report.md`. The 3-seed mean ± std is
a separate quantity in `reports/generated/multi_seed_report.md`; a seed-42 CI
does not have to contain the 3-seed mean.

### 2.7.3 Did it work on future traffic? (temporal holdout)

No — and the system reports this explicitly. `EXP-P1-CSE2018-TEMPORAL-R10-001`
sorts CSE-CIC-IDS2018 by its real `Timestamp` and trains on 14–20 Feb 2018,
validates on 20–22 Feb, and tests on 22 Feb–2 Mar. The split passes the exact
duplicate, rounded near-duplicate, and temporal-ordering audits (L-01/L-02/L-05).

| Metric | Random split | Temporal holdout |
|:---|:---:|:---:|
| Accuracy | 0.9723 | 0.9633 |
| Precision | 0.8242 | 0.0332 |
| Recall | 0.9580 | 0.0068 |
| F1 | 0.8861 | **0.0113** [0.0101, 0.0124] |
| ROC-AUC | 0.9902 | 0.3905 |

The test period contains 50,306 attacks (3.08%) after Policy A removed
label-conflicting and duplicate rows; these are the surviving **unique** future
attacks, not the raw day-level prevalence. Bot recall falls from 99.17%
(random) to 0.09% (temporal), infiltration from 10.70% to 0.94%, and web/XSS/SQL
attacks to 0.00%. The 99% headline is therefore an **in-domain upper bound**, not
a future-day performance claim. Full comparison:
`reports/generated/temporal_split_report.md`. The dashboard's model-comparison
table carries the same caveat.

### 2.7.4 Prove the simulator isn't bluffing (run this)

The simulator only creates packets. It never writes a score. Run:

```bash
.venv/bin/python scripts/demo/explain_score.py
```

It loads the frozen artifact, builds the scenario packets, runs them through the same `FlowBuilder`,
prints the 10 features, and calls the same `predict_proba` used by the dashboard. Example output
(abridged):

```
model sha256: 7c6ad493b773b687da24a2a12dcb21bd03bd56b76809462b983454aeacf2b774
benign control: score = 0.020312 -> BENIGN
slow_http_dos:  score = 0.991025 -> ATTACK (HIGH)
same two packets, only the gap changes:
  gap=0.05s -> 0.103262
  gap=0.50s -> 0.343725
  gap=1.00s -> 0.527782
  gap=2.00s -> 0.265950
  gap=3.25s -> 0.991025
```

The score changes when only the packet timing changes, and a normal TCP request scores 0.02 in the
same code path. In the UI, the **features** dialog shows the same 10 values for every alert. The
scenario verifier checks all seven scenarios end-to-end:

```bash
.venv/bin/python scripts/demo/verify_attack_scenarios.py
```

If someone claims the demo is staged, point them at `scripts/demo/explain_score.py`, the feature
dialog, and the `predict_proba` call in `src/xrlids/demo/replay.py::_predict_flow`.

### 2.8 Showing REAL traffic from this laptop's WiFi

On this machine the WiFi interface is `wlo1` (`192.168.0.109/24`, gateway `192.168.0.1`).

```bash
# 1. Stop any running dashboard first, then (NEEDS root — run it yourself):
sudo .venv/bin/python dashboard/server.py --live --iface wlo1
#    …or start it without root and use the UI: mode "Live capture", interface wlo1
#    (the UI shows "raw sockets denied" unless the server itself runs with sudo)

# Optional capture filter (simple matcher): tcp / udp / "tcp port 443"
sudo .venv/bin/python dashboard/server.py --live --iface wlo1 --bpf "tcp port 443"
```

What you will see: flows whose addresses are *yours* — `192.168.0.109` talking to DNS servers,
browsers talking to websites, ARP/DHCP/mDNS broadcasts, etc. They will look completely different
from the demo data, and that is the point: it is your real network.

Honest limits of WiFi capture in normal (managed) mode: the card only delivers frames addressed to
this laptop plus broadcast/multicast. You will **not** see other devices' unicast traffic on the
same WiFi (that would require monitor mode, which this project deliberately does not use). Nothing
is ever transmitted, dropped, or modified — the socket is read-only.

#### Which devices can the dashboard see?

Live mode also shows a **Devices Observed on WiFi** panel. This is *not* the router's client table.
The router is the access point and knows every associated station; this laptop is a client and can
only observe what reaches its NIC:

| Evidence | What it reveals |
|---|---|
| Local neighbour cache (`/proc/net/arp`, `ip neigh`) | Devices this laptop recently talked to; seeded at session start |
| ARP requests/replies | IP ↔ MAC pairs for devices that broadcast ARP |
| DHCP options 12/60 | Hostname and vendor class from lease traffic |
| mDNS | `.local` hostnames and A/AAAA records |
| SSDP | Device activity and `SERVER:` hints |
| Ethernet/IPv4 headers | MAC/IP pairs for frames to this laptop or broadcast/multicast |

The panel labels `SEEN` (at least one frame observed in this session) versus `CACHED` (from the
neighbour cache, no frame observed yet). It marks privacy/random MACs and identifies the gateway
and this laptop. It never sends ARP scans, pings, or other probes, and it stores observations in
memory only. Idle devices, IPv6-only devices, clients isolated by the AP, and other clients'
unicast traffic may be missing.

For the authoritative list, use the router's admin page/API, SNMP, or run the collector on the AP.
The `DeviceTracker` implementation is `src/xrlids/live/devices.py`; the API is
`GET /api/live/devices` (also included in `/api/live` as `devices`, `network`, and
`device_counters`).

Terminology note: "live" in the dashboard means *the Python process receives packets as they
arrive* — the capture is real, but it is passive observation, not interception.

### 2.9 Verification quick-reference

```bash
# Is the dashboard running, and in which mode?
pgrep -af "dashboard/server.py"

# What does the API say right now? (status, mode, counters, flows, alerts, injection)
curl -s http://127.0.0.1:8000/api/live | .venv/bin/python -m json.tool | head -40

# Attack-simulator catalogue + calibrated expectations
curl -s http://127.0.0.1:8000/api/live/scenarios | .venv/bin/python -m json.tool | head -40

# Re-verify every simulator scenario against the frozen model
.venv/bin/python scripts/demo/verify_attack_scenarios.py

# Prove a scenario's score: print the R10 features and the model's predict_proba output
.venv/bin/python scripts/demo/explain_score.py

# In the UI, click "features" on any alert to see the same values and output

# Full test suite (408 tests)
.venv/bin/pytest -q

# This laptop's real addresses (compare against dashboard IPs)
ip -brief addr
```

### 2.10 Map: which file does what

| File | Responsibility |
|---|---|
| `src/xrlids/live/capture.py` | Packet sources: AF_PACKET live socket, PCAP reader, synthetic stream; permission checks; optional passive raw-frame observer hook |
| `src/xrlids/live/devices.py` | Passive WiFi device discovery (ARP/DHCP/mDNS/SSDP/neighbour cache; no probes) |
| `src/xrlids/demo/pcap.py` | Packet representation (`PacketInfo`) and PCAP parsing; frame builder for tests/demos |
| `src/xrlids/demo/flow.py` | D-006 bidirectional flow assembly + R10 feature computation |
| `src/xrlids/demo/live_lab.py` | Per-flow observations, alert creation/bands, alert callbacks (observational only) |
| `src/xrlids/demo/replay.py` | `ReplayEngine`: loads the frozen model/preprocessor, scores flows, thresholds |
| `src/xrlids/demo/attack_sim.py` | Calibrated attack-scenario packet scripts (simulation only) |
| `dashboard/server.py` | HTTP API, `LiveSession` (merge queue, injection worker, counters, snapshots) |
| `dashboard/app.js` / `index.html` | UI: Live Monitor tab (+ Attack Simulator, alert banner, attack-source summary, per-alert feature dialog), Replay & Evidence tab |
| `scripts/demo/verify_attack_scenarios.py` | End-to-end re-verification of all calibrated scenario scores |
| `scripts/demo/explain_score.py` | Prints the R10 features and frozen-model `predict_proba` for a scenario (anti-bluffing proof) |
| `results/experiments/EXP-P1-CIC2017-R10-001/` | The frozen model + preprocessor the live pipeline loads |

---

## Part 3 — Quick answers (FAQ)

**Q: Are the packets in the dashboard real WiFi packets?**
A: Only in **live mode** (`sudo … --live --iface wlo1`). In sample mode you see a synthetic 42-packet
demo file; simulator rows (`203.0.113.x`) are in-memory by design. Neither ever touches your network.

**Q: Why do the IP addresses differ so much from my network?**
A: The demo LAN is fictional (`192.168.1.x`), the fake attacker is `10.0.0.99`, and the simulator
uses the RFC 5737 documentation range (`203.0.113.x`). Your real WiFi is `192.168.0.x` — that
difference is exactly what distinguishes demo data from live data.

**Q: Why did the dashboard show a packet of impossible size (e.g. 5,880 bytes)?**
A: Because it is a simulated demo capture, generated in code; it was never on a physical wire.
Real frames cap at 1,514 bytes. Live capture can never show such packets.

**Q: Can the system block or stop attacks?**
A: No. It is strictly observational: it never sends, drops, or reroutes. The "Policy Suggestion
(NOT enforced)" column is a display-only mapping of what a separate, future response stage could
decide; the UI labels it "(suggested)" and states that nothing is blocked.

**Q: How exactly is the score calculated?**
A: `score = random_forest.predict_proba(preprocessor.transform(R10_features))[0]` — the frozen
Random Forest's positive-class probability. The 10 R10 values are shown in the **features** dialog
on every alert; the score is not a lookup or a hardcoded value. See 2.5 for the worked example.

**Q: Where is the deep-learning model?**
A: The LSTM is trained and frozen (5-flow sequences, 3 seeds) and the fusion model is evaluated
offline; their 3-seed metrics are in 2.7.1. The Live Monitor deliberately uses the per-flow Random
Forest, because a live per-flow score has no 5-flow sequence context. The Replay & Evidence tab
shows the offline evidence; the live score is not an LSTM output.

**Q: How do I see which IP is attacking?**
A: The **Detected Attack Sources** panel aggregates alerts by source IP (with targets, alert count,
max score, and latest time). The **Live Flows** and **Alerts** tables show the full source and
destination endpoints; simulator sources are marked `SIM` and use `203.0.113.x`.

**Q: Why doesn't the device list show every phone/laptop in my house, like the router login does?**
A: Because a WiFi client cannot read the access point's association table. The router knows every
associated station; this laptop only sees traffic addressed to it plus broadcast/multicast (ARP,
DHCP, mDNS, SSDP). Idle or AP-isolated clients may be missing. The dashboard labels this "observed"
and does not send scans/probes. For the authoritative list, use the router's admin page/API or run
the collector on the AP. See §2.8.

**Q: Which traffic is blocked?**
A: **None.** The console is observational. `BLOCK` / `THROTTLE` / `MONITOR` / `ALLOW` are
display-only policy suggestions, labeled `(suggested)` and `(NOT enforced)`. No firewall, routing,
or packet-drop state is touched.

**Q: Where does the frontend alert me?**
A: A red/amber banner appears on new alerts; the **Alerts** table keeps history; the **Detected
Attack Sources** panel summarizes attackers; and each alert has a **features** button showing the
exact model input/output. There is no email/SMS/pager integration.

**Q: Is the attack simulator just bluffing?**
A: No. It only creates packets; the score comes from the frozen model. Run
`scripts/demo/explain_score.py` to see a benign control (≈0.02), the calibrated scenario (≈0.99), and
the same two packets scoring differently as the gap changes. The UI's feature dialog shows the same
values, and `verify_attack_scenarios.py` re-verifies all seven scenarios. See 2.7.4.

**Q: Why do some flows (like the demo's DNS query) never appear as completed?**
A: D-006 completes TCP flows on FIN/RST or 120 s of silence. The demo DNS flow is UDP with no
closing packet, so it completes only at the idle timeout or when you press Stop.

**Q: Is the model re-trained or "learning" while monitoring?**
A: No. The live pipeline uses the frozen artifact from `EXP-P1-CIC2017-R10-001` exactly as trained.

**Q: Why do classic SYN floods/port scans show "not detected" in the simulator?**
A: That is a documented property/limitation of this frozen model on clean synthetic traffic (see
2.7). The evasion demos exist so the console shows the model's real behaviour rather than a staged
detection — an honesty feature, not a bug.
