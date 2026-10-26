# XRL-IDARS Web Console

A zero-dependency, lightweight web console with two views:

1. **Live Monitor** — observational live capture: packets → bidirectional flows (D-006) → frozen R10 features → frozen CIC-IDS2017 Random Forest detector. Streams per-flow records (endpoints, protocol, packet counts, threat scores, alerts), with an alert banner, a **Detected Attack Sources** summary (source IPs, targets, counts, max score), a **Devices Observed on WiFi** panel (live capture only), and a per-alert **features** dialog showing the exact 10 model inputs and output.
2. **Replay & Evidence** — reproducible PCAP replay verification statistics, an offline model comparison (3-seed RF / LSTM / RF+LSTM fusion), TreeSHAP feature attributions, and the generated research figures gallery.

> **What is real vs. simulated?** See [`docs/HOW_IT_WORKS.md`](../docs/HOW_IT_WORKS.md) for the full
> end-to-end explanation: which modes use real traffic (live capture only), why the demo/simulator IPs
> differ from your network, and how every component works in detail.

---

## Quick Start (no root required)

```bash
python dashboard/server.py            # default port 8000
python dashboard/server.py 8080       # custom port
# Or: python scripts/demo/run_dashboard.py
```

Open `http://127.0.0.1:8000/` in your browser.

- **Live Monitor tab** → *Benchmark Dataset Replay (CIC-IDS2017)* → **Start Capture**: streams real evaluation flows directly from the official CIC-IDS2017 benchmark dataset (DDoS, DoS Hulk, PortScan, and Benign) with verified ground truth and live Random Forest scoring. Perfect for exhibitions, project vivas, and professor evaluations (no root needed).
- **Live Monitor tab** → *Sample PCAP stream (no root)* → **Start Capture**: replays `data/demo/sample_traffic.pcap` at its original pacing through the complete live packet pipeline.
- **Attack Simulator panel** (inside the Live Monitor tab): injects calibrated synthetic attack scenarios on demand — see below.
- **Detected Attack Sources**: aggregates alerts by source IP. Nothing is blocked; the policy suggestion is display-only.
- **Alerts → features**: opens the exact R10 feature vector, ground truth label, and the frozen model's output for that flow.
- **Replay & Evidence tab**: static replay verification, TreeSHAP table, and research figures (including a *Run Replay Analysis* button that re-runs `scripts/demo/run_replay_demo.py`).

> **Live detector vs. deep model:** the Live Monitor serves the frozen per-flow **Random Forest**.
> The LSTM (5-flow sequences) and RF+LSTM fusion are trained/evaluated offline; their 3-seed metrics
> are in `results/experiments/EXP-P1-CIC2017-R10-001/multi_seed_metrics.json` and summarized in
> [`docs/HOW_IT_WORKS.md`](../docs/HOW_IT_WORKS.md) §2.7.1. The live score is not an LSTM output.

## Demonstration Guide (Exhibitions & Professor Viva)

Follow these steps to demonstrate the intrusion detection and explainable AI capabilities:

### Step 1: Start the Web Dashboard
```bash
# In the project root directory:
source .venv/bin/activate
python dashboard/server.py
```
Then navigate to **http://127.0.0.1:8000/** in your web browser.

### Step 2: Benchmark Dataset Demonstration (Recommended)
1. In the **Live Monitor** tab, select **Benchmark Dataset Replay (CIC-IDS2017)**.
2. Select an attack category from the dropdown:
   - `Curated Benchmark Mix (DDoS, DoS Hulk, PortScan, Benign)` *(best overall demo)*
   - `Friday Afternoon — DDoS Attacks + Benign`
   - `Wednesday — DoS Hulk / Slowloris + Benign`
   - `Friday Afternoon — PortScan Recon + Benign`
   - `Monday — Normal Enterprise Benign Only`
3. Click **Start Capture**.
4. Observe:
   - Real-time flow table populating with IP endpoints, protocols, packet counts, threat scores, and **Truth** badges.
   - High-confidence attacks triggering the red **ATTACK DETECTED** banner.
   - The **Detected Attack Sources** table aggregating attacker IPs and suggesting Dueling DQN mitigation actions (e.g. `BLOCK`).
   - Click the **features** link next to any flow to open the feature provenance modal, displaying the exact 10 R10 feature values and TreeSHAP feature attributions.

### Step 3: Terminal CLI Commands Reference
Run these standalone terminal commands to demonstrate technical depth and offline verification:

```bash
# 1. Run offline PCAP replay through the full detection pipeline
python scripts/demo/run_replay_demo.py

# 2. Verify all calibrated attack scenarios against the frozen detector
python scripts/demo/verify_attack_scenarios.py

# 3. Prove real-time inference and model authenticity with TreeSHAP feature vector
python scripts/demo/explain_score.py

# 4. Run the full unit & integration test suite (409 tests)
pytest -q
```

## Attack Simulator (simulation only)

The Live Monitor tab includes an **Attack Simulator** panel: choose a calibrated scenario, press
**Inject Attack**, and its packets are synthesised **in memory** and pushed through the exact
monitoring pipeline (FlowBuilder → frozen R10 features → frozen detector). Nothing is transmitted on
the network and no firewall/routing state is touched. Injected flows are tagged `SIM` in the flow
table and appear with the frozen model's real scores and alerts. Injection requires a running session;
at most one injection runs at a time.

### Calibrated scenario set

Every scenario ships with a **calibrated expectation** — the exact score the frozen detector produced
when the script was verified end-to-end (`scripts/demo/verify_attack_scenarios.py`, tolerance ±0.05):

| Scenario | Category | Packets | Duration | Flow(s) | Frozen score | Band |
|---|---|---|---|---|---|---|
| `slow_http_dos` | low-and-slow | 2 | 3.25 s | 1 | 0.9910 | HIGH |
| `slow_http_dos_lite` | low-and-slow | 2 | 3.27 s | 1 | 0.9163 | HIGH |
| `slowloris_session` | low-and-slow | 3 | 5.00 s | 1 | 0.7667 | ALERT |
| `low_rate_drip` | low-and-slow | 3 | 8.00 s | 1 | 0.5476 | ALERT |
| `syn_flood` | flood (evasion demo) | 201 | 1.00 s | 1 | 0.0002 | NOT DETECTED |
| `http_flood` | flood (evasion demo) | 301 | 1.50 s | 1 | 0.0290 | NOT DETECTED |
| `port_sweep` | scan (evasion demo) | 80 | 1.96 s | 40 | 0.0169 | NOT DETECTED |

### Why the evasion demos exist (documented limitation)

Probing the frozen detector across the physically realisable packet-script space (2–400 packets,
54–1500-byte lengths, 0.1 ms–8 s durations, flag mixes) shows that its high-confidence region for
clean synthetic traffic is the **low-and-slow family** (2–4 packets, 3–8 s, small equal-size
payloads). Classic fast patterns (SYN/HTTP floods, port sweeps) score near zero with this model: its
learned flood/scan regions rely on CIC FlowMeter artefacts — e.g. `packet_length_std` values above
the physical 1500-byte limit and flows of thousands of packets — that a clean synthetic capture
cannot reproduce. Those scenarios ship deliberately as *NOT DETECTED (evasion demo)* entries, so the
console shows the model's real behaviour rather than a staged detection. The same effect explains why
the bundled sample capture's attack flows score borderline (0.37–0.52) in Replay & Evidence.

### Verifying the calibration

```bash
.venv/bin/python scripts/demo/verify_attack_scenarios.py
```

Re-runs every scenario through `FlowBuilder → frozen R10 → frozen RF
(EXP-P1-CIC2017-R10-001)` and checks completed-flow counts, packet counts, recorded scores (±0.05),
and band consistency (`HIGH ≥ 0.85`, `ALERT ≥ 0.50`, `NONE < 0.50`).

### Proving the score is real (not a stored constant)

```bash
.venv/bin/python scripts/demo/explain_score.py
```

It prints the model path/SHA-256, a benign control score, the scenario's exact R10 features, the
frozen `predict_proba` output, and a timing sweep where only the inter-packet gap changes. The UI's
**features** dialog shows the same values for every alert. If someone claims the demo is staged,
this is the shortest reproducible counter-example.

### Pacing

Injections run at **1× speed**: the calibrated scores depend on each flow's time shape
(`flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`), so pacing is not rescaled in
production. Inter-packet deltas are preserved by wall-clock restamping at emission.

## Live Interface Capture (requires root)

Raw socket capture (AF_PACKET) requires `CAP_NET_RAW` / root:

```bash
sudo .venv/bin/python dashboard/server.py --live --iface wlo1
# Optional capture filter:
sudo .venv/bin/python dashboard/server.py --live --iface wlo1 --bpf "tcp port 443"
```

Or launch the server with `sudo` (no `--live`) and press **Start Capture** in the UI with mode *Live interface (requires root)* and an interface name (e.g. `wlo1`, listed via autocomplete).

**Safety invariants**

- **Strictly observational:** never injects, modifies, drops, or reroutes traffic; no firewall/iptables/routing mutations, ever.
- **No accuracy claims on live traffic:** real networks have no ground truth; the Live Monitor shows flows, alerts, and model scores only.
- **Scores use the frozen research threshold** $\tau = 0.50$ (D-003). The "Policy Suggestion (NOT enforced)" column is the DQN response-policy mapping for display only — the console never actuates, and the UI labels each suggestion `(suggested)`.
- **Flow completion** follows the canonical D-006 policy: TCP FIN/RST or 120 s idle timeout (pending flows are flushed when the session stops).
- **Local only:** the server binds to `127.0.0.1`.

### Observed WiFi devices (live mode only)

The Live Monitor includes a **Devices Observed on WiFi** table. It is a *passive observation*
panel, not the router's association table:

| Source | What it can reveal |
|---|---|
| `/proc/net/arp` / `ip neigh` | Devices this laptop has recently exchanged traffic with (seeded at session start) |
| ARP requests/replies | IP ↔ MAC mappings for devices that broadcast ARP |
| DHCP | Hostname (option 12) and vendor class (option 60) from lease traffic |
| mDNS | `.local` hostnames and A/AAAA records |
| SSDP | Device activity and `SERVER:` hints |
| Ethernet/IPv4 headers | MAC/IP pairs for frames addressed to this laptop or broadcast/multicast |

A WiFi **client** cannot read the access point's client-association table. Idle devices, IPv6-only
devices, devices behind AP isolation, and other clients' unicast traffic may be missing. The panel
deliberately does **not** send ARP scans, pings, or probes, and it stores only in-memory
observations (no history DB).

For the authoritative list, use the router's admin page/API or run the collector on the AP.
The panel distinguishes `SEEN` (a frame was observed in this capture) from `CACHED` (from the
neighbour cache, no frame yet), and marks privacy/random MACs.

The same data is available at `GET /api/live/devices`; `/api/live` also includes `devices`,
`network`, `device_counters`, and `device_discovery`.

---

## File Structure

```text
dashboard/
├── app.js        # Vanilla JavaScript client logic (live polling + evidence view)
├── index.html    # Single-page console markup and embedded styles
├── README.md     # This documentation and operational guide
└── server.py     # Python HTTP/REST server: static assets, live session, APIs
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves `index.html` |
| `GET` | `/app.js` | Serves JavaScript application logic |
| `GET` | `/api/data` | Replay summary, SHAP importances, and figure listing (evidence view) |
| `POST` | `/api/run-replay` | Runs `scripts/demo/run_replay_demo.py` and returns the refreshed summary |
| `GET` | `/api/live` | Live session snapshot: status, counters, recent flows, recent alerts, observed devices, network metadata |
| `GET` | `/api/live/devices` | Passive device-discovery snapshot (empty outside live capture) |
| `GET` | `/api/live/dataset-categories` | Available evaluation categories for benchmark dataset replay |
| `POST` | `/api/live/start` | Starts a session — JSON body: `{"mode": "dataset"|"sample"|"live", "dataset_category": "mixed", "interface": "wlo1", "bpf_filter": "tcp port 443", "pcap": null, "pace_speed": 2.0, "loop": true, "max_packets": null}` |
| `POST` | `/api/live/stop` | Stops the session (flushes pending flows) and returns the final snapshot |
| `GET` | `/api/live/interfaces` | Available interface names + raw-socket permission status |
| `GET` | `/api/live/scenarios` | Calibrated attack-simulator scenario catalogue (metadata + expected scores/bands) |
| `POST` | `/api/live/inject-attack` | Injects a scenario into the live pipeline — JSON body: `{"scenario": "slow_http_dos"}` (simulation only; requires a running session) |
| `GET` | `/figures/{name}` | Serves generated research figures (`.png`) |

---

## Pipeline Components Reused (frozen, tested)

| Stage | Component | Source |
|---|---|---|
| Packet capture (live socket / PCAP / synthetic) | `PacketCaptureService` | `src/xrlids/live/capture.py` (Phase 3A) |
| Passive WiFi device discovery | `DeviceTracker` | `src/xrlids/live/devices.py` (ARP/DHCP/mDNS/SSDP; no probes) |
| Flow construction (canonical 5-tuple, D-006) | `FlowBuilder` | `src/xrlids/demo/flow.py` |
| R10 feature extraction | `flows_to_dataframe` | `src/xrlids/demo/extractor.py` |
| Detector + thresholds | `ReplayEngine` (frozen CIC RF, $\tau=0.50$) | `src/xrlids/demo/replay.py` |
| Observational flow/alert recording | `LiveLabMonitor` | `src/xrlids/demo/live_lab.py` |
| Attack scenario synthesis (simulation only) | `build_scenario_packets` | `src/xrlids/demo/attack_sim.py` (calibrated; verified by `scripts/demo/verify_attack_scenarios.py`) |

No new inference logic is introduced by the console; it is a display and orchestration layer over the frozen pipeline. Timestamps in Sample stream mode are restamped to wall-clock time, so timing-derived feature values (and therefore scores) may differ marginally from the frozen replay artifacts — expected for real-time operation.
