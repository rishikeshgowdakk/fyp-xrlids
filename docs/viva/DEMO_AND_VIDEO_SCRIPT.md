# Demo Runbook, Viva Script & Video Recording Guide

*Created 2026-10-20. Companion to [`FINAL_VIVA_GUIDE.md`](FINAL_VIVA_GUIDE.md) (research Q&A) and
[`../HOW_IT_WORKS.md`](../HOW_IT_WORKS.md) (system explanation). This file is the **practical**
script: what to run, what to click, what to say, and what to do when something breaks.*

---

## 1. Readiness verdict (verified 2026-10-20)

### 1.1 Demo readiness — ✅ READY

| Check | Result |
|---|---|
| Frontend starts (no build step — static HTML/JS served by Python) | ✅ `dashboard/server.py 8000 --sample` → running |
| Live Monitor tab renders + polls (`/api/live`) | ✅ counters, flows, alerts updating every 1 s |
| Passive WiFi device panel (`/api/live/devices`) | ✅ implemented; live path needs sudo; parser verified with crafted ARP/DHCP/mDNS/SSDP frames |
| Attack Simulator end-to-end (HTTP + UI) | ✅ `slow_http_dos` → 2-packet flow, 3250.6 ms, score **0.9910**, **HIGH** alert |
| Scenario catalogue (`/api/live/scenarios`) | ✅ 7 scenarios with calibrated expectations |
| Replay & Evidence tab (`/api/data`) | ✅ 42 packets / 6 flows; 7 figures; TreeSHAP table |
| Deterministic replay metrics | ✅ research τ=0.50 → 83.3% (F1 0.8000); operational τ=0.40 → 100% (F1 1.0000) |
| Frozen model artifacts | ✅ `EXP-P1-CIC2017-R10-001/*.joblib` present (RF 26 MB + preprocessor) |
| Simulator calibration re-verification | ✅ 7/7 scenarios OK (`scripts/demo/verify_attack_scenarios.py`) |
| Full test suite | ✅ **452 passed, 0 failed** (`pytest -q`, exit 0) |
| Phase 2/3 artifacts (RL, response, burst, gate) | ✅ result directories present |
| Root required? | ❌ No for sample mode; ✅ only for optional live WiFi capture |

### 1.2 Production readiness — ⚠️ RESEARCH PROTOTYPE, not production-exposed

Honest gaps (know these before a viva question):

| Area | Current state | Production requirement |
|---|---|---|
| Network exposure | Binds `127.0.0.1` only | Reverse proxy + TLS + authentication/RBAC |
| HTTP server | Python stdlib `ThreadingHTTPServer`, single process | ASGI/WSGI server, worker pool, health checks |
| State | In-memory deques (flows/alerts), no history DB | Durable storage (e.g. Postgres/OpenSearch) + retention policy |
| Model shipping | `.joblib` artifacts are **gitignored** (`*.joblib`) | Versioned model registry / release artifact; integrity hash |
| Missing-model behaviour | Falls back to a heuristic detector with `engine_warning` | Fail closed / refuse to start, or serve last-known-good model |
| Capture privileges | Live capture needs root / `CAP_NET_RAW` | systemd unit with `AmbientCapabilities=CAP_NET_RAW` + hardening |
| Throughput | RF ~sub-ms/flow; full fusion (LSTM) heavier; single node | eBPF/XDP + hardware acceleration; horizontal scaling |
| Response | Observational only (dashboard never actuates) | Enforcement stays inside the audited transaction/safety-gate path |
| CI/CD | None (no `.github/workflows`, no Dockerfile) | CI pipeline, container image, deployment manifests |
| Multi-node | Single-node locks | Distributed coordination (Raft/queue), shared model server |

**Safe demo claim:** "The detection + monitoring prototype is demo-ready end-to-end; production
deployment would require the hardening items above." Never claim it is production-deployed.

---

## 2. Pre-demo checklist (T-10 minutes)

```bash
cd ~/Desktop/fyp-xrlids

# 1) Start the dashboard (sample mode — no root needed)
.venv/bin/python dashboard/server.py 8000 --sample
# leave this terminal running

# 2) Open the UI
#    http://127.0.0.1:8000   (Live Monitor is the default tab)
```

Sanity checks before the examiner walks in:

1. Header status line reads **"running · sample stream (bundled demo capture)"**.
2. **Packets Captured** counter is increasing (refresh after a few seconds).
3. Scenario dropdown lists 7 entries; the expectation badge shows
   **"calibrated: HIGH · score ≈ 0.991"** for the default scenario.
4. Nothing else is running on port 8000.

Optional (only if you will show *real* WiFi traffic — needs your sudo password):

```bash
# stop the sample-mode server first (Ctrl+C in its terminal), then:
sudo .venv/bin/python dashboard/server.py --live --iface wlo1
# check your interface name with: ip -brief addr
```

In live mode, the **Devices Observed on WiFi** panel populates from passive ARP/DHCP/mDNS/SSDP
traffic and the local neighbour cache. It is *not* the router's association table; see Q17 below.

> If the examiner asks for real traffic and you cannot sudo: stay in sample mode and say so
> explicitly. Never present sample data as live.

Backup plan (recommended): record the video demo **before** the viva and keep the file handy. If the
live demo fails, play the recording and narrate over it.

---

## 3. The demo scripts

### 3.1 Three-minute demo (core story)

| Step | Action | Say |
|---|---|---|
| 1 | Point at the header + status line | "This is an observational intrusion-detection console. It never blocks or modifies traffic — it watches, scores, and alerts." |
| 2 | Point at **Live Counters** | "Packets are grouped into bidirectional flows under decision D-006: a TCP flow closes on FIN/RST, otherwise 120 s idle. Each completed flow is scored once." |
| 3 | Attack Simulator → keep default **Slow HTTP DoS (slowhttptest-style)** | "This scenario is calibrated against the frozen model. The badge shows the score it will produce: 0.991, HIGH." |
| 4 | Click **Inject Attack**, then point at the status line | "The packets are synthesised in memory and pushed through the same pipeline as captured traffic. Nothing is sent on the network." |
| 5 | Wait ~3.5 s (narrate while waiting: "the flow must finish before it is scored — that's the 3.25 s gap") | "There it is: 2 packets, 3250 ms, score 0.991, ATTACK, HIGH alert." |
| 6 | Point at **Detected Attack Sources**; click **features** on the injected alert | "Every alerting source IP is summarized here. 'BLOCK (suggested)' is not a block — nothing is enforced. The features dialog shows the exact 10 values the model received and its output." |
| 7 | (Optional, 20 s) Inject **Port sweep scan (evasion demo)** | "40 flows, zero alerts — a documented limitation of this model on clean synthetic scans. We ship it deliberately instead of staging a fake detection." |

### 3.2 Seven-minute demo (recommended)

1. **Problem + architecture (60 s)** — signature IDS vs flow ML; walk the diagram from
   `../HOW_IT_WORKS.md` Part 1: capture → flows → 10 features → frozen RF → dashboard.
2. **Live Monitor tour (60 s)** — counters, flows table, alerts table, alert banner, Detected Attack
   Sources panel; explain SIM badge, τ=0.50 research threshold, alert bands (HIGH ≥ 0.85 /
   MEDIUM ≥ 0.65 / LOW ≥ 0.50), and that "BLOCK (suggested)" never blocks anything.
3. **Simulator: detected scenario (60 s)** — `slow_http_dos` → 0.991 HIGH; click **features** on the
   alert to show the exact R10 input and model output. Mention calibration + verifier script.
4. **Simulator: evasion demo (45 s)** — `syn_flood` or `port_sweep` → near-zero scores; explain
   the FlowMeter-artifact limitation honestly (this is a strength in a viva, not a weakness).
5. **Replay & Evidence tab (90 s)** — 42-packet deterministic replay; 6 flows with ground truth;
   research τ=0.50 → 83.3% (one borderline miss at 0.4692 shown explicitly), operational τ=0.40 →
   100%. TreeSHAP feature importance below.
6. **All three benchmarks + model evidence (60 s)** — 19,321,418 raw rows across all three datasets (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15) with separate held-out test splits, feature contracts (R10 vs R4), and independent evaluations:
   - **CIC-IDS2017**: 355,833 aligned test flows, R10 contract, Fusion F1=0.9745 ($\alpha=0.50$).
   - **CSE-CIC-IDS2018**: 1,662,419 aligned test flows, R10 contract, LSTM F1=0.9603 ($\alpha=0.00$).
   - **UNSW-NB15**: 24,496 aligned test flows, R4 contract, Fusion F1=0.8970 ($\alpha=0.60$).
7. **Flow Evaluation & Exhibition Demo (Modes A, B, C) (60 s)** — demonstrate Mode B (200 flows) across all three benchmarks with side-by-side RF, LSTM ($T=5$, causal sequence), and Fusion metrics, 3 confusion matrices, source-file provenance with clearly labeled synthetic display endpoints, on-demand TreeSHAP explanations, and Dueling DQN dry-run actions.
8. **Limitations + production path (45 s)** — live traffic has no ground truth (never claim accuracy); production gaps: auth/TLS, persistence, model registry, eBPF/XDP, CI.

### 3.3 Twelve-minute full demo

Run 3.2, then add:

- **Live capture explanation (90 s)**: what live mode is (`AF_PACKET`, root), what it can see in
  managed WiFi mode (this laptop's traffic + broadcast/multicast, not other clients' unicast),
  why live flows look nothing like the demo IPs, and what the **Devices Observed on WiFi** panel
  adds (passive ARP/DHCP/mDNS/SSDP + neighbour cache; not the router's association table).
- **RL/response recap (90 s)**: 6-D state, Dueling DQN, safety gate, transactional rollback;
  H0 rejected (p<0.001) but the 15% practical criterion was **not** met (11.29%/14.10% cost
  reduction) — report it as pre-registered and honest.
- **Any viva question** from §4.

---

## 4. Viva Q&A — dashboard/demo-specific supplement

> The full research Q&A (datasets, RF/LSTM/fusion, RL, SHAP, rollback) is in
> [`FINAL_VIVA_GUIDE.md`](FINAL_VIVA_GUIDE.md). These are the questions examiners ask **while the
> dashboard is on screen.**

**Q1. Are these real packets from my WiFi?**
No — in the default sample mode this is a bundled synthetic 42-packet capture, and simulator rows
are in-memory. Real traffic appears only after live capture is started with `sudo ... --live
--iface <name>`. The UI labels the mode and the SIM badge marks injected flows.

**Q2. Why do the IP addresses differ from my network?**
The demo LAN is fictional (`192.168.1.x`), the fake attacker host is `10.0.0.99`, and the simulator
uses the RFC 5737 documentation range (`203.0.113.x`) so it can never collide with real hosts. Your
WiFi is whatever `ip -brief addr` shows (e.g. `192.168.0.x`). This difference is the fastest way to
prove to an examiner which mode is running.

**Q3. Why does the demo capture contain a 5,880-byte packet?**
Because it is generated in code, not captured. Real Ethernet/WiFi frames cap at 1,514 bytes. This is
a feature of a reproducible demo file, and impossible in live capture.

**Q4. Where is the deep-learning model? Why does the live monitor use only the Random Forest?**
The LSTM is trained and frozen (5-flow sequences, R10 input): 3-seed accuracy 0.9858, F1 0.9610,
AUC 0.9973; RF+LSTM fusion is 0.9903 / 0.9735 / 0.9986. The live monitor loads the frozen RF because
a live per-flow score has no 5-flow sequence context, and fusion needs aligned RF/LSTM score streams.
RF is the deployed per-flow detector for deterministic latency and exact R10 parity; the DL results
are in Replay & Evidence → **Offline Model Comparison** (3-seed RF / LSTM / fusion) and the
experiment artifacts. **The live score is not an LSTM output** — state that plainly if asked.

**Q5. One replay attack shows "BENIGN (INCORRECT)" — is that a bug?**
No — it is the threshold decision being shown honestly. The flow scores 0.4692, below the research
τ=0.50, so it is classified benign; at the operational candidate τ=0.40 the same replay is 100%
correct. D-003 (operational threshold) remains an open decision; we display both thresholds.

**Q6. Why do your SYN flood / port scan demos get "not detected"?**
A calibrated property of this frozen model on clean synthetic traffic: its learned flood/scan
regions rely on CIC FlowMeter artefacts (e.g. packet-length std above the physical 1500-byte limit,
thousands-packet flows) that clean captures cannot reproduce. We ship those scenarios as labelled
evasion demos so the model's real behaviour is visible. This is exactly the kind of finding a viva
should reward — no staged detections.

**Q7. How do we know the simulator isn't faking detections?**
Scenario parameters were searched over the physically realisable script space and every surviving
script was verified end-to-end through `FlowBuilder → frozen R10 → frozen RF`. The recorded scores
are re-checked by `scripts/demo/verify_attack_scenarios.py`; the live UI shows the model's own
output, and the code never writes scores. Injection only supplies packets. The strongest live proof
is `scripts/demo/explain_score.py`: a normal TCP request scores **0.0203**, `slow_http_dos` scores
**0.9910**, and the same two packets score **0.103 / 0.344 / 0.528 / 0.266 / 0.991** as only the
inter-packet gap changes. In the UI, click **features** on any alert to see the exact 10 values and
the model output for that flow.

**Q8. Is the injection dangerous? Can it attack a real host?**
No. Packets are objects in memory pushed into the pipeline queue; the program never opens a sending
socket for them, and the attacker addresses are documentation-range IPs. The monitoring service
itself only reads (live capture) — it never sends, drops, or reroutes.

**Q9. How do you know live features match the training features?**
Parity tests verify computed features against the offline definitions to `atol ≤ 1e-4`; the R10
contract is frozen and shared by training, replay, and live paths. The test suite (452 tests)
includes the parity and pipeline tests.

**Q10. What happens if the model files are missing on the demo machine?**
The server falls back to a heuristic detector and exposes an `engine_warning` in the API/UI. For a
viva, check the warning field is empty before you start; if it is set, the demo is running without
the frozen model — say so or fix the artifacts first.

**Q11. Why does the DNS flow never appear as completed?**
D-006 completes TCP flows on FIN/RST; UDP has no close semantics, so it completes only at the 120 s
idle timeout or when the session stops. This is documented and expected.

**Q12. What would it take to productionise this?**
Auth/TLS/reverse proxy, durable storage, model registry with integrity hashes, capability-scoped
capture, eBPF/XDP for line rate, CI/CD + containers, and distributed coordination. The detection and
observability logic is complete; the operational envelope is not.

**Q13. What is the "Policy Suggestion (NOT enforced)" column?**
A display-only mapping of the DQN response-policy bands (BLOCK ≥ 0.50, THROTTLE ≥ 0.40, MONITOR
≥ 0.20, ALLOW otherwise), labeled `(suggested)`. The dashboard never actuates and states "No traffic
is blocked"; enforcement lives in the audited transaction/safety-gate path, tested only inside
isolated network namespaces.

**Q14. How many tests are in the suite, and what do they cover?**
The test suite contains **452 automated tests** across 66 modules covering: Phase 1 data/model contracts, leakage/dedup guarantees, parity, and replay (408 → 417); Phase 2A Cost-Optimal baseline policies (423); Research Evaluation Workbench APIs and population reconciliations (435); and Phase D CSV dataset evaluation, target-leakage prevention, strict label parsing, non-finite row reconciliation, and schema enforcement (452). `pytest -q` is the single gate; expected result: 452 passed with 0 failures.

**Q15. How exactly is the score calculated?**
`score = random_forest.predict_proba(preprocessor.transform(R10_features))[0]` — the frozen RF's
positive-class probability. `ATTACK if score ≥ 0.50`; alert bands HIGH ≥ 0.85, MEDIUM ≥ 0.65,
LOW ≥ 0.50. The **features** dialog shows the exact 10 values; the worked example is in
`docs/HOW_IT_WORKS.md` §2.5.

**Q16. Which IP is attacking, and which traffic is blocked?**
The **Detected Attack Sources** panel aggregates alerts by source IP (targets, alert count, max
score, latest time). Live Flows/Alerts show full `src → dst` endpoints; simulator addresses are
marked `SIM` (`203.0.113.x`). **Nothing is blocked** — BLOCK/THROTTLE are `(suggested)` labels only;
no firewall, routing, or packet-drop state is touched.

**Q17. Where does the frontend alert me?**
A banner appears on new alerts (HIGH/MEDIUM hold for 15 s so sample noise cannot hide an injected
detection), the **Alerts** table keeps history, the **Detected Attack Sources** panel summarizes
attackers, and each alert has a **features** button. There is no email/SMS/pager integration.

**Q18. How uncertain are the detector metrics?**
Per-seed 95% bootstrap intervals were computed from the frozen held-out predictions (B=1000; no
retraining or test-set selection). Examples: CSE seed-42 RF F1 = 0.8861 [0.8851, 0.8872]; CIC
fusion F1 = 0.9745 [0.9737, 0.9754]; UNSW fusion F1 = 0.8970 [0.8930, 0.9009]. These intervals
quantify **test-set sampling uncertainty**, not training-seed variance; the 3-seed mean ± std is
reported separately. Full table: `reports/generated/bootstrap_ci_report.md`.

**Q19. Did you test on future traffic? What did it show?**
Yes. `EXP-P1-CSE2018-TEMPORAL-R10-001` is a strict future-day holdout: train 14–20 Feb
2018, validation 20–22 Feb, test 22 Feb–2 Mar, sorted by the real CSE `Timestamp` and cut at
hour boundaries. L-01/L-02/L-05 pass. The frozen RF scores F1 **0.0113** (recall 0.0068,
ROC-AUC 0.3905) versus 0.8861 on the random split. Bot recall falls from 99.17% to 0.09%;
infiltration from 10.70% to 0.94%; web/XSS/SQL to 0%. The test is 3.08% attacks after Policy A
dedup (50,306 unique future attacks), so this is a hard, conflict-free future set. This is a
negative result, and we report it: the 99% headline is an in-domain upper bound, not a
future-day readiness claim. Full comparison: `reports/generated/temporal_split_report.md`.

**Q20. Does the dashboard show every device connected to the WiFi, like the router login?**
No — and it says so. The router is the access point and knows every associated station. The
dashboard runs on a WiFi client, so it can only observe traffic addressed to this laptop plus
broadcast/multicast: ARP, DHCP, mDNS, SSDP, and the local neighbour cache. The **Devices Observed
on WiFi** panel labels `SEEN` vs `CACHED` and never claims to be the router's association table.
Idle, IPv6-only, or AP-isolated clients may be missing. It deliberately sends no ARP scans, pings,
or probes.
For an authoritative list, use the router's admin page/API or run the collector on the AP.

---

## 5. Video demo — recording script

### 5.1 Setup

- **Recorder:** OBS Studio (1920×1080, 30 fps) or ffmpeg:
  ```bash
  ffmpeg -f x11grab -video_size 1920x1080 -framerate 30 -i "$DISPLAY" \
         -f pulse -i default -c:v libx264 -preset veryfast -crf 20 -c:a aac demo.mp4
  ```
- **Browser:** one tab, `http://127.0.0.1:8000`, zoom 110–125% (`Ctrl` `+`), bookmarks bar hidden.
- **Terminal:** font ≥ 16 pt; only the dashboard terminal visible.
- **Timing:** record at 1× pacing (do not speed up injections — the wait is part of the proof).
- **Length target:** 6–8 minutes. One continuous take is fine; segment-record if you need retakes.

### 5.2 Shot list + narration

**Shot 1 — Title (0:00–0:20, static or webcam)**
> "XRL-IDARS: an explainable intrusion-detection and response prototype. This video shows the live
> detection console, the calibrated attack simulator, and the evidence behind the models."

**Shot 2 — Architecture (0:20–1:10, show `docs/HOW_IT_WORKS.md` Part 1 diagram)**
> "Traffic is captured or replayed, grouped into bidirectional flows under D-006, summarised by ten
> frozen features, and scored by a frozen Random Forest trained on CIC-IDS2017. Results stream to a
> zero-dependency web console. The monitor is observational: it never blocks or modifies traffic."

**Shot 3 — Live Monitor tour (1:10–2:10)**
> "This is the Live Monitor. The sample stream is a bundled synthetic capture — no root needed. The
> counters show packets, completed flows, and alerts. The flows table lists every completed flow
> with endpoints, packet count, duration, and the model's attack probability. Alerts fire at the
> research threshold of 0.50, with severity bands: HIGH above 0.85, MEDIUM above 0.65."

**Shot 4 — Attack Simulator, detected scenario (2:10–3:20)**
> "The Attack Simulator injects calibrated scenarios in memory. This slow-HTTP-DoS scenario is
> expected to score 0.991 — HIGH. I press Inject Attack… [wait] … the first packet is sent into the
> pipeline; the flow completes after 3.25 seconds; and here is the result: two packets, 3250
> milliseconds, score 0.991, ATTACK, HIGH alert. The score is the frozen model's real output."

**Shot 4b — Attack sources + score provenance (3:20–3:50, optional but recommended)**
> "The Detected Attack Sources panel aggregates every alerting IP. Clicking features on the alert
> shows the exact ten R10 values the model received and the output it produced. And note the label:
> 'BLOCK (suggested)' — this console never blocks anything."

**Shot 5 — Evasion demo (3:50–4:30)**
> "Now a classic SYN flood. It produces two hundred packets over one second… and scores near zero.
> This is a documented limitation: the model's learned flood signature depends on CIC FlowMeter
> artefacts that clean captures cannot reproduce. We expose this honestly instead of tuning a fake
> detection."

**Shot 6 — Replay & Evidence (4:30–5:40)**
> "The Replay & Evidence tab is deterministic. Forty-two packets, six flows, with ground truth.
> At the research threshold, accuracy is 83.3 percent — and you can see the single borderline miss
> at 0.4692. At the operational candidate threshold of 0.40, the same replay is 100 percent. Below,
> TreeSHAP ranks the features driving the detector."

**Shot 7 — Data and model evidence (5:40–6:30, terminal or slides)**
> "The models were trained on 19.3 million raw rows across CIC-IDS2017, CSE-CIC-IDS2018 and
> UNSW-NB15, reduced to 10.2 million modeling rows after duplicate and label-conflict rejection.
> Three-seed fusion results: CIC accuracy 0.9903 with AUC 0.9986; CSE 0.9912; UNSW 0.8988. The
> live console intentionally serves the per-flow Random Forest; the LSTM and fusion results are the
> offline evidence."

**Shot 8 — Closing + limitations (6:30–7:15)**
> "The detector and console are complete and covered by 452 passing tests. Live traffic has no
> ground truth, so we never report accuracy on it. Production deployment would require
> authentication, TLS, durable storage, a model registry, and kernel-bypass capture. The research
> contribution — leakage-safe training, calibrated simulation, and an honest evaluation — is
> reproducible from the repository."

### 5.3 Recording tips

- Do a silent dry run first; note the exact timings of the injection waits.
- Narrate during waits (do not leave dead air): explain D-006 or the score bands.
- Keep the mouse still while speaking; move it only to the next control.
- Record the terminal command once (server start) so the setup is verifiable.
- If you must shorten the 8 s drip scenario in the edit, label the cut; keep at least one real-time
  injection uncut.
- Save as `demo_xrlids_<date>.mp4`; keep a copy offline for viva day.

---

## 6. Recovery playbook (if something breaks)

| Symptom | Cause | Fix |
|---|---|---|
| `Address already in use` | Old server still running | `pkill -f "[d]ashboard/server.py"`, then restart |
| Page shows no data | Server crashed / wrong port | Check terminal; open `http://127.0.0.1:8000`; restart |
| UI stale after code change | Browser cache | `Ctrl+Shift+R` |
| "raw sockets denied" | No root | Stay in sample mode (say so) or restart with `sudo` |
| Live mode shows no flows | Wrong interface / no traffic / filter too narrow | `ip -brief addr`; clear the filter; generate traffic (open a website) |
| UDP-only flows missing | D-006 waits 120 s idle | Expected; point at a TCP flow or press Stop |
| Injection error "No running session" | Monitor not started | Click **Start Capture** (or restart with `--sample`) |
| Injection error "still running" | One injection at a time | Wait for completion (3–8 s) |
| `engine_warning` in the API | Model artifacts missing/unloadable | Restore `results/experiments/EXP-P1-CIC2017-R10-001/*.joblib`; heuristics are not the frozen model |
| Examiner asks for real traffic, no sudo | Privilege restriction | Show the recorded video + explain the managed-mode limits |

---

## 7. One-page cheat sheet (numbers to memorize)

| Fact | Value |
|---|---|
| Raw datasets | 19,321,418 rows / 20 files (CIC 2,830,743 · CSE 16,233,002 · UNSW 257,673) |
| Modeling populations | 10,214,137 rows (1,779,322 + 8,312,295 + 122,520) |
| CIC rows removed in cleaning | 1,051,421 (dupes, invalid, non-finite, conflicts) |
| Feature contract | R10 (10 flow features); UNSW auxiliary R4 (D-002) |
| Live thresholds | research τ = 0.50; operational candidate τ = 0.40 (D-003 open) |
| Alert bands | HIGH ≥ 0.85 · MEDIUM ≥ 0.65 · LOW ≥ 0.50 |
| Multi-seed fusion (acc / F1 / AUC) | CIC 0.9903/0.9735/0.9986 · CSE 0.9912/0.9602/0.9965 · UNSW 0.8988/0.8963/0.9674 |
| Deep models (3-seed acc / F1 / AUC) | RF 0.9816/0.9515/0.9968 · LSTM 0.9858/0.9610/0.9973 · Fusion 0.9903/0.9735/0.9986 |
| Live detector | Frozen per-flow Random Forest (not the LSTM; DL/fusion are offline evidence) |
| Score formula | `random_forest.predict_proba(preprocessor.transform(R10))[0]`; ATTACK if ≥ 0.50 |
| Replay demo | 42 packets · 6 flows · 83.3% @0.50 · 100% @0.40 |
| Simulator (detected) | 0.9910 · 0.9163 · 0.7667 · 0.5476 |
| Simulator (evasion demos) | 0.0002 · 0.0290 · 0.0169 |
| Proof script | benign 0.0203 · attack 0.9910 · gap sweep 0.103/0.344/0.528/0.266/0.991 |
| Blocked traffic | 0 — policy suggestions only (`BLOCK (suggested)`, NOT enforced) |
| Tests | 452 passed, 0 failed |
| RL hypothesis | H0 rejected (p < 0.001); cost −11.29% / −14.10%; 15% practical criterion NOT met |
| D-006 | TCP closes on FIN/RST; otherwise 120 s idle |
| Live capture | AF_PACKET raw socket; root/CAP_NET_RAW; read-only |

---

## 8. Exact command reference

```bash
# Dashboard (sample mode — no root)
.venv/bin/python dashboard/server.py 8000 --sample

# Dashboard (real WiFi — run yourself, needs sudo; interface from `ip -brief addr`)
sudo .venv/bin/python dashboard/server.py --live --iface wlo1

# Optional simple capture filter
sudo .venv/bin/python dashboard/server.py --live --iface wlo1 --bpf "tcp port 443"

# Scenario calibration re-verification
.venv/bin/python scripts/demo/verify_attack_scenarios.py

# Prove a scenario's score (prints R10 features + frozen-model predict_proba)
.venv/bin/python scripts/demo/explain_score.py

# Full test suite
.venv/bin/pytest -q

# API spot checks
curl -s http://127.0.0.1:8000/api/live | python3 -m json.tool | head -40
curl -s http://127.0.0.1:8000/api/live/scenarios | python3 -m json.tool | head -40
```
