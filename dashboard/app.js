// XRL-IDARS Dashboard — Clean Professional Frontend
// Zero external dependencies. Connects to the existing server.py API.

const FEATURE_DESCRIPTIONS = {
  "packet_length_std": "Std dev of packet lengths — high variance → data transfers vs scans",
  "packet_length_mean": "Mean packet length (bytes) across forward and backward packets",
  "flow_packets_per_s": "Packet rate per second — floods/DoS show extreme spikes",
  "flow_bytes_per_s": "Throughput (bytes/s) across the flow lifetime",
  "flow_duration_ms": "Total active duration of the bidirectional flow (ms)",
  "ack_count": "TCP ACK flag count in both directions",
  "fin_count": "TCP FIN flag count — indicates graceful closure",
  "syn_count": "TCP SYN flag count — high without ACK → SYN flood",
  "syn_ack_ratio": "Ratio of SYN to ACK flags in the handshake",
  "rst_count": "TCP RST flag count — aborted connections"
};

const LIVE_POLL_MS = 1000;
const MAX_LIVE_ROWS = 500;

let liveSessionKey = null;
let currentBenchmark = "cicids2017";
let seenFlowIds = new Set();
let seenAlertKeys = new Set();
let renderedFlowCount = 0;
let renderedAlertCount = 0;
let scenariosCache = [];
let alertDetailsCache = new Map();
let bannerScore = 0;
let bannerHoldUntil = 0;

function escapeHtml(v) {
  return String(v === null || v === undefined ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// ─── Tabs ───
function showTab(name) {
  document.querySelectorAll(".tab-content").forEach(el => {
    el.classList.toggle("active", el.id === "tab-" + name);
  });
  document.querySelectorAll(".topbar-tabs button").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === name);
  });
}

// ─── Policy suggestion (display only) ───
function policyFor(score) {
  if (score >= 0.50) return { action: "BLOCK", cls: "badge-red" };
  if (score >= 0.40) return { action: "THROTTLE", cls: "badge-orange" };
  if (score >= 0.20) return { action: "MONITOR", cls: "badge-blue" };
  return { action: "ALLOW", cls: "badge-green" };
}

// ─── Live Controls ───
function onLiveModeChange() {
  const mode = document.getElementById("live-mode").value;
  const dsCat = document.getElementById("dataset-category");
  const iface = document.getElementById("live-iface");
  const bpf = document.getElementById("live-bpf");
  const notice = document.getElementById("live-notice");

  if (dsCat) dsCat.style.display = mode === "dataset" ? "inline-block" : "none";
  if (iface) iface.style.display = mode === "live" ? "inline-block" : "none";
  if (bpf) bpf.style.display = mode === "live" ? "inline-block" : "none";

  if (notice) {
    if (mode === "dataset") {
      notice.className = "notice";
      notice.innerHTML =
        '<strong>Benchmark Dataset Replay:</strong> Streams authentic CIC-IDS2017 flows with ' +
        'ground-truth labels and real-time RF threat scoring (τ = 0.50). No root access needed.';
    } else if (mode === "sample") {
      notice.className = "notice";
      notice.innerHTML =
        '<strong>Sample PCAP Stream:</strong> Replays recorded capture at original pacing through ' +
        'the complete live pipeline. No root required.';
    } else {
      notice.className = "notice";
      notice.innerHTML =
        '<strong>Live Interface Capture (root required):</strong> Captures real packets via AF_PACKET raw socket. ' +
        'Strictly observational — never injects, drops, or modifies traffic.';
    }
  }
}

async function loadLiveInterfaces() {
  try {
    const res = await fetch("/api/live/interfaces");
    if (!res.ok) return;
    const data = await res.json();
    const list = document.getElementById("iface-list");
    list.innerHTML = "";
    (data.interfaces || []).forEach(name => {
      const opt = document.createElement("option");
      opt.value = name;
      list.appendChild(opt);
    });
  } catch (_) {}
}

async function startLive() {
  const mode = document.getElementById("live-mode").value;
  const benchmarkSelect = document.getElementById("live-benchmark");
  const benchmark = benchmarkSelect ? benchmarkSelect.value : "cicids2017";
  const dsCat = document.getElementById("dataset-category");
  const datasetCategory = dsCat ? dsCat.value : null;
  const interfaceName = document.getElementById("live-iface").value.trim();
  const bpf = document.getElementById("live-bpf").value.trim();
  const btn = document.getElementById("live-start-btn");
  const notice = document.getElementById("live-notice");

  btn.disabled = true;
  btn.textContent = "Starting…";
  try {
    const res = await fetch("/api/live/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode,
        benchmark,
        dataset_category: datasetCategory,
        interface: interfaceName || null,
        bpf_filter: bpf || null
      })
    });
    const data = await res.json();
    if (data.error) {
      notice.className = "notice error";
      notice.textContent = data.error;
      btn.disabled = false;
    } else {
      renderLive(data);
    }
  } catch (err) {
    notice.className = "notice error";
    notice.textContent = "Could not start: " + err.message;
    btn.disabled = false;
  } finally {
    btn.textContent = "▶ Start";
    pollLive();
  }
}

async function stopLive() {
  const btn = document.getElementById("live-stop-btn");
  btn.disabled = true;
  btn.textContent = "Stopping…";
  try {
    const res = await fetch("/api/live/stop", { method: "POST" });
    if (res.ok) renderLive(await res.json());
  } catch (_) {}
  finally {
    btn.textContent = "⏹ Stop";
    pollLive();
  }
}

// ─── Attack Simulator ───
async function loadScenarios() {
  try {
    const res = await fetch("/api/live/scenarios");
    if (!res.ok) return;
    const data = await res.json();
    scenariosCache = data.scenarios || [];
    const select = document.getElementById("scenario-select");
    select.innerHTML = "";
    scenariosCache.forEach(spec => {
      const opt = document.createElement("option");
      opt.value = spec.id;
      opt.textContent = spec.name;
      select.appendChild(opt);
    });
    renderScenarioInfo();
  } catch (_) {}
}

function renderScenarioInfo() {
  const select = document.getElementById("scenario-select");
  const spec = scenariosCache.find(s => s.id === select.value);
  const badge = document.getElementById("scenario-expectation");
  const desc = document.getElementById("scenario-desc");
  if (!spec) { badge.textContent = "—"; desc.textContent = ""; return; }
  badge.textContent = spec.expected_band === "NONE"
    ? "calibrated: NOT DETECTED (evasion demo)"
    : "calibrated: " + spec.expected_band + " · score ≈ " + Number(spec.expected_score).toFixed(3);
  badge.className = spec.expected_band === "NONE" ? "badge badge-dim" : "badge badge-red";
  desc.textContent = spec.description + " — " + spec.packet_count + " pkts, " +
    spec.expected_flows + " flow(s), " + Number(spec.duration_s).toFixed(1) + "s " +
    "(" + spec.attacker_ip + " → " + spec.victim_ip + ")";
}

async function injectAttack() {
  const select = document.getElementById("scenario-select");
  const statusEl = document.getElementById("inject-status");
  const btn = document.getElementById("inject-btn");
  if (!select.value) return;
  btn.disabled = true;
  try {
    const res = await fetch("/api/live/inject-attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario: select.value })
    });
    const data = await res.json();
    statusEl.textContent = data.error ? "error: " + data.error : "injecting " + select.value + " …";
  } catch (err) {
    statusEl.textContent = "error: " + err.message;
  } finally { pollLive(); }
}

// ─── Live Polling ───
async function pollLive() {
  try {
    const res = await fetch("/api/live");
    if (!res.ok) throw new Error("HTTP " + res.status);
    renderLive(await res.json());
  } catch (_) {}
}

function renderLive(snap) {
  const running = snap.status === "running";

  // Status badge
  const statusEl = document.getElementById("live-status");
  if (running) {
    statusEl.textContent = "● Running";
    statusEl.className = "badge badge-green";
  } else if (snap.status === "error") {
    statusEl.textContent = "Error";
    statusEl.className = "badge badge-red";
  } else {
    statusEl.textContent = "Stopped";
    statusEl.className = "badge badge-dim";
  }

  // Topbar status
  const dot = document.getElementById("live-dot");
  dot.className = "pulse-dot" + (running ? " live" : "");
  document.getElementById("topbar-status-text").textContent = running
    ? (snap.mode === "dataset" ? "Dataset Stream" : snap.mode === "live" ? "Live: " + (snap.interface || "?") : "Sample Stream")
    : "Idle";

  // Buttons
  document.getElementById("live-start-btn").disabled = running;
  document.getElementById("live-stop-btn").disabled = !running;

  // Keep mode selector synced
  if (running && snap.mode) {
    const modeSelect = document.getElementById("live-mode");
    if (modeSelect && modeSelect.value !== snap.mode) modeSelect.value = snap.mode;
  }

  // Stats
  document.getElementById("lv-packets").textContent = (snap.counters.packets || 0).toLocaleString();
  document.getElementById("lv-flows").textContent = (snap.counters.flows || 0).toLocaleString();
  document.getElementById("lv-alerts").textContent = (snap.counters.alerts || 0).toLocaleString();
  document.getElementById("lv-rate").textContent = (snap.counters.packets_per_s || 0).toFixed(1) + " pkt/s";
  document.getElementById("lv-elapsed").textContent = formatDuration(snap.counters.elapsed_s || 0);
  document.getElementById("lv-mode-label").textContent = snap.started_at
    ? "Since " + new Date(snap.started_at).toLocaleTimeString() : "Not started";

  // Alert stat color
  const alertCard = document.getElementById("alert-stat-card");
  if (alertCard) {
    const cnt = snap.counters.alerts || 0;
    alertCard.className = cnt > 0 ? "stat-card red" : "stat-card";
  }

  // Counters
  document.getElementById("flow-counter").textContent = (snap.counters.flows || 0) + " flows";
  document.getElementById("alert-counter").textContent = (snap.counters.alerts || 0) + " alerts";

  // Injection status
  renderInjection(snap, running);

  // Live Performance & Real-Time Analysis
  const la = snap.live_analysis || {};
  const isGt = Boolean(la.has_ground_truth);
  const gtPanel = document.getElementById("live-eval-gt-panel");
  const livePanel = document.getElementById("live-eval-live-panel");
  const evalStatus = document.getElementById("live-eval-status");

  if (evalStatus) {
    evalStatus.textContent = running
      ? (isGt ? "Testing Dataset Analysis Active" : "Live Wiretap Active")
      : "Stopped";
    evalStatus.className = "badge " + (running ? (isGt ? "badge-green" : "badge-blue") : "badge-dim");
  }

  if (gtPanel && livePanel) {
    gtPanel.style.display = isGt ? "block" : "none";
    livePanel.style.display = isGt ? "none" : "block";
  }

  if (isGt) {
    const accEl = document.getElementById("live-acc-val");
    if (accEl) accEl.textContent = (la.accuracy !== null && la.accuracy !== undefined) ? (la.accuracy * 100).toFixed(1) + "%" : "—";

    const f1El = document.getElementById("live-f1-val");
    if (f1El) f1El.textContent = (la.f1 !== null && la.f1 !== undefined) ? Number(la.f1).toFixed(4) : "—";

    const recEl = document.getElementById("live-rec-val");
    if (recEl) recEl.textContent = (la.recall !== null && la.recall !== undefined) ? (la.recall * 100).toFixed(1) + "%" : "—";

    const precEl = document.getElementById("live-prec-val");
    if (precEl) precEl.textContent = (la.precision !== null && la.precision !== undefined) ? (la.precision * 100).toFixed(1) + "%" : "—";

    const tpEl = document.getElementById("cm-tp");
    if (tpEl) tpEl.textContent = Number(la.tp || 0).toLocaleString();

    const fpEl = document.getElementById("cm-fp");
    if (fpEl) fpEl.textContent = Number(la.fp || 0).toLocaleString();

    const fnEl = document.getElementById("cm-fn");
    if (fnEl) fnEl.textContent = Number(la.fn || 0).toLocaleString();

    const tnEl = document.getElementById("cm-tn");
    if (tnEl) tnEl.textContent = Number(la.tn || 0).toLocaleString();
  }

  const spec = la.score_distribution || {};
  const specHigh = document.getElementById("spec-high");
  if (specHigh) specHigh.textContent = (spec.high || 0).toLocaleString();
  const specMed = document.getElementById("spec-med");
  if (specMed) specMed.textContent = (spec.medium || 0).toLocaleString();
  const specLow = document.getElementById("spec-low");
  if (specLow) specLow.textContent = (spec.low || 0).toLocaleString();
  const specBenign = document.getElementById("spec-benign");
  if (specBenign) specBenign.textContent = (spec.benign || 0).toLocaleString();

  // Error notice
  const notice = document.getElementById("live-notice");
  if (snap.error) {
    notice.className = "notice error";
    notice.textContent = "Error: " + snap.error;
  } else if (snap.engine_warning) {
    notice.className = "notice error";
    notice.textContent = snap.engine_warning;
  }

  // Pipeline source label
  const pipeSource = document.getElementById("pipe-source");
  if (pipeSource) {
    pipeSource.textContent = snap.mode === "dataset" ? "📊 CIC-IDS2017"
      : snap.mode === "live" ? "📡 " + (snap.interface || "Live")
      : snap.mode === "sample" ? "📁 PCAP" : "📡 Source";
  }

  // New session detection
  const isNewSession = snap.started_at !== liveSessionKey;
  if (isNewSession) {
    liveSessionKey = snap.started_at;
    seenFlowIds = new Set();
    seenAlertKeys = new Set();
    renderedFlowCount = 0;
    renderedAlertCount = 0;
    alertDetailsCache = new Map();
    dismissAlertBanner();
    document.getElementById("live-flows-body").innerHTML =
      '<tr><td colspan="10" style="text-align:center; padding:30px; color: var(--text-dim);">Waiting for flows…</td></tr>';
    document.getElementById("live-alerts-body").innerHTML =
      '<tr><td colspan="7" style="text-align:center; padding:20px; color: var(--text-dim);">No alerts</td></tr>';
    const srcBody = document.getElementById("attack-sources-body");
    if (srcBody) srcBody.innerHTML =
      '<tr><td colspan="4" style="text-align:center; padding:20px; color: var(--text-dim);">No attack sources detected</td></tr>';
  }

  appendLiveFlows(snap.recent_flows || []);
  appendLiveAlerts(snap.recent_alerts || [], { suppressBanner: isNewSession });
  renderDevices(snap);
  renderAttackSources(snap.recent_alerts || []);
}

function renderInjection(snap, running) {
  const statusEl = document.getElementById("inject-status");
  const btn = document.getElementById("inject-btn");
  const inj = snap.injection;
  if (!running) {
    statusEl.textContent = "start monitor first";
    btn.disabled = true;
  } else if (inj && inj.active) {
    statusEl.textContent = "⏳ " + inj.scenario + " · " + inj.packets_sent + "/" + inj.packets_total + " pkts";
    btn.disabled = true;
  } else if (inj) {
    const when = inj.finished_at ? new Date(inj.finished_at).toLocaleTimeString() : "";
    statusEl.textContent = "✓ " + inj.scenario + " done " + when;
    btn.disabled = false;
  } else {
    statusEl.textContent = "ready";
    btn.disabled = false;
  }
}

// ─── Flow Rendering ───
function appendLiveFlows(flows) {
  const fresh = flows.filter(f => !seenFlowIds.has(f.flow_id));
  if (fresh.length === 0) return;
  const tbody = document.getElementById("live-flows-body");
  if (renderedFlowCount === 0) tbody.innerHTML = "";

  fresh.forEach(flow => {
    seenFlowIds.add(flow.flow_id);
    renderedFlowCount++;
    const p = policyFor(flow.attack_score);
    const isAttack = flow.prediction_class === 1;
    const srcText = String(flow.src_endpoint);
    const dstText = String(flow.dst_endpoint);
    const isSim = srcText.startsWith("203.0.113.") || dstText.startsWith("203.0.113.");
    const gt = flow.ground_truth && flow.ground_truth !== "UNKNOWN" ? flow.ground_truth : "-";
    const time = flow.timestamp ? new Date(flow.timestamp).toLocaleTimeString() : "-";
    const score = Number(flow.attack_score);

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${flow.flow_id}</td>
      <td class="mono">${time}</td>
      <td><strong>${flow.protocol}</strong></td>
      <td class="mono">${escapeHtml(srcText)}${isSim ? ' <span class="badge badge-sim">SIM</span>' : ""}</td>
      <td class="mono">${escapeHtml(dstText)}</td>
      <td class="mono">${flow.packet_count}</td>
      <td class="mono"><strong style="color:${score >= 0.50 ? 'var(--red)' : score >= 0.20 ? 'var(--orange)' : 'var(--green)'}">${score.toFixed(4)}</strong></td>
      <td>${gt !== "-" ? `<span class="badge ${gt === "ATTACK" || gt.includes("ATTACK") ? "badge-red" : "badge-green"}">${escapeHtml(gt)}</span>` : '<span style="color:var(--text-dim)">—</span>'}</td>
      <td><span class="badge ${isAttack ? "badge-red" : "badge-green"}">${flow.prediction_label}</span></td>
      <td><span class="badge ${p.cls}">${p.action}</span></td>
    `;
    tbody.prepend(tr);
  });
  while (tbody.children.length > MAX_LIVE_ROWS) tbody.removeChild(tbody.lastChild);
}

function appendLiveAlerts(alerts, options = {}) {
  const fresh = alerts.filter(a => !seenAlertKeys.has(a.timestamp + "|" + a.flow_id));
  if (fresh.length === 0) return;
  const tbody = document.getElementById("live-alerts-body");
  if (renderedAlertCount === 0) tbody.innerHTML = "";

  fresh.forEach(alert => {
    const key = alert.flow_id + "|" + alert.timestamp;
    seenAlertKeys.add(key);
    alertDetailsCache.set(key, alert);
    renderedAlertCount++;
    const time = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : "-";
    const levelCls = alert.alert_level === "HIGH" ? "badge-red" : alert.alert_level === "MEDIUM" ? "badge-orange" : "badge-dim";

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${time}</td>
      <td><span class="badge ${levelCls}">${alert.alert_level}</span></td>
      <td class="mono"><strong>${Number(alert.confidence).toFixed(4)}</strong></td>
      <td class="mono">${escapeHtml(alert.src_endpoint)}</td>
      <td class="mono">${escapeHtml(alert.dst_endpoint)}</td>
      <td><strong>${alert.protocol}</strong></td>
      <td><button class="btn-link" data-alert-key="${key}" title="Inspect R10 features">🔍 Inspect</button></td>
    `;
    const btn = tr.querySelector("button[data-alert-key]");
    if (btn) btn.addEventListener("click", () => showAlertDetails(btn.dataset.alertKey));
    tbody.prepend(tr);
  });
  while (tbody.children.length > MAX_LIVE_ROWS) tbody.removeChild(tbody.lastChild);
  if (!options.suppressBanner) showAlertBanner(fresh[fresh.length - 1]);
}

// ─── Alert Banner ───
function showAlertBanner(alert) {
  const banner = document.getElementById("alert-banner");
  if (!banner) return;
  const score = Number(alert.confidence) || 0;
  const now = Date.now();
  if (score < bannerScore && now < bannerHoldUntil) return;
  const level = alert.alert_level || "ALERT";
  banner.className = "alert-banner visible" + (level === "HIGH" ? "" : level === "MEDIUM" ? " medium" : " low");
  document.getElementById("alert-banner-title").textContent = level + " ALERT";
  document.getElementById("alert-banner-text").textContent =
    "Score " + score.toFixed(4) + " · " + alert.src_endpoint + " → " +
    alert.dst_endpoint + " · " + alert.protocol + " · Flow #" + alert.flow_id;
  bannerScore = score;
  bannerHoldUntil = now + (score >= 0.65 ? 15000 : 5000);
}

function dismissAlertBanner() {
  const banner = document.getElementById("alert-banner");
  if (banner) banner.classList.remove("visible");
  bannerScore = 0;
  bannerHoldUntil = 0;
}

// ─── Alert Details Dialog ───
function showAlertDetails(key) {
  const alert = alertDetailsCache.get(key);
  if (!alert) return;
  const details = alert.details || {};
  const rows = Object.entries(details).length
    ? Object.entries(details).map(([n, v]) =>
        `<tr><td class="mono">${n}</td><td class="mono">${Number(v).toFixed(4)}</td></tr>`
      ).join("")
    : '<tr><td colspan="2" style="color:var(--text-dim)">No feature payload recorded</td></tr>';
  const score = Number(alert.confidence);
  const isSim = String(alert.src_endpoint).startsWith("203.0.113.") || String(alert.dst_endpoint).startsWith("203.0.113.");
  const gt = alert.ground_truth && alert.ground_truth !== "UNKNOWN" ? alert.ground_truth : null;
  const label = score >= 0.50 ? "ATTACK" : "BENIGN";

  document.getElementById("score-dialog-title").textContent = "Score Provenance — Flow #" + alert.flow_id;
  document.getElementById("score-dialog-body").innerHTML = `
    <p><strong>${alert.src_endpoint} → ${alert.dst_endpoint}</strong> · ${alert.protocol} ·
      ${alert.packet_count} pkts · ${Number(alert.duration_ms).toFixed(1)} ms
      ${isSim ? '<span class="badge badge-sim">SIM</span>' : ""}
      ${gt ? ' · Truth: <span class="badge badge-red">' + escapeHtml(gt) + '</span>' : ""}</p>
    <p style="margin-top:8px;">R10 feature values sent to the frozen detector:</p>
    <table><thead><tr><th>Feature</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table>
    <p style="margin-top:8px;">Frozen model output:</p>
    <pre>score = random_forest.predict_proba(preprocessor.transform(R10))[0]
      = ${score.toFixed(6)}
label = ${label} (research τ = 0.50)
alert = ${alert.alert_level} (HIGH ≥ 0.85, MEDIUM ≥ 0.65, LOW ≥ 0.50)</pre>
    <p style="margin-top:8px; color: var(--text-dim);">
      ${isSim ? "This flow came from the attack simulator. Packets were synthesized in memory." :
        "This flow came from the capture stream."}
      <strong>Nothing is blocked</strong> — policy suggestions are display-only.
    </p>
  `;
  const dialog = document.getElementById("score-dialog");
  if (typeof dialog.showModal === "function") dialog.showModal();
  else dialog.setAttribute("open", "");
}

function closeScoreDialog() {
  const dialog = document.getElementById("score-dialog");
  if (!dialog) return;
  if (typeof dialog.close === "function") dialog.close();
  else dialog.removeAttribute("open");
}

// ─── Attack Sources ───
function renderAttackSources(alerts) {
  const tbody = document.getElementById("attack-sources-body");
  if (!tbody) return;
  const byIp = new Map();
  (alerts || []).forEach(alert => {
    const src = String(alert.src_endpoint || "?");
    const ip = src.includes(":") ? src.slice(0, src.lastIndexOf(":")) : src;
    const e = byIp.get(ip) || { ip, alerts: 0, maxScore: 0, latest: "" };
    e.alerts++;
    e.maxScore = Math.max(e.maxScore, Number(alert.confidence) || 0);
    if (!e.latest || String(alert.timestamp) > e.latest) e.latest = alert.timestamp;
    byIp.set(ip, e);
  });
  const rows = Array.from(byIp.values()).sort((a, b) => b.maxScore - a.maxScore);
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:20px; color:var(--text-dim)">No attack sources</td></tr>';
    return;
  }
  tbody.innerHTML = "";
  rows.forEach(e => {
    const p = policyFor(e.maxScore);
    const isSim = e.ip.startsWith("203.0.113.");
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono"><strong>${e.ip}</strong>${isSim ? ' <span class="badge badge-sim">SIM</span>' : ""}</td>
      <td class="mono">${e.alerts}</td>
      <td class="mono"><strong style="color:var(--red)">${e.maxScore.toFixed(4)}</strong></td>
      <td><span class="badge ${p.cls}">${p.action}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

// ─── Devices ───
function formatAge(seconds) {
  const v = Number(seconds);
  if (!Number.isFinite(v) || v < 0) return "—";
  if (v < 5) return "now";
  if (v < 60) return Math.round(v) + "s";
  if (v < 3600) return Math.floor(v / 60) + "m";
  return Math.floor(v / 3600) + "h";
}

function renderDevices(snap) {
  const tbody = document.getElementById("devices-body");
  const networkEl = document.getElementById("device-network");
  const countEl = document.getElementById("device-count");
  const routerLink = document.getElementById("device-router-link");
  const routerAnchor = document.getElementById("router-admin-link");
  if (!tbody || !networkEl || !countEl) return;

  if (snap.mode !== "live") {
    if (routerLink) routerLink.style.display = "none";
    networkEl.textContent = snap.mode
      ? "Device discovery available in live capture mode only"
      : "Live capture not started";
    countEl.textContent = "0 observed";
    countEl.className = "badge badge-dim";
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px; color:var(--text-dim)">Start live capture to discover devices</td></tr>';
    return;
  }

  const network = snap.network || {};
  const parts = [];
  if (network.ssid) parts.push("SSID " + network.ssid);
  if (network.gateway_ip) parts.push("GW " + network.gateway_ip);
  if (network.local_ip) parts.push("PC " + network.local_ip);
  if (network.signal_dbm != null) parts.push(network.signal_dbm + " dBm");
  networkEl.textContent = parts.join(" · ") || "Live capture on " + (snap.interface || "interface");

  if (routerLink && routerAnchor) {
    const gw = String(network.gateway_ip || "");
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(gw)) {
      routerAnchor.href = "http://" + gw;
      routerLink.style.display = "";
    } else {
      routerLink.style.display = "none";
    }
  }

  const devices = snap.devices || [];
  const c = snap.device_counters || {};
  countEl.textContent = devices.length + " observed";
  countEl.className = "badge" + (devices.length ? " badge-blue" : " badge-dim");

  if (devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px; color:var(--text-dim)">Waiting for ARP/DHCP/mDNS traffic…</td></tr>';
    return;
  }

  tbody.innerHTML = "";
  devices.forEach(d => {
    const badges = [];
    if (d.is_local) badges.push('<span class="badge badge-blue">THIS PC</span>');
    if (d.is_gateway) badges.push('<span class="badge badge-orange">GATEWAY</span>');
    if (d.is_random_mac) badges.push('<span class="badge badge-dim">PRIVATE MAC</span>');
    const label = d.hostname || d.label || "Unknown";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${escapeHtml(label)}</strong><br>${badges.join(" ")}</td>
      <td class="mono">${escapeHtml(d.ip || "—")}</td>
      <td class="mono">${escapeHtml(d.mac || "—")}</td>
      <td>${escapeHtml(d.vendor || "Unknown")}</td>
      <td>${escapeHtml((d.evidence || []).join(", ") || "—")}</td>
      <td class="mono">${Number(d.packets || 0).toLocaleString()}</td>
      <td class="mono">${d.live_seen ? formatAge(d.age_s) : "cached"}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ─── Utilities ───
function formatDuration(s) {
  if (!s || s <= 0) return "0s";
  if (s < 60) return s.toFixed(1) + "s";
  const m = Math.floor(s / 60);
  const sec = Math.round(s % 60);
  return m + "m " + sec + "s";
}

// ─── Replay & Evidence ───
async function loadDashboard(benchmarkId) {
  const b = benchmarkId || currentBenchmark || "cicids2017";
  currentBenchmark = b;
  const statusEl = document.getElementById("status-text");
  try {
    if (statusEl) statusEl.textContent = "Loading " + b + "…";
    const res = await fetch("/api/data?benchmark=" + encodeURIComponent(b));
    if (!res.ok) throw new Error("Failed to load data");
    const data = await res.json();
    renderDashboard(data);
    if (statusEl) statusEl.textContent = "Updated " + new Date().toLocaleTimeString();
  } catch (err) {
    if (statusEl) statusEl.textContent = "Error: " + err.message;
  }
}

function switchBenchmark(benchmarkId) {
  currentBenchmark = benchmarkId;
  ["cicids2017", "cse2018", "unswnb15"].forEach(id => {
    const btn = document.getElementById("bench-btn-" + id);
    if (btn) {
      btn.className = (id === benchmarkId) ? "btn btn-sm btn-primary" : "btn btn-sm";
    }
  });
  loadDashboard(benchmarkId);
}

function renderDashboard(data) {
  if (data.benchmark_info) {
    const info = data.benchmark_info;
    const titleEl = document.getElementById("model-comparison-title");
    if (titleEl) titleEl.textContent = "Model Comparison — " + info.short_name;
    const nameEl = document.getElementById("bench-info-name");
    if (nameEl) nameEl.textContent = info.name;
    const descEl = document.getElementById("bench-info-desc");
    if (descEl) descEl.textContent = info.description || info.role;
    const contractEl = document.getElementById("bench-info-contract");
    if (contractEl) contractEl.textContent = "Contract: " + info.contract;
    const popEl = document.getElementById("bench-info-pop");
    if (popEl) popEl.textContent = "Population: " + info.test_population;
    const caveatEl = document.getElementById("benchmark-caveat-notice");
    if (caveatEl) {
      if (info.id === "cse2018") {
        caveatEl.innerHTML = "<strong>⚠️ Temporal holdout caveat:</strong> On the CSE-CIC-IDS2018 strict future-period holdout (22 Feb–2 Mar 2018), " +
          "the Random Forest scored <strong>F1 0.0113</strong> (recall 0.0068, ROC-AUC 0.3905) on 50,306 surviving future attacks, " +
          "demonstrating real-world vulnerability to temporal concept drift.";
      } else if (info.id === "unswnb15") {
        caveatEl.innerHTML = "<strong>⚠️ Degraded sensor schema (R4):</strong> Missing TCP flags (SYN, ACK, RST, FIN) in the original Argus flow exporter " +
          "forces a degraded 4-feature contract. Cross-dataset transfer from CIC-IDS2017 to UNSW-NB15 degraded by 18.5% F1.";
      } else {
        caveatEl.innerHTML = "<strong>🌟 Flagship Dual-Benchmark:</strong> Evaluated under the full canonical 10-feature R10 contract. " +
          "The Phase 2 Dueling DQN reinforcement learning response policies are calibrated against this distribution.";
      }
    }
  }

  const replay = data.replay;
  if (replay) {
    document.getElementById("val-packets").textContent = (replay.total_packets || 0).toLocaleString();
    document.getElementById("val-flows").textContent = (replay.total_flows || 0).toLocaleString();
    if (replay.metrics_research) {
      document.getElementById("val-res-acc").textContent = (replay.metrics_research.accuracy * 100).toFixed(1) + "%";
      document.getElementById("val-res-f1").textContent = "F1: " + replay.metrics_research.f1.toFixed(4) + " (τ = 0.50)";
    }
    if (replay.metrics_operational) {
      document.getElementById("val-ops-acc").textContent = (replay.metrics_operational.accuracy * 100).toFixed(1) + "%";
      document.getElementById("val-ops-f1").textContent = "F1: " + replay.metrics_operational.f1.toFixed(4) + " (τ = 0.40)";
    }

    const tbody = document.getElementById("flows-table-body");
    tbody.innerHTML = "";
    const flows = replay.flow_events || [];
    if (flows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" style="text-align:center; padding:20px; color:var(--text-dim)">No flows</td></tr>';
    } else {
      flows.forEach(flow => {
        const p = policyFor(flow.attack_score);
        const isAttack = flow.ground_truth_label === "ATTACK";
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="mono">${flow.flow_id}</td>
          <td><strong>${flow.protocol_name}</strong></td>
          <td class="mono">${flow.src_endpoint}</td>
          <td class="mono">${flow.dst_endpoint}</td>
          <td class="mono">${flow.packet_count}</td>
          <td class="mono">${flow.duration_ms.toFixed(1)}</td>
          <td class="mono"><strong style="color:${flow.attack_score >= 0.50 ? 'var(--red)' : 'var(--green)'}">${flow.attack_score.toFixed(4)}</strong></td>
          <td><span class="badge ${isAttack ? 'badge-red' : 'badge-green'}">${flow.ground_truth_label}</span></td>
          <td>${flow.prediction_label} (${flow.verdict})</td>
          <td><span class="badge ${p.cls}">${p.action}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }
  }

  renderModelComparison(data.model_comparison);

  // SHAP
  const shap = data.shap;
  if (shap && shap.global_importance) {
    const shapTbody = document.getElementById("shap-table-body");
    shapTbody.innerHTML = "";
    shap.global_importance.forEach(item => {
      const desc = FEATURE_DESCRIPTIONS[item.feature] || "Flow statistical metric";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono"><strong>#${item.rank}</strong></td>
        <td class="mono"><strong>${item.feature}</strong></td>
        <td class="mono">${item.mean_abs_shap.toFixed(4)}</td>
        <td style="color:var(--text-muted)">${desc}</td>
      `;
      shapTbody.appendChild(tr);
    });
  }

  // Figures
  const select = document.getElementById("figure-select");
  const currentVal = select.value;
  select.innerHTML = "";
  if (data.figures && data.figures.length > 0) {
    data.figures.forEach(fig => {
      const opt = document.createElement("option");
      opt.value = fig;
      opt.textContent = formatFigureName(fig);
      select.appendChild(opt);
    });
    select.value = (currentVal && data.figures.includes(currentVal)) ? currentVal : data.figures[0];
    changeFigure();
  } else {
    select.innerHTML = '<option value="">No figures found</option>';
  }
}

function renderModelComparison(comparison) {
  const tbody = document.getElementById("model-comparison-body");
  if (!tbody) return;
  if (!comparison || !comparison.models || Object.keys(comparison.models).length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--text-dim)">No model data found</td></tr>';
    return;
  }
  const labels = { random_forest: "Random Forest", lstm: "LSTM (5-flow)", fusion: "RF + LSTM Fusion" };
  const roles = { random_forest: "Live per-flow detector", lstm: "Offline sequence model", fusion: "Offline ensemble" };
  const fmt = entry => {
    if (!entry) return "—";
    let base = Number(entry.mean).toFixed(4) + " ± " + Number(entry.std).toFixed(4);
    if (entry.ci && entry.ci.lower != null && entry.ci.upper != null) {
      base += '<br><span style="font-size:10px; color:var(--text-dim)">95% CI [' +
        Number(entry.ci.lower).toFixed(4) + ", " + Number(entry.ci.upper).toFixed(4) + "]</span>";
    }
    return base;
  };
  tbody.innerHTML = "";
  ["random_forest", "lstm", "fusion"].forEach(name => {
    const model = comparison.models[name];
    if (!model) return;
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${labels[name] || name}</strong></td>
      <td class="mono">${fmt(model.accuracy)}</td>
      <td class="mono">${fmt(model.f1)}</td>
      <td class="mono">${fmt(model.roc_auc)}</td>
      <td style="color:var(--text-muted)">${roles[name] || ""}</td>
    `;
    tbody.appendChild(tr);
  });
}

function formatFigureName(f) {
  return f.replace(".png", "").replace(/_/g, " ").replace(/\b\w/g, l => l.toUpperCase());
}

function changeFigure() {
  const select = document.getElementById("figure-select");
  const display = document.getElementById("figure-display");
  const caption = document.getElementById("figure-caption");
  const val = select.value;
  if (val) {
    display.src = "/figures/" + val;
    display.style.display = "inline-block";
    caption.textContent = select.options[select.selectedIndex].text;
  } else {
    display.style.display = "none";
    caption.textContent = "";
  }
}

async function runAnalysis() {
  const btn = document.getElementById("run-btn");
  const statusEl = document.getElementById("status-text");
  btn.disabled = true;
  btn.textContent = "Running…";
  statusEl.textContent = "Executing replay pipeline…";
  try {
    const res = await fetch("/api/run-replay", { method: "POST" });
    if (!res.ok) throw new Error("Server " + res.status);
    const data = await res.json();
    renderDashboard(data);
    statusEl.textContent = "✓ Complete " + new Date().toLocaleTimeString();
  } catch (err) {
    statusEl.textContent = "Failed: " + err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "▶ Run Replay";
  }
}

// ─── Init ───
function handleUrlHash() {
  const hash = window.location.hash;
  if (hash === "#evidence") {
    showTab("evidence");
  } else if (hash === "#cse2018") {
    showTab("evidence");
    switchBenchmark("cse2018");
  } else if (hash === "#unswnb15") {
    showTab("evidence");
    switchBenchmark("unswnb15");
  } else if (hash === "#inspect") {
    const firstKey = alertDetailsCache.keys().next().value;
    if (firstKey) showAlertDetails(firstKey);
  } else if (hash === "#flows") {
    const el = document.getElementById("flow-counter");
    if (el) el.scrollIntoView({ behavior: "instant" });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  onLiveModeChange();
  loadDashboard();
  loadLiveInterfaces();
  loadScenarios();
  pollLive();
  setInterval(pollLive, LIVE_POLL_MS);
  window.addEventListener("hashchange", handleUrlHash);
  setTimeout(handleUrlHash, 800);
});
