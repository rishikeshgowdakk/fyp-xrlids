// XRL-IDARS zero-dependency dashboard: Live Monitor + Replay & Evidence views.

const FEATURE_DESCRIPTIONS = {
  "packet_length_std": "Standard deviation of packet lengths in the flow (high variance indicates data transfers vs scans)",
  "packet_length_mean": "Mean packet length in bytes across forward and backward packets",
  "flow_packets_per_s": "Rate of packets transferred per second (floods and DoS exhibit extreme spikes)",
  "flow_bytes_per_s": "Throughput in bytes per second across the flow lifetime",
  "flow_duration_ms": "Total active duration of the bidirectional flow in milliseconds",
  "ack_count": "Total count of TCP ACK flags observed in both directions",
  "fin_count": "Total count of TCP FIN flags observed indicating graceful connection closure",
  "syn_count": "Total count of TCP SYN flags observed (high count without ACK indicates SYN flood)",
  "syn_ack_ratio": "Ratio of SYN flags to ACK flags in the flow handshake",
  "rst_count": "Total count of TCP RST flags observed indicating aborted connections"
};

const LIVE_POLL_MS = 1000;
const MAX_LIVE_ROWS = 500;
const LIVE_NOTICE_TEXT = "Observational only — this console never modifies firewall, routing, or traffic. " +
  "Live traffic has no ground truth, so accuracy is not claimed here; the score is the frozen CIC-IDS2017 " +
  "Random Forest output (research \u03C4 = 0.50). Flow completion follows the D-006 policy (TCP FIN/RST or 120 s idle timeout).";

let liveSessionKey = null;
let seenFlowIds = new Set();
let seenAlertKeys = new Set();
let renderedFlowCount = 0;
let renderedAlertCount = 0;
let scenariosCache = [];

// ---------------------------------------------------------------- tabs
function showTab(name) {
  document.getElementById("tab-live").style.display = name === "live" ? "block" : "none";
  document.getElementById("tab-evidence").style.display = name === "evidence" ? "block" : "none";
  document.querySelectorAll(".tab").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === name);
  });
}

// ---------------------------------------------------------------- live monitor
function determineResponseAction(score) {
  // Matches Dueling DQN response policy mapping (observational display only;
  // the dashboard never actuates — no firewall or routing mutations).
  if (score >= 0.50) {
    return { action: "BLOCK", badgeClass: "badge-invert" };
  } else if (score >= 0.40) {
    return { action: "THROTTLE", badgeClass: "badge" };
  } else if (score >= 0.20) {
    return { action: "MONITOR", badgeClass: "badge" };
  } else {
    return { action: "ALLOW", badgeClass: "badge" };
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
    if (data.permissions && !data.permissions.raw_socket) {
      const status = document.getElementById("live-status");
      if (!status.textContent.startsWith("running")) {
        status.textContent = "stopped · raw sockets denied (sudo needed for live capture; sample stream available)";
      }
    }
  } catch (err) {
    /* transient; keep the page usable */
  }
}

// ---------------------------------------------------------------- attack simulator
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
  } catch (err) {
    /* transient; keep the page usable */
  }
}

function scenarioExpectationText(spec) {
  if (!spec) return "—";
  if (spec.expected_band === "NONE") {
    return "calibrated: NOT DETECTED (evasion demo)";
  }
  return "calibrated: " + spec.expected_band + " · score ≈ " + Number(spec.expected_score).toFixed(3);
}

function renderScenarioInfo() {
  const select = document.getElementById("scenario-select");
  const spec = scenariosCache.find(s => s.id === select.value);
  const badge = document.getElementById("scenario-expectation");
  const desc = document.getElementById("scenario-desc");
  if (!spec) {
    badge.textContent = "—";
    badge.className = "badge";
    desc.textContent = "";
    return;
  }
  badge.textContent = scenarioExpectationText(spec);
  badge.className = "badge" + (spec.expected_band === "NONE" ? "" : " badge-invert");
  desc.textContent = spec.description + " — " + spec.packet_count + " packets, " +
    spec.expected_flows + " flow(s), " + Number(spec.duration_s).toFixed(2) + " s " +
    "(attacker " + spec.attacker_ip + " → " + spec.victim_ip + ")";
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
    if (data.error) {
      statusEl.textContent = "error: " + data.error;
    } else {
      statusEl.textContent = "injecting " + select.value + " …";
    }
  } catch (err) {
    statusEl.textContent = "error: " + err.message;
  } finally {
    pollLive();
  }
}

async function pollLive() {
  try {
    const res = await fetch("/api/live");
    if (!res.ok) throw new Error("HTTP " + res.status);
    renderLive(await res.json());
  } catch (err) {
    /* transient poll failure; next tick retries */
  }
}

function renderLive(snap) {
  const running = snap.status === "running";
  const statusEl = document.getElementById("live-status");
  if (running) {
    statusEl.textContent = snap.mode === "live"
      ? "running · live:" + (snap.interface || "?") + (snap.bpf_filter ? " · filter: " + snap.bpf_filter : "")
      : "running · sample stream (bundled demo capture)";
  } else if (snap.status === "error") {
    statusEl.textContent = "error";
  } else {
    statusEl.textContent = "stopped";
  }
  document.getElementById("live-dot").className = "dot" + (running ? " live" : "");
  document.getElementById("live-start-btn").disabled = running;
  document.getElementById("live-stop-btn").disabled = !running;

  document.getElementById("lv-packets").textContent = (snap.counters.packets || 0).toLocaleString();
  document.getElementById("lv-flows").textContent = (snap.counters.flows || 0).toLocaleString();
  document.getElementById("lv-alerts").textContent = (snap.counters.alerts || 0).toLocaleString();
  document.getElementById("lv-rate").textContent = (snap.counters.packets_per_s || 0).toFixed(1) + " pkt/s";
  document.getElementById("lv-elapsed").textContent = formatDuration(snap.counters.elapsed_s || 0);
  document.getElementById("lv-mode-label").textContent = snap.started_at
    ? "started " + new Date(snap.started_at).toLocaleTimeString()
    : "not started";

  renderInjectionStatus(snap, running);

  const notice = document.getElementById("live-notice");
  if (snap.error) {
    notice.className = "notice error";
    notice.textContent = "Session error: " + snap.error;
  } else if (snap.engine_warning) {
    notice.className = "notice error";
    notice.textContent = snap.engine_warning;
  } else {
    notice.className = "notice";
    notice.textContent = LIVE_NOTICE_TEXT;
  }

  if (snap.started_at !== liveSessionKey) {
    // New session (or cleared): reset rendered rows.
    liveSessionKey = snap.started_at;
    seenFlowIds = new Set();
    seenAlertKeys = new Set();
    renderedFlowCount = 0;
    renderedAlertCount = 0;
    document.getElementById("live-flows-body").innerHTML =
      '<tr><td colspan="10" style="text-align: center;">Waiting for the first completed flow…</td></tr>';
    document.getElementById("live-alerts-body").innerHTML =
      '<tr><td colspan="7" style="text-align: center;">No alerts.</td></tr>';
  }

  appendLiveFlows(snap.recent_flows || []);
  appendLiveAlerts(snap.recent_alerts || []);
}

function renderInjectionStatus(snap, running) {
  const statusEl = document.getElementById("inject-status");
  const btn = document.getElementById("inject-btn");
  const inj = snap.injection;
  if (!running) {
    statusEl.textContent = "idle (start the monitor to inject)";
    btn.disabled = true;
  } else if (inj && inj.active) {
    statusEl.textContent = "injecting " + inj.scenario + " · " + inj.packets_sent + "/" + inj.packets_total +
      " packets · expected " + (inj.expected_band === "NONE" ? "not detected" : inj.expected_band + " ≈ " +
      Number(inj.expected_score).toFixed(3));
    btn.disabled = true;
  } else if (inj) {
    const when = inj.finished_at ? new Date(inj.finished_at).toLocaleTimeString() : "";
    statusEl.textContent = "last injection: " + inj.scenario + " finished " + when +
      " · expected " + (inj.expected_band === "NONE" ? "not detected" : inj.expected_band + " ≈ " +
      Number(inj.expected_score).toFixed(3));
    btn.disabled = false;
  } else {
    statusEl.textContent = "idle";
    btn.disabled = false;
  }
}

function appendLiveFlows(flows) {
  const fresh = flows.filter(f => !seenFlowIds.has(f.flow_id));
  if (fresh.length === 0) return;
  const tbody = document.getElementById("live-flows-body");
  if (renderedFlowCount === 0) {
    tbody.innerHTML = "";
  }
  fresh.forEach(flow => {
    seenFlowIds.add(flow.flow_id);
    renderedFlowCount++;
    const actionInfo = determineResponseAction(flow.attack_score);
    const isAttack = flow.prediction_class === 1;
    const srcText = String(flow.src_endpoint);
    const dstText = String(flow.dst_endpoint);
    const isSim = srcText.startsWith("203.0.113.") || dstText.startsWith("203.0.113.");
    const tr = document.createElement("tr");
    const time = flow.timestamp ? new Date(flow.timestamp).toLocaleTimeString() : "-";
    tr.innerHTML = `
      <td class="mono">${flow.flow_id}</td>
      <td class="mono">${time}</td>
      <td><strong>${flow.protocol}</strong></td>
      <td class="mono">${srcText}${isSim ? ' <span class="badge" title="Attack simulator packet (synthetic, in-memory injection)">SIM</span>' : ""}</td>
      <td class="mono">${dstText}</td>
      <td class="mono">${flow.packet_count}</td>
      <td class="mono">${Number(flow.duration_ms).toFixed(1)}</td>
      <td class="mono"><strong>${Number(flow.attack_score).toFixed(4)}</strong></td>
      <td><span class="badge ${isAttack ? "badge-invert" : ""}">${flow.prediction_label}</span></td>
      <td><span class="badge ${actionInfo.badgeClass}">${actionInfo.action}</span></td>
    `;
    tbody.prepend(tr);
  });
  while (tbody.children.length > MAX_LIVE_ROWS) {
    tbody.removeChild(tbody.lastChild);
  }
}

function appendLiveAlerts(alerts) {
  const fresh = alerts.filter(a => !seenAlertKeys.has(a.timestamp + "|" + a.flow_id));
  if (fresh.length === 0) return;
  const tbody = document.getElementById("live-alerts-body");
  if (renderedAlertCount === 0) {
    tbody.innerHTML = "";
  }
  fresh.forEach(alert => {
    seenAlertKeys.add(alert.timestamp + "|" + alert.flow_id);
    renderedAlertCount++;
    const tr = document.createElement("tr");
    const time = alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : "-";
    tr.innerHTML = `
      <td class="mono">${time}</td>
      <td><span class="badge ${alert.alert_level === "HIGH" ? "badge-invert" : ""}">${alert.alert_level}</span></td>
      <td class="mono">${Number(alert.confidence).toFixed(4)}</td>
      <td class="mono">${alert.src_endpoint}</td>
      <td class="mono">${alert.dst_endpoint}</td>
      <td><strong>${alert.protocol}</strong></td>
      <td class="mono">${alert.packet_count}</td>
    `;
    tbody.prepend(tr);
  });
  while (tbody.children.length > MAX_LIVE_ROWS) {
    tbody.removeChild(tbody.lastChild);
  }
}

async function startLive() {
  const mode = document.getElementById("live-mode").value;
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
      body: JSON.stringify({ mode: mode, interface: interfaceName || null, bpf_filter: bpf || null })
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
    notice.textContent = "Could not start capture: " + err.message;
    btn.disabled = false;
  } finally {
    btn.textContent = "Start Capture";
    pollLive();
  }
}

async function stopLive() {
  const btn = document.getElementById("live-stop-btn");
  btn.disabled = true;
  btn.textContent = "Stopping…";
  try {
    const res = await fetch("/api/live/stop", { method: "POST" });
    if (res.ok) {
      renderLive(await res.json());
    }
  } catch (err) {
    /* transient */
  } finally {
    btn.textContent = "Stop";
    pollLive();
  }
}

function formatDuration(seconds) {
  if (!seconds || seconds <= 0) return "0s";
  if (seconds < 60) return seconds.toFixed(1) + "s";
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return m + "m " + s + "s";
}

// ---------------------------------------------------------------- replay & evidence
async function loadDashboard() {
  const statusEl = document.getElementById("status-text");
  try {
    statusEl.textContent = "Loading data...";
    const res = await fetch("/api/data");
    if (!res.ok) throw new Error("Failed to load data");
    const data = await res.json();
    renderDashboard(data);
    statusEl.textContent = "Updated " + new Date().toLocaleTimeString();
  } catch (err) {
    statusEl.textContent = "Error: " + err.message;
  }
}

function renderDashboard(data) {
  const replay = data.replay;
  if (replay) {
    document.getElementById("val-packets").textContent = replay.total_packets || 0;
    document.getElementById("val-flows").textContent = replay.total_flows || 0;

    if (replay.metrics_research) {
      document.getElementById("val-res-acc").textContent = (replay.metrics_research.accuracy * 100).toFixed(1) + "%";
      document.getElementById("val-res-f1").textContent = "F1: " + replay.metrics_research.f1.toFixed(4) + " (tau = 0.50)";
    }

    if (replay.metrics_operational) {
      document.getElementById("val-ops-acc").textContent = (replay.metrics_operational.accuracy * 100).toFixed(1) + "%";
      document.getElementById("val-ops-f1").textContent = "F1: " + replay.metrics_operational.f1.toFixed(4) + " (tau = 0.40)";
    }

    const tbody = document.getElementById("flows-table-body");
    tbody.innerHTML = "";

    const flows = replay.flow_events || [];
    if (flows.length === 0) {
      tbody.innerHTML = '<tr><td colspan="10" style="text-align: center;">No flows available</td></tr>';
    } else {
      flows.forEach(flow => {
        const tr = document.createElement("tr");
        const actionInfo = determineResponseAction(flow.attack_score);
        const isAttackTruth = flow.ground_truth_label === "ATTACK";

        tr.innerHTML = `
          <td class="mono">${flow.flow_id}</td>
          <td><strong>${flow.protocol_name}</strong></td>
          <td class="mono">${flow.src_endpoint}</td>
          <td class="mono">${flow.dst_endpoint}</td>
          <td class="mono">${flow.packet_count}</td>
          <td class="mono">${flow.duration_ms.toFixed(1)}</td>
          <td class="mono"><strong>${flow.attack_score.toFixed(4)}</strong></td>
          <td><span class="badge ${isAttackTruth ? 'badge-invert' : ''}">${flow.ground_truth_label}</span></td>
          <td>${flow.prediction_label} (${flow.verdict})</td>
          <td><span class="badge ${actionInfo.badgeClass}">${actionInfo.action}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }
  }

  // SHAP Table
  const shap = data.shap;
  if (shap && shap.global_importance) {
    const shapTbody = document.getElementById("shap-table-body");
    shapTbody.innerHTML = "";
    shap.global_importance.forEach(item => {
      const tr = document.createElement("tr");
      const desc = FEATURE_DESCRIPTIONS[item.feature] || "Flow statistical metric";
      tr.innerHTML = `
        <td class="mono"><strong>#${item.rank}</strong></td>
        <td class="mono"><strong>${item.feature}</strong></td>
        <td class="mono">${item.mean_abs_shap.toFixed(4)}</td>
        <td>${desc}</td>
      `;
      shapTbody.appendChild(tr);
    });
  }

  // Figures Select
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
    if (currentVal && data.figures.includes(currentVal)) {
      select.value = currentVal;
    } else {
      select.value = data.figures[0];
    }
    changeFigure();
  } else {
    select.innerHTML = '<option value="">No figures found</option>';
  }
}

function formatFigureName(filename) {
  return filename
    .replace(".png", "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, l => l.toUpperCase());
}

function changeFigure() {
  const select = document.getElementById("figure-select");
  const display = document.getElementById("figure-display");
  const caption = document.getElementById("figure-caption");
  const val = select.value;

  if (val) {
    display.src = "/figures/" + val;
    display.style.display = "inline-block";
    caption.textContent = "Viewing: " + select.options[select.selectedIndex].text + " (reports/figures/" + val + ")";
  } else {
    display.style.display = "none";
    caption.textContent = "";
  }
}

async function runAnalysis() {
  const btn = document.getElementById("run-btn");
  const statusEl = document.getElementById("status-text");

  btn.disabled = true;
  btn.textContent = "Running Analysis...";
  statusEl.textContent = "Executing packet-to-prediction replay pipeline...";

  try {
    const res = await fetch("/api/run-replay", { method: "POST" });
    if (!res.ok) throw new Error("Server returned " + res.status);
    const data = await res.json();
    renderDashboard(data);
    statusEl.textContent = "Replay complete! Updated " + new Date().toLocaleTimeString();
  } catch (err) {
    statusEl.textContent = "Execution failed: " + err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "Run Replay Analysis";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  loadDashboard();
  loadLiveInterfaces();
  loadScenarios();
  pollLive();
  setInterval(pollLive, LIVE_POLL_MS);
});
