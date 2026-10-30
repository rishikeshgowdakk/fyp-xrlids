/**
 * XRL-IDARS — Live Intrusion Detection & Autonomous Response Demonstration Logic
 * Orchestrates genuine Scapy packet capture, flow processing, TreeSHAP, and DQN advisory response.
 */

let pollInterval = null;
let selectedFlowId = null;
let cachedDetections = [];
const explanationCache = new Map();

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  startPolling();
});

function startPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(pollDemoStatus, 750);
  pollDemoStatus();
}

async function pollDemoStatus() {
  try {
    const res = await fetch('/api/demo/status');
    if (!res.ok) return;
    const data = await res.json();
    renderUI(data);
  } catch (err) {
    console.debug('Polling /api/demo/status error:', err);
  }
}

function renderUI(data) {
  if (!data) return;

  // 1. Status Badges
  const badgeStatus = document.getElementById('badge-capture-status');
  if (badgeStatus) {
    badgeStatus.textContent = data.capture_status || 'STOPPED';
    badgeStatus.className = 'status-badge ' + (data.capture_status ? data.capture_status.toLowerCase() : 'stopped');
  }

  const badgeMode = document.getElementById('badge-capture-mode');
  if (badgeMode) {
    badgeMode.textContent = data.mode || 'ISOLATED LAB';
  }

  const badgeModel = document.getElementById('badge-model-status');
  if (badgeModel) {
    const isLoaded = (data.model_status === 'LOADED');
    badgeModel.textContent = isLoaded ? 'MODEL LOADED' : 'MODEL ERROR';
    badgeModel.style.color = isLoaded ? 'var(--status-green)' : 'var(--status-red)';
    badgeModel.style.background = isLoaded ? 'var(--status-green-bg)' : 'var(--status-red-bg)';
    badgeModel.style.borderColor = isLoaded ? 'var(--status-green-border)' : 'var(--status-red-border)';
  }

  // Button disabled states
  const isRunning = (data.capture_status === 'RUNNING');
  const btnStart = document.getElementById('btn-start-monitoring');
  const btnStop = document.getElementById('btn-stop-monitoring');
  const btnLaunch = document.getElementById('btn-launch-sim');
  const btnStopSim = document.getElementById('btn-stop-sim');

  if (btnStart) btnStart.disabled = isRunning;
  if (btnStop) btnStop.disabled = !isRunning;
  if (btnLaunch) btnLaunch.disabled = !isRunning || (data.simulation && data.simulation.active);
  if (btnStopSim) btnStopSim.disabled = !(data.simulation && data.simulation.active);

  // 2. Metric Cards
  if (data.metrics) {
    const pEl = document.getElementById('cnt-packets');
    const fEl = document.getElementById('cnt-flows');
    const tEl = document.getElementById('cnt-threats');
    const aEl = document.getElementById('cnt-alerts');

    if (pEl) pEl.textContent = Number(data.metrics.packets_captured || 0).toLocaleString();
    if (fEl) fEl.textContent = Number(data.metrics.flows_processed || 0).toLocaleString();
    if (tEl) tEl.textContent = Number(data.metrics.threats_detected || 0).toLocaleString();
    if (aEl) aEl.textContent = Number(data.metrics.active_alerts || 0).toLocaleString();
  }

  // 3. Traffic Table
  renderTrafficTable(data.traffic || []);

  // 4. Detection Table
  renderDetectionTable(data.detections || []);

  // 5. Response Panel
  if (data.response) {
    const dqnEl = document.getElementById('resp-dqn-action');
    const gateEl = document.getElementById('resp-gate-decision');
    const enfEl = document.getElementById('resp-enforced-action');
    const notEl = document.getElementById('resp-notice');

    if (dqnEl) dqnEl.textContent = data.response.dqn_action || 'ALLOW';
    if (gateEl) {
      const isOverridden = Boolean(data.response.safety_override);
      gateEl.textContent = isOverridden ? 'OVERRIDDEN' : 'APPROVED';
      gateEl.style.color = isOverridden ? 'var(--status-amber)' : 'var(--status-green)';
    }
    if (enfEl) enfEl.textContent = data.response.enforced_action || 'ALLOW';
    if (notEl) {
      if (data.response.safety_override && data.response.override_reason) {
        notEl.textContent = 'Safety Gate Invariant Applied: ' + data.response.override_reason;
      } else {
        notEl.textContent = 'Mode: ADVISORY / DRY_RUN ONLY. Zero network mutations or firewall modifications applied.';
      }
    }
  }

  // 6. Latency Percentiles
  if (data.latency && data.latency.total_ms) {
    const p50 = document.getElementById('lat-p50');
    const p95 = document.getElementById('lat-p95');
    const p99 = document.getElementById('lat-p99');

    if (p50) p50.textContent = (data.latency.total_ms.p50 || 0).toFixed(1) + ' ms';
    if (p95) p95.textContent = (data.latency.total_ms.p95 || 0).toFixed(1) + ' ms';
    if (p99) p99.textContent = (data.latency.total_ms.p99 || 0).toFixed(1) + ' ms';
  }

  if (data.throughput) {
    const ppsEl = document.getElementById('tp-pps');
    const fpsEl = document.getElementById('tp-fps');
    if (ppsEl) ppsEl.textContent = (data.throughput.packets_per_second || 0).toFixed(1);
    if (fpsEl) fpsEl.textContent = (data.throughput.flows_per_second || 0).toFixed(1);
  }

  // 7. Event Timeline
  renderTimeline(data.events || []);

  // 8. Auto-select latest flow for Explainability if none selected
  if (!selectedFlowId && data.detections && data.detections.length > 0) {
    selectFlow(data.detections[0].flow_id);
  }
}

function renderTrafficTable(traffic) {
  const tbody = document.getElementById('tbody-traffic');
  if (!tbody) return;

  if (!traffic || traffic.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim); padding: 24px;">No traffic captured. Click "Start Monitoring" and launch a simulation.</td></tr>`;
    return;
  }

  tbody.innerHTML = traffic.map(item => {
    const timeStr = item.timestamp ? item.timestamp.split('T')[1].split('.')[0] : '--';
    return `
      <tr>
        <td>${escapeHtml(timeStr)}</td>
        <td><strong>#${Number(item.flow_id || 0)}</strong></td>
        <td><span class="badge badge-none">${escapeHtml(item.protocol || 'TCP')}</span></td>
        <td style="font-size: 0.73rem;">${escapeHtml(item.src_endpoint || '')} → ${escapeHtml(item.dst_endpoint || '')}</td>
        <td>${Number(item.packet_count || 0)}</td>
        <td>${Number(item.duration_ms || 0).toFixed(1)} ms</td>
      </tr>
    `;
  }).join('');
}

function renderDetectionTable(detections) {
  cachedDetections = detections || [];
  const tbody = document.getElementById('tbody-detection');
  if (!tbody) return;

  if (!detections || detections.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 24px;">Awaiting completed flow detections...</td></tr>`;
    return;
  }

  tbody.innerHTML = detections.map(d => {
    const isAttack = (d.result === 'ATTACK');
    const resBadge = isAttack ? '<span class="badge badge-attack">ATTACK</span>' : '<span class="badge badge-benign">BENIGN</span>';

    let srcBadge = '<span class="badge badge-none">NONE</span>';
    if (d.detection_source === 'RULE') srcBadge = '<span class="badge badge-rule">RULE</span>';
    else if (d.detection_source === 'HYBRID') srcBadge = '<span class="badge badge-hybrid">HYBRID</span>';
    else if (d.detection_source && d.detection_source.includes('RF')) srcBadge = '<span class="badge badge-rf">' + escapeHtml(d.detection_source) + '</span>';

    const rulesStr = (d.rule_matches && d.rule_matches.length > 0) ? d.rule_matches.join(', ') : 'None';
    const isSelected = (selectedFlowId === d.flow_id);

    return `
      <tr class="clickable ${isSelected ? 'selected' : ''}" onclick="selectFlow(${Number(d.flow_id)})">
        <td><strong>#${Number(d.flow_id)}</strong></td>
        <td>${resBadge}</td>
        <td>${srcBadge}</td>
        <td><strong>${(Number(d.attack_score || 0) * 100).toFixed(1)}%</strong></td>
        <td>${d.rf_score !== null && d.rf_score !== undefined ? (Number(d.rf_score) * 100).toFixed(1) + '%' : '--'}</td>
        <td>${d.fusion_score !== null && d.fusion_score !== undefined ? (Number(d.fusion_score) * 100).toFixed(1) + '%' : (d.lstm_score !== null && d.lstm_score !== undefined ? (Number(d.lstm_score) * 100).toFixed(1) + '%' : '--')}</td>
        <td style="font-size: 0.72rem; color: var(--text-muted);">${escapeHtml(rulesStr)}</td>
      </tr>
    `;
  }).join('');
}

function renderTimeline(events) {
  const container = document.getElementById('timeline-list');
  if (!container) return;

  if (!events || events.length === 0) {
    container.innerHTML = `<div style="text-align: center; color: var(--text-dim); padding: 16px;">No events recorded. Start monitoring to begin event logging.</div>`;
    return;
  }

  container.innerHTML = events.slice(0, 30).map(ev => {
    const timeStr = ev.timestamp ? ev.timestamp.split('T')[1].split('.')[0] : '--';
    let cls = '';
    if (ev.type && ev.type.includes('ALERT')) cls = 'alert';
    else if (ev.type && ev.type.includes('RULE')) cls = 'rule';
    else if (ev.type && ev.type.includes('DQN')) cls = 'dqn';

    return `
      <div class="timeline-item ${cls}">
        <span class="timeline-time">${escapeHtml(timeStr)}</span>
        <span class="timeline-src">${escapeHtml(ev.source || 'SYS')}</span>
        <span class="timeline-msg">${escapeHtml(ev.message || '')}</span>
      </div>
    `;
  }).join('');
}

// Select a flow and fetch exact TreeSHAP attribution
async function selectFlow(flowId) {
  selectedFlowId = Number(flowId);
  const flowLabel = document.getElementById('shap-flow-id');
  if (flowLabel) flowLabel.textContent = '#' + selectedFlowId;

  // Re-render table selection highlight
  renderDetectionTable(cachedDetections);

  // Check cache
  if (explanationCache.has(selectedFlowId)) {
    renderShapExplanation(explanationCache.get(selectedFlowId));
    return;
  }

  const container = document.getElementById('shap-bars-container');
  if (container) {
    container.innerHTML = `<div style="text-align: center; color: var(--text-dim); padding: 24px 8px;">Computing TreeSHAP local attribution for Flow #${selectedFlowId}...</div>`;
  }

  try {
    // Call server /api/csv/explain
    const res = await fetch('/api/csv/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ flow_id: selectedFlowId, benchmark: 'cicids2017' })
    });

    if (!res.ok) {
      // Fallback to /api/demo/explain
      const resDemo = await fetch('/api/demo/explain?flow_id=' + selectedFlowId);
      if (resDemo.ok) {
        const demoData = await resDemo.json();
        if (demoData.status === 'ok') {
          explanationCache.set(selectedFlowId, demoData);
          renderShapExplanation(demoData);
          return;
        }
      }
      showShapUnavailable();
      return;
    }

    const data = await res.json();
    explanationCache.set(selectedFlowId, data);
    renderShapExplanation(data);
  } catch (err) {
    console.debug('TreeSHAP fetch error:', err);
    showShapUnavailable();
  }
}

function showShapUnavailable() {
  const container = document.getElementById('shap-bars-container');
  if (container) {
    container.innerHTML = `<div style="text-align: center; color: var(--status-amber); padding: 24px 8px; font-weight: 600;">TreeSHAP explanation unavailable for this flow.</div>`;
  }
}

function renderShapExplanation(data) {
  const container = document.getElementById('shap-bars-container');
  if (!container) return;

  const baseValEl = document.getElementById('shap-base-val');
  if (baseValEl && data.base_value !== undefined) {
    baseValEl.textContent = Number(data.base_value).toFixed(3);
  }

  const feats = data.top_features || data.features || [];
  if (!feats || feats.length === 0) {
    showShapUnavailable();
    return;
  }

  // Max absolute attribution for scale
  let maxAttr = 0.0001;
  feats.forEach(f => {
    const a = Math.abs(Number(f.shap_attribution !== undefined ? f.shap_attribution : (f.attribution || 0)));
    if (a > maxAttr) maxAttr = a;
  });

  const barsHtml = feats.slice(0, 7).map(f => {
    const attr = Number(f.shap_attribution !== undefined ? f.shap_attribution : (f.attribution || 0));
    const val = (f.value !== undefined) ? Number(f.value) : 0;
    const isPos = (attr >= 0);
    const widthPct = Math.min(100, Math.round((Math.abs(attr) / maxAttr) * 100));

    const barFill = isPos
      ? `<div class="shap-bar-fill-pos" style="width: ${widthPct}%; margin-left: 0;"></div>`
      : `<div class="shap-bar-fill-neg" style="width: ${widthPct}%; margin-left: auto;"></div>`;

    const sign = isPos ? '+' : '';
    const colorStyle = isPos ? 'color: var(--status-red);' : 'color: var(--accent);';

    return `
      <div class="shap-bar-row">
        <span class="shap-feat-name" title="${escapeHtml(f.feature || '')}">${escapeHtml(f.feature || '')}</span>
        <span class="shap-feat-val">${val.toFixed(1)}</span>
        <div class="shap-bar-track">
          ${barFill}
        </div>
        <span class="shap-attr-val" style="${colorStyle}">${sign}${attr.toFixed(4)}</span>
      </div>
    `;
  }).join('');

  container.innerHTML = barsHtml;
}

// ---------------------------------------------------- User Actions
async function startMonitoring() {
  try {
    const res = await fetch('/api/demo/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'isolated_lab', benchmark: 'cicids2017' })
    });
    const data = await res.json();
    if (data.error) {
      alert('Error starting monitoring: ' + data.error);
    }
    pollDemoStatus();
  } catch (err) {
    alert('Failed to start monitoring: ' + err.message);
  }
}

async function stopMonitoring() {
  try {
    await fetch('/api/demo/stop', { method: 'POST' });
    pollDemoStatus();
  } catch (err) {
    console.error('Stop monitoring failed:', err);
  }
}

async function resetSession() {
  try {
    selectedFlowId = null;
    explanationCache.clear();
    await fetch('/api/demo/reset', { method: 'POST' });
    pollDemoStatus();
  } catch (err) {
    console.error('Reset session failed:', err);
  }
}

async function launchSimulation() {
  const sel = document.getElementById('select-scenario');
  const scId = sel ? sel.value : 'scenario_a_benign';

  try {
    const res = await fetch('/api/demo/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: scId, speed: 1.0 })
    });
    const data = await res.json();
    if (data.error) {
      alert('Simulation error: ' + data.error);
    }
    pollDemoStatus();
  } catch (err) {
    alert('Failed to launch simulation: ' + err.message);
  }
}

async function stopSimulation() {
  try {
    await fetch('/api/demo/simulate/stop', { method: 'POST' });
    pollDemoStatus();
  } catch (err) {
    console.error('Stop simulation failed:', err);
  }
}

function exportData(format) {
  window.location.href = '/api/demo/export?format=' + encodeURIComponent(format);
}

// Backward compatibility function required by tests
function startTwoMinuteScenario() {
  startMonitoring().then(() => {
    launchSimulation();
  });
}

function escapeHtml(str) {
  if (typeof str !== 'string') return String(str || '');
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
