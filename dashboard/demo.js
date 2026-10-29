/**
 * XRL-IDARS — Live Demonstration Logic (demo.js)
 * Clean, lightweight orchestrator for the 4-zone exhibition interface.
 */

let pollInterval = null;
let currentFilter = 'all';
let isRunningScenario = false;
let scenarioTimer = null;
let scenarioSecondsLeft = 120;
let selectedFlowId = null;
let cachedFlows = [];
let activeExplainingFlowId = null;
const flowExplanationCache = new Map();
let currentBenchmark = 'cicids2017';

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
  fetchOverviewBenchmark();
  startPolling();
});

// Fetch official benchmark data for Zone 4
async function fetchOverviewBenchmark() {
  try {
    const res = await fetch('/api/overview');
    if (!res.ok) return;
    const data = await res.json();
    // Benchmark strip is already populated with canonical figures in HTML,
    // but we can ensure dynamic consistency if needed.
  } catch (err) {
    console.warn('Could not fetch overview benchmark:', err);
  }
}

// Polling /api/live
function startPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(pollLiveSession, 800);
  pollLiveSession();
}

async function pollLiveSession() {
  try {
    const res = await fetch('/api/live');
    if (!res.ok) return;
    const session = await res.json();
    updateUIFromSession(session);
  } catch (err) {
    console.debug('Live polling tick error:', err);
  }
}

function updateUIFromSession(session) {
  if (session.benchmark) {
    currentBenchmark = session.benchmark;
  }
  const analysis = session.live_analysis || {};
  const counters = session.counters || {};

  // Zone 1: Light up pipeline strip if active
  const isRunning = session.status === 'running';
  animatePipeline(isRunning);

  // Zone 2: Update the 4 numbers only
  const tp = analysis.tp || 0;
  const fp = analysis.fp || 0;
  const fn = analysis.fn || 0;
  const total = counters.flows || (tp + fp + fn + (analysis.tn || 0));

  document.getElementById('cnt-total').textContent = total.toLocaleString();
  document.getElementById('cnt-tp').textContent = tp.toLocaleString();
  document.getElementById('cnt-fn').textContent = fn.toLocaleString();
  document.getElementById('cnt-fp').textContent = fp.toLocaleString();

  // Zone 3: Flow Stream list
  if (session.recent_flows && session.recent_flows.length > 0) {
    cachedFlows = session.recent_flows;
    renderFlowList(cachedFlows);

    // If no flow selected, select the newest
    if (selectedFlowId === null && cachedFlows.length > 0) {
      inspectFlow(cachedFlows[cachedFlows.length - 1]);
    }
  }
}

// Animate pipeline nodes
function animatePipeline(active) {
  const nodes = ['node-packet', 'node-features', 'node-detector', 'node-shap', 'node-action'];
  if (!active) {
    nodes.forEach(id => document.getElementById(id)?.classList.remove('active'));
    return;
  }

  const now = Date.now();
  const step = Math.floor((now / 400) % nodes.length);
  nodes.forEach((id, idx) => {
    const el = document.getElementById(id);
    if (el) {
      if (idx === step) {
        el.classList.add('active');
      } else {
        el.classList.remove('active');
      }
    }
  });
}

// Render Flow Stream
function renderFlowList(flows) {
  const container = document.getElementById('flow-stream-list');
  if (!container) return;

  const filtered = flows.filter(f => {
    const isAttack = f.prediction_label === 'ATTACK' || (f.attack_score >= 0.50);
    if (currentFilter === 'attacks') return isAttack;
    if (currentFilter === 'benign') return !isAttack;
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = '<div style="text-align: center; color: var(--text-dim); margin-top: 40px; font-size: 0.85rem;">No flows matching filter.</div>';
    return;
  }

  // Show up to 40 most recent in reverse chronological order
  const displayFlows = filtered.slice(-40).reverse();

  let html = '';
  displayFlows.forEach(flow => {
    const isSelected = selectedFlowId === flow.flow_id;
    const isAttack = flow.prediction_label === 'ATTACK' || (flow.attack_score >= 0.50);
    const scorePct = Math.round((flow.attack_score || 0) * 100);

    let actionBadge = '<span class="badge-action-allow">ALLOW</span>';
    if (scorePct >= 85) {
      actionBadge = '<span class="badge-action-block">BLOCK</span>';
    } else if (scorePct >= 50) {
      actionBadge = '<span class="badge-action-alert">ALERT</span>';
    }

    const typeBadge = isAttack 
      ? '<span class="badge-attack">ATTACK</span>' 
      : '<span class="badge-benign">BENIGN</span>';

    const barColor = isAttack ? 'var(--status-red)' : 'var(--status-green)';

    const isRuleTriggered = flow.rule_triggered && flow.rule_matches && flow.rule_matches.length > 0;
    const ruleBadge = isRuleTriggered
      ? `<span class="badge-rule" title="Deterministic Rule: ${escapeHtml(flow.rule_matches.join(', '))}">RULE: ${escapeHtml(flow.rule_matches[0])}</span>`
      : '';

    html += `
      <div class="flow-row ${isSelected ? 'selected' : ''}" onclick="onFlowRowClick(${flow.flow_id})">
        <div class="flow-main">
          <div class="flow-endpoints">${escapeHtml(flow.src_endpoint || '172.16.0.1')} → ${escapeHtml(flow.dst_endpoint || '192.168.10.50')}</div>
          <div class="flow-meta">Flow #${flow.flow_id} · ${flow.protocol || 'TCP'} · ${flow.packet_count || 10} pkts · ${flow.duration_ms || 120} ms</div>
        </div>
        <div class="flow-badge-group">
          <div class="flow-score-bar-bg" title="Attack Confidence: ${scorePct}%">
            <div class="flow-score-bar-fill" style="width: ${scorePct}%; background: ${barColor};"></div>
          </div>
          <span style="font-size: 0.76rem; font-weight: 700; font-family: monospace; min-width: 34px;">${scorePct}%</span>
          ${ruleBadge}
          ${typeBadge}
          ${actionBadge}
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

function onFlowRowClick(flowId) {
  selectedFlowId = flowId;
  const flow = cachedFlows.find(f => f.flow_id === flowId);
  if (flow) {
    inspectFlow(flow);
    renderFlowList(cachedFlows);
  }
}

// Populate "Why?" Card
function inspectFlow(flow) {
  if (!flow) return;
  selectedFlowId = flow.flow_id;
  const scorePct = Math.round((flow.attack_score || 0) * 100);

  // Headers & Meta
  const flowIdEl = document.getElementById('why-flow-id');
  const confEl = document.getElementById('why-confidence');
  const endpointsEl = document.getElementById('why-endpoints');

  if (flowIdEl) flowIdEl.textContent = `#${flow.flow_id} (${flow.protocol || 'TCP'})`;
  if (confEl) confEl.textContent = `${scorePct}%`;
  if (endpointsEl) endpointsEl.textContent = `${flow.src_endpoint || '172.16.0.1:49152'} → ${flow.dst_endpoint || '192.168.10.50:80'}`;

  const ruleRowEl = document.getElementById('why-rule-row');
  const ruleValEl = document.getElementById('why-rule-val');
  if (ruleRowEl && ruleValEl) {
    if (flow.rule_triggered && flow.rule_matches && flow.rule_matches.length > 0) {
      ruleRowEl.style.display = 'block';
      ruleValEl.textContent = flow.rule_matches.join(', ');
    } else {
      ruleRowEl.style.display = 'none';
    }
  }

  // Action badge
  const badgeEl = document.getElementById('why-action-badge');
  const policyActionEl = document.getElementById('why-policy-action');

  if (badgeEl && policyActionEl) {
    if (scorePct >= 85) {
      badgeEl.className = 'badge-action-block';
      badgeEl.textContent = 'BLOCK';
      policyActionEl.textContent = 'Cost-Optimal Gate: BLOCK / ISOLATE (Advisory)';
      policyActionEl.style.color = 'var(--status-red)';
    } else if (scorePct >= 50) {
      badgeEl.className = 'badge-action-alert';
      badgeEl.textContent = 'ALERT';
      policyActionEl.textContent = 'Cost-Optimal Gate: RATE_LIMIT / ALERT (Advisory)';
      policyActionEl.style.color = 'var(--status-amber)';
    } else {
      badgeEl.className = 'badge-action-allow';
      badgeEl.textContent = 'ALLOW';
      policyActionEl.textContent = 'Cost-Optimal Gate: ALLOW (Safe)';
      policyActionEl.style.color = 'var(--status-green)';
    }
  }

  const factorsContainer = document.getElementById('why-shap-factors');
  if (!factorsContainer) return;

  const flowId = flow.flow_id;
  activeExplainingFlowId = flowId;

  // If the flow does not have complete preserved features, show honest unavailable state
  if (!flow.features || typeof flow.features !== 'object' || Object.keys(flow.features).length === 0) {
    renderShapUnavailable(factorsContainer, 'TreeSHAP explanation unavailable for this flow.');
    return;
  }

  // Check cache
  if (flowExplanationCache.has(flowId)) {
    renderShapExplanation(factorsContainer, flowExplanationCache.get(flowId));
    return;
  }

  // Show loading indicator
  renderShapLoading(factorsContainer, flowId);

  // Request real TreeSHAP from /api/csv/explain
  fetch('/api/csv/explain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      flow_id: flow.flow_id,
      features: flow.features,
      benchmark: currentBenchmark,
    }),
  })
    .then(async res => {
      if (!res.ok) {
        let msg = 'TreeSHAP computation failed';
        try {
          const errData = await res.json();
          if (errData && errData.error) msg = errData.error;
        } catch (_) {}
        throw new Error(msg);
      }
      return await res.json();
    })
    .then(data => {
      // Discard stale responses if user clicked another flow
      if (activeExplainingFlowId !== flowId) return;

      if (!data || !data.features || !Array.isArray(data.features) || data.features.length === 0) {
        renderShapUnavailable(factorsContainer, 'TreeSHAP explanation unavailable for this flow.');
        return;
      }

      flowExplanationCache.set(flowId, data);
      renderShapExplanation(factorsContainer, data);
    })
    .catch(err => {
      if (activeExplainingFlowId !== flowId) return;
      console.warn(`TreeSHAP explanation failed for Flow #${flowId}:`, err);
      renderShapUnavailable(factorsContainer, 'TreeSHAP explanation unavailable for this flow.');
    });
}

function renderShapExplanation(container, data) {
  const rawFeatures = data.features || [];
  // Rank features strictly by absolute SHAP attribution
  const sorted = [...rawFeatures].sort((a, b) => Math.abs(b.shap_attribution) - Math.abs(a.shap_attribution));

  if (sorted.length === 0) {
    renderShapUnavailable(container, 'TreeSHAP explanation unavailable for this flow.');
    return;
  }

  let html = '';
  sorted.forEach((feat, idx) => {
    const isIncrease = feat.direction === 'INCREASES_THREAT' || feat.shap_attribution > 0;
    const sign = feat.shap_attribution > 0 ? '+' : '';
    const formattedShap = `${sign}${feat.shap_attribution.toFixed(4)}`;
    const formattedVal = formatFeatureVal(feat.value);
    const borderClass = isIncrease ? 'threat-increase' : 'threat-decrease';
    const valColor = isIncrease ? 'var(--status-red)' : 'var(--status-green)';
    const dirText = isIncrease
      ? '▲ Increases RF Attack Score'
      : '▼ Decreases RF Attack Score (Pushes Benign)';
    const dirColor = isIncrease ? 'var(--status-red)' : 'var(--status-green)';

    html += `
      <div class="shap-factor ${borderClass}">
        <div class="shap-factor-title">
          <span style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-main);">${idx + 1}. ${escapeHtml(feat.feature)}</span>
          <span style="color: ${valColor}; font-family: var(--font-mono); font-weight: 700; font-size: 0.76rem;">
            SHAP ${formattedShap}
          </span>
        </div>
        <div class="shap-factor-desc">
          Value: <strong style="color: var(--text-main); font-family: var(--font-mono);">${formattedVal}</strong> · 
          <span style="color: ${dirColor}; font-weight: 600;">${dirText}</span>
        </div>
      </div>
    `;
  });

  html += `
    <div class="shap-scientific-notice">
      <div style="font-weight: 700; color: var(--text-main); margin-bottom: 2px; font-size: 0.72rem;">
        Random Forest TreeSHAP Explanation
      </div>
      <div style="font-size: 0.69rem; color: var(--text-dim); line-height: 1.35;">
        Attributions indicate mathematical contribution to Random Forest tree decision splits, not proof of network-attack causality. TreeSHAP explains the Random Forest detector ONLY; it does not explain the LSTM or DQN.
      </div>
    </div>
  `;

  container.innerHTML = html;
}

function renderShapLoading(container, flowId) {
  container.innerHTML = `
    <div style="text-align: center; color: var(--text-dim); padding: 32px 12px; font-size: 0.82rem;">
      <div style="margin-bottom: 6px; font-weight: 600; color: var(--text-main);">Computing TreeSHAP Attributions...</div>
      <div style="font-size: 0.72rem; color: var(--text-muted);">
        Evaluating Random Forest tree decision splits for Flow #${flowId}
      </div>
    </div>
  `;
}

function renderShapUnavailable(container, message) {
  container.innerHTML = `
    <div style="text-align: center; color: var(--text-muted); padding: 32px 12px; font-size: 0.82rem;">
      <div style="color: var(--accent-amber); margin-bottom: 6px; font-weight: 600;">⚠️ Notice</div>
      <div>${escapeHtml(message || 'TreeSHAP explanation unavailable for this flow.')}</div>
      <div style="font-size: 0.72rem; color: var(--text-dim); margin-top: 6px;">
        Explanations require complete preserved inference features matching the model contract.
      </div>
    </div>
  `;
}

function formatFeatureVal(val) {
  if (val === null || val === undefined || isNaN(val)) return '0';
  const num = Number(val);
  if (Number.isInteger(num)) return num.toLocaleString();
  if (Math.abs(num) >= 1000) return num.toLocaleString(undefined, { maximumFractionDigits: 2 });
  if (Math.abs(num) < 0.001 && num !== 0) return num.toExponential(2);
  return num.toFixed(3);
}

// Flow Filter Buttons
function setFlowFilter(filter, btn) {
  currentFilter = filter;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderFlowList(cachedFlows);
}

// Start Stream Replay API
async function startStream(category = 'mixed', loop = true) {
  try {
    const res = await fetch('/api/live/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: 'dataset',
        benchmark: 'cicids2017',
        dataset_category: category,
        loop: loop,
        pace_speed: 1.5,
      }),
    });
    return await res.json();
  } catch (err) {
    console.error('Failed to start stream:', err);
  }
}

// Stop Stream API
async function stopReplayStream() {
  if (scenarioTimer) clearInterval(scenarioTimer);
  isRunningScenario = false;
  document.getElementById('scenario-progress').style.display = 'none';

  try {
    const res = await fetch('/api/live/stop', { method: 'POST' });
    const data = await res.json();
    return data;
  } catch (err) {
    console.error('Failed to stop stream:', err);
  }
}

// Inject attack scenario dropdown
async function handleInjectSelect(scenario) {
  if (!scenario) return;
  try {
    // If not running, start stream first
    await startStream('mixed', true);
    await fetch('/api/live/inject-attack', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: scenario }),
    });
  } catch (err) {
    console.error('Injection error:', err);
  } finally {
    document.getElementById('select-inject-attack').value = '';
  }
}

// 2-Minute Scripted Demonstration Scenario
async function startTwoMinuteScenario() {
  if (isRunningScenario) return;
  isRunningScenario = true;

  const progressContainer = document.getElementById('scenario-progress');
  const phaseLabel = document.getElementById('scenario-phase-name');
  const timeLabel = document.getElementById('scenario-time-remaining');
  const fillBar = document.getElementById('scenario-progress-fill');

  progressContainer.style.display = 'block';
  scenarioSecondsLeft = 120;

  // Step 1: Start clean stream with benign traffic
  await startStream('mixed', true);

  if (scenarioTimer) clearInterval(scenarioTimer);

  scenarioTimer = setInterval(async () => {
    scenarioSecondsLeft -= 1;
    const elapsed = 120 - scenarioSecondsLeft;
    const pct = (elapsed / 120) * 100;
    fillBar.style.width = `${pct}%`;
    timeLabel.textContent = `${scenarioSecondsLeft}s remaining`;

    // Phase management
    if (elapsed < 25) {
      phaseLabel.textContent = 'Phase 1: Normal Baseline Traffic (0:00 - 0:25)';
    } else if (elapsed === 25) {
      phaseLabel.textContent = 'Phase 2: PortScan Reconnaissance (0:25 - 0:55)';
      await fetch('/api/live/inject-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: 'port_sweep' }),
      });
    } else if (elapsed === 55) {
      phaseLabel.textContent = 'Phase 3: High-Rate DDoS Flood (0:55 - 1:25)';
      await fetch('/api/live/inject-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: 'syn_flood' }),
      });
    } else if (elapsed === 85) {
      phaseLabel.textContent = 'Phase 4: Low & Slow DoS (1:25 - 1:45)';
      await fetch('/api/live/inject-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: 'slowloris' }),
      });
    } else if (elapsed === 105) {
      phaseLabel.textContent = 'Phase 5: Baseline Recovery (1:45 - 2:00)';
    } else if (scenarioSecondsLeft <= 0) {
      // Completed!
      clearInterval(scenarioTimer);
      isRunningScenario = false;
      await stopReplayStream();
      showScorecard();
    }
  }, 1000);
}

// Show Final Scorecard Modal
function showScorecard() {
  const total = document.getElementById('cnt-total').textContent;
  const tp = document.getElementById('cnt-tp').textContent;
  const fp = document.getElementById('cnt-fp').textContent;
  const fn = document.getElementById('cnt-fn').textContent;

  document.getElementById('modal-flows').textContent = total || '120';
  document.getElementById('modal-caught').textContent = `${tp} caught`;
  document.getElementById('modal-false-alarms').textContent = fp || '0';

  const modal = document.getElementById('modal-scorecard');
  if (modal) modal.style.display = 'flex';
}

function closeScorecard() {
  const modal = document.getElementById('modal-scorecard');
  if (modal) modal.style.display = 'none';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
