// XRL-IDARS Research Evaluation Workbench — Client Application
// Zero external dependencies. Connects to server.py APIs.

let currentEvalBenchmark = "cicids2017";
let currentEvalSlice = "aligned";
let currentEvalModel = "fusion";
let evalDataCache = null;

let currentFlowPage = 1;
let currentFlowFilterStatus = "all";
let currentFlowFilterLabel = "all";

const LIVE_POLL_MS = 1000;
let liveSessionActive = false;
let seenFlowIds = new Set();
let seenAlertKeys = new Set();
let alertDetailsCache = new Map();

function escapeHtml(v) {
  return String(v === null || v === undefined ? "" : v)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function fmt(num, decimals = 4) {
  if (num === null || num === undefined || isNaN(num)) return "—";
  return Number(num).toFixed(decimals);
}

// ─── Tab Switching ───
function showTab(name) {
  if (name === "evidence") {
    name = "evaluation"; // Backward-compatibility
  }
  document.querySelectorAll(".tab-content").forEach(el => {
    el.classList.toggle("active", el.id === "tab-" + name);
  });
  document.querySelectorAll(".topbar-tabs button").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === name || (name === "evaluation" && btn.dataset.tab === "evidence"));
  });

  // Lazy-load data when switching tabs
  if (name === "evaluation") {
    loadEvaluation();
  } else if (name === "overview") {
    loadOverview();
  } else if (name === "comparison") {
    loadComparison();
  } else if (name === "flows") {
    loadFlows();
  } else if (name === "explainability") {
    loadExplainability();
  } else if (name === "response") {
    loadResponseBenchmark();
  } else if (name === "limitations") {
    loadLimitations();
  }
}

// ─── PAGE B: Dataset Evaluation ───
async function loadEvaluation() {
  const benchSelect = document.getElementById("eval-benchmark-select");
  const sliceSelect = document.getElementById("eval-slice-select");
  if (benchSelect) currentEvalBenchmark = benchSelect.value;
  if (sliceSelect) currentEvalSlice = sliceSelect.value;

  try {
    const res = await fetch(`/api/evaluation?benchmark=${currentEvalBenchmark}&slice=${currentEvalSlice}`);
    if (!res.ok) throw new Error("Server returned " + res.status);
    const data = await res.json();
    evalDataCache = data;
    renderEvaluation(data);
  } catch (err) {
    console.error("Failed to load evaluation data:", err);
  }
}

function onEvalBenchmarkChange() {
  currentEvalBenchmark = document.getElementById("eval-benchmark-select").value;
  loadEvaluation();
}

function onEvalSliceChange() {
  currentEvalSlice = document.getElementById("eval-slice-select").value;
  loadEvaluation();
}

function onEvalModelSelect() {
  currentEvalModel = document.getElementById("eval-model-select").value;
  if (evalDataCache) {
    renderEvaluation(evalDataCache);
  }
}

function renderEvaluation(data) {
  if (!data || !data.models) return;

  // Derivation notice
  const derivEl = document.getElementById("pop-derivation-text");
  if (derivEl) {
    derivEl.textContent = `${data.population.toLocaleString()} test flows. ${data.dropped_derivation || ""}`;
  }

  // Model selection
  const modelKey = currentEvalModel in data.models ? currentEvalModel : (data.models.fusion ? "fusion" : Object.keys(data.models)[0]);
  const model = data.models[modelKey] || {};

  // High-level tiles
  document.getElementById("eval-accuracy").textContent = model.accuracy != null ? (model.accuracy * 100).toFixed(2) + "%" : "—";
  document.getElementById("eval-precision").textContent = fmt(model.precision);
  document.getElementById("eval-recall").textContent = fmt(model.recall);
  document.getElementById("eval-f1").textContent = fmt(model.f1);

  // Model details
  document.getElementById("m-arch").textContent = model.family ? `${model.family} (${modelKey})` : modelKey;
  document.getElementById("m-contract").textContent = data.benchmark.contract || "R10";
  document.getElementById("m-thresh").textContent = `τ = ${fmt(model.threshold || 0.50, 2)} (Positive: Class 1)`;
  document.getElementById("m-auc").textContent = `ROC: ${fmt(model.roc_auc)} | PR: ${fmt(model.pr_auc)}`;

  // Confusion matrix
  const conf = model.confusion || { tn: 0, fp: 0, fn: 0, tp: 0 };
  const total = (conf.tn + conf.fp + conf.fn + conf.tp) || 1;
  document.getElementById("cm-tn").textContent = conf.tn.toLocaleString();
  document.getElementById("cm-tn-pct").textContent = ((conf.tn / total) * 100).toFixed(2) + "% of total";
  document.getElementById("cm-fp").textContent = conf.fp.toLocaleString();
  document.getElementById("cm-fp-pct").textContent = ((conf.fp / total) * 100).toFixed(2) + "% false alarms";
  document.getElementById("cm-fn").textContent = conf.fn.toLocaleString();
  document.getElementById("cm-fn-pct").textContent = ((conf.fn / total) * 100).toFixed(2) + "% missed attacks";
  document.getElementById("cm-tp").textContent = conf.tp.toLocaleString();
  document.getElementById("cm-tp-pct").textContent = ((conf.tp / total) * 100).toFixed(2) + "% detected";

  // Per-class & family table
  const tbody = document.getElementById("per-class-tbody");
  tbody.innerHTML = "";

  const perClass = model.per_class || {};
  ["benign", "attack"].forEach(cls => {
    if (perClass[cls]) {
      const row = perClass[cls];
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>Class: ${cls.toUpperCase()}</strong></td>
        <td class="mono">${fmt(row.precision)}</td>
        <td class="mono">${fmt(row.recall)}</td>
        <td class="mono">${fmt(row.f1)}</td>
        <td class="mono">${(row.support || 0).toLocaleString()}</td>
      `;
      tbody.appendChild(tr);
    }
  });

  // Add per_family rows if present
  if (data.per_family && data.per_family.length > 0) {
    data.per_family.forEach(fam => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><span style="color:var(--text-dim)">Family:</span> ${escapeHtml(fam.attack_family || fam.family || "Attack")}</td>
        <td class="mono">—</td>
        <td class="mono">${fmt(fam.recall || fam.detection_rate)}</td>
        <td class="mono">—</td>
        <td class="mono">${(fam.support || fam.test_flows || 0).toLocaleString()}</td>
      `;
      tbody.appendChild(tr);
    });
  }
}

// ─── PAGE A: Overview ───
async function loadOverview() {
  try {
    const res = await fetch("/api/overview");
    if (!res.ok) return;
    const data = await res.json();

    document.getElementById("ov-commit").textContent = `Commit: ${data.git_commit.slice(0, 7)}`;

    // Component verification statuses
    const compTbody = document.getElementById("ov-components-tbody");
    compTbody.innerHTML = "";
    (data.component_statuses || []).forEach(cs => {
      const badgeCls = cs.status === "VERIFIED_FOR_DEFINED_SCOPE" ? "badge-green"
        : (cs.status === "PARTIALLY_VERIFIED" ? "badge-orange" : "badge-red");
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${escapeHtml(cs.component)}</strong></td>
        <td class="mono">${escapeHtml(cs.scope)}</td>
        <td><span class="badge ${badgeCls}">${escapeHtml(cs.status)}</span></td>
        <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(cs.finding)}</td>
      `;
      compTbody.appendChild(tr);
    });

    // Datasets table
    const dsTbody = document.getElementById("ov-datasets-tbody");
    dsTbody.innerHTML = "";
    (data.datasets || []).forEach(ds => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${escapeHtml(ds.name)}</strong></td>
        <td class="mono">${escapeHtml(ds.contract)}</td>
        <td class="mono">${(ds.test_flows || 0).toLocaleString()}</td>
        <td class="mono">${escapeHtml(ds.accuracy)}</td>
        <td class="mono">${escapeHtml(ds.f1)}</td>
        <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(ds.role)}</td>
      `;
      dsTbody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load overview:", err);
  }
}

// ─── PAGE C: Model Comparison ───
async function loadComparison() {
  const benchSelect = document.getElementById("cmp-benchmark-select");
  const bench = benchSelect ? benchSelect.value : "cicids2017";

  try {
    const res = await fetch(`/api/comparison?benchmark=${bench}`);
    if (!res.ok) return;
    const data = await res.json();
    renderComparison(data);
  } catch (err) {
    console.error("Failed to load comparison:", err);
  }
}

function onCmpBenchmarkChange() {
  loadComparison();
}

function renderComparison(data) {
  if (!data || !data.models) return;

  // Degenerate alert
  const alertEl = document.getElementById("cmp-degenerate-alert");
  const alertText = document.getElementById("cmp-degenerate-text");
  if (data.fusion && data.fusion.is_degenerate) {
    alertEl.style.display = "block";
    alertText.textContent = data.fusion.warning;
  } else {
    alertEl.style.display = "none";
  }

  // Fusion info
  document.getElementById("cmp-formula").textContent = data.fusion.formula;
  document.getElementById("cmp-alpha").textContent = fmt(data.fusion.alpha, 2);
  document.getElementById("cmp-beta").textContent = fmt(1.0 - data.fusion.alpha, 2);

  // Shuffled-window ablation
  const ab = data.shuffled_window_ablation;
  if (ab) {
    document.getElementById("ab-ordered").textContent = fmt(ab.lstm_ordered_condition_a ? ab.lstm_ordered_condition_a.f1 : 0.9314);
    document.getElementById("ab-shuffled").textContent = fmt(ab.lstm_shuffled_condition_b ? ab.lstm_shuffled_condition_b.f1 : 0.9353);
    document.getElementById("ab-delta").textContent = `${fmt(ab.delta ? ab.delta.f1_order_gain : -0.0038)} (No temporal order gain)`;
  }

  // Models table
  const tbody = document.getElementById("cmp-models-tbody");
  tbody.innerHTML = "";

  const roles = {
    majority: "Prior Baseline (Predict All Benign)",
    logistic_regression: "Linear Feature Baseline",
    decision_tree: "Single Tree Baseline",
    random_forest: "Primary Live Monitor (Frozen R10)",
    lstm: "Supervised Sequence Model (T=5)",
    fusion: "Score-Level Linear Combination",
  };

  ["majority", "logistic_regression", "decision_tree", "random_forest", "lstm", "fusion"].forEach(name => {
    const m = data.models[name];
    if (!m) return;

    let accStr = fmt(m.accuracy);
    let f1Str = fmt(m.f1);

    // Bootstrap CI if available
    const ci = data.bootstrap_cis && data.bootstrap_cis[name] ? data.bootstrap_cis[name].threshold_metrics : null;
    if (ci && ci.accuracy && ci.f1) {
      accStr += ` <span style="font-size:10px; color:var(--text-dim)">[${fmt(ci.accuracy.ci_lower)}, ${fmt(ci.accuracy.ci_upper)}]</span>`;
      f1Str += ` <span style="font-size:10px; color:var(--text-dim)">[${fmt(ci.f1.ci_lower)}, ${fmt(ci.f1.ci_upper)}]</span>`;
    }

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${name.replace("_", " ").toUpperCase()}</strong></td>
      <td class="mono">${accStr}</td>
      <td class="mono">${f1Str}</td>
      <td class="mono">${fmt(m.roc_auc)}</td>
      <td style="color:var(--text-muted); font-size:12px;">${roles[name] || ""}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ─── PAGE D: Flow Explorer ───
async function loadFlows() {
  const bench = currentEvalBenchmark || "cicids2017";
  try {
    const res = await fetch(`/api/flows?benchmark=${bench}&page=${currentFlowPage}&limit=25&status=${currentFlowFilterStatus}&label=${currentFlowFilterLabel}`);
    if (!res.ok) return;
    const data = await res.json();
    renderFlows(data);
  } catch (err) {
    console.error("Failed to load flows:", err);
  }
}

function onFlowFilterChange() {
  currentFlowFilterStatus = document.getElementById("flow-filter-status").value;
  currentFlowFilterLabel = document.getElementById("flow-filter-label").value;
  currentFlowPage = 1;
  loadFlows();
}

function changeFlowPage(delta) {
  currentFlowPage = Math.max(1, currentFlowPage + delta);
  loadFlows();
}

function exportFlowsCsv() {
  const bench = currentEvalBenchmark || "cicids2017";
  const url = `/api/flows/export?benchmark=${bench}&status=${currentFlowFilterStatus}&label=${currentFlowFilterLabel}`;
  window.open(url, "_blank");
}

function renderFlows(data) {
  if (!data || !data.flows) return;

  document.getElementById("flow-count-badge").textContent = `${data.filtered_rows.toLocaleString()} matching flows (${data.total_rows_cached.toLocaleString()} cached)`;
  document.getElementById("flow-current-page").textContent = data.page;
  document.getElementById("flow-total-pages").textContent = data.total_pages;

  const tbody = document.getElementById("flows-tbody");
  tbody.innerHTML = "";

  data.flows.forEach(f => {
    const gt = f.ground_truth;
    const mp = f.model_prediction;
    const gtBadge = gt.label === 1 ? `<span class="badge badge-red">[ATTACK]</span>` : `<span class="badge badge-green">[BENIGN]</span>`;
    const predBadge = mp.prediction_class === 1 ? `<span class="badge badge-red">ATTACK</span>` : `<span class="badge badge-green">BENIGN</span>`;

    let outcomeBadge = `<span class="badge badge-green">CORRECT</span>`;
    if (mp.outcome_status === "FALSE_POSITIVE") {
      outcomeBadge = `<span class="badge badge-orange">FALSE ALARM (FP)</span>`;
    } else if (mp.outcome_status === "FALSE_NEGATIVE") {
      outcomeBadge = `<span class="badge badge-red">MISSED ATTACK (FN)</span>`;
    }

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">#${f.flow_id}</td>
      <td><div class="gt-box">${gtBadge}</div></td>
      <td class="mono">${fmt(mp.rf_score)}</td>
      <td class="mono">${fmt(mp.lstm_score)}</td>
      <td class="mono">${fmt(mp.fusion_score)}</td>
      <td>${predBadge}</td>
      <td>${outcomeBadge}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ─── PAGE E: Explainability ───
async function loadExplainability() {
  const bench = currentEvalBenchmark || "cicids2017";
  try {
    const res = await fetch(`/api/explainability?benchmark=${bench}`);
    if (!res.ok) return;
    const data = await res.json();
    renderExplainability(data);
  } catch (err) {
    console.error("Failed to load explainability:", err);
  }
}

function renderExplainability(data) {
  if (!data || !data.global_importance) return;

  const tbody = document.getElementById("shap-tbody");
  tbody.innerHTML = "";

  const descriptions = {
    packet_length_std: "Variance of packet sizes — distinguishes automated floods from interactive sessions",
    packet_length_mean: "Mean byte length of packets in bidirectional flow",
    flow_packets_per_s: "Rate of packet transmission — extreme rates indicate DoS/DDoS bursts",
    flow_bytes_per_s: "Throughput volume across flow lifetime",
    flow_duration_ms: "Total connection duration in milliseconds",
    ack_count: "Cumulative TCP ACK flags observed",
    fin_count: "Graceful teardown TCP FIN flags",
    syn_count: "Connection handshake initiation TCP SYN flags",
    syn_ack_ratio: "Ratio of SYN to ACK flags — high ratio indicates scanning/SYN flood",
    rst_count: "Abrupt termination TCP RST flags",
  };

  data.global_importance.forEach((item, idx) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">#${idx + 1}</td>
      <td><strong>${escapeHtml(item.feature)}</strong></td>
      <td class="mono">${data.contract}</td>
      <td class="mono">${fmt(item.mean_abs_shap || item.importance)}</td>
      <td style="color:var(--text-muted); font-size:12px;">${descriptions[item.feature] || "Traffic flow moment metric"}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ─── PAGE F: Autonomous Response ───
async function loadResponseBenchmark() {
  const regime = document.getElementById("resp-regime-select").value;
  const mode = document.getElementById("resp-mode-select").value;

  try {
    const res = await fetch(`/api/response-benchmark?regime=${regime}&mode=${mode}`);
    if (!res.ok) return;
    const data = await res.json();
    renderResponseBenchmark(data);
  } catch (err) {
    console.error("Failed to load response benchmark:", err);
  }
}

function onResponseParamsChange() {
  loadResponseBenchmark();
}

function renderResponseBenchmark(data) {
  if (!data || !data.policies) return;

  // Head to head winner callout
  const winnerEl = document.getElementById("resp-winner-text");
  if (data.head_to_head) {
    const h2h = data.head_to_head;
    const isBaseline = h2h.superior_policy.includes("Cost_Optimal");
    const diffPct = Math.abs(h2h.relative_cost_reduction_pct).toFixed(2);
    winnerEl.innerHTML = isBaseline
      ? `<span class="badge badge-green">Cost-Optimal Baseline WON</span> Achieving <strong>${diffPct}% lower cost</strong> than the trained DQN.`
      : `<span class="badge badge-purple">DQN Achieved Lower Cost</span> with ${diffPct}% cost reduction (Failed the 15% practical improvement target).`;
  }

  // Policies table
  const tbody = document.getElementById("resp-policies-tbody");
  tbody.innerHTML = "";

  data.policies.forEach(p => {
    const isDqn = p.policy_name.includes("DQN");
    const isCostOpt = p.policy_name.includes("Cost_Optimal");
    const nameBadge = isCostOpt ? `<span class="badge badge-green">${escapeHtml(p.policy_name)}</span>`
      : (isDqn ? `<span class="badge badge-purple">${escapeHtml(p.policy_name)}</span>` : escapeHtml(p.policy_name));

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${nameBadge}</strong></td>
      <td class="mono">${(p.evaluation_a_total_operational_cost || 0).toLocaleString()}</td>
      <td class="mono">${fmt(p.evaluation_a_mean_cost_per_flow)}</td>
      <td class="mono">${(p.business_availability_score_pct || 0).toFixed(2)}%</td>
      <td class="mono">${((p.false_quarantine_rate || 0) * 100).toFixed(2)}%</td>
      <td class="mono">${fmt(p.action_chattering_index)}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ─── PAGE G: Research Limitations ───
async function loadLimitations() {
  try {
    const res = await fetch("/api/limitations");
    if (!res.ok) return;
    const data = await res.json();

    const container = document.getElementById("limitations-container");
    container.innerHTML = "";

    (data.limitations || []).forEach(lim => {
      const sevBadge = lim.severity === "CRITICAL" ? "badge-red"
        : (lim.severity === "HIGH" ? "badge-orange" : "badge-blue");

      const div = document.createElement("div");
      div.className = "card section-gap";
      div.innerHTML = `
        <div class="card-header">
          <h2>${escapeHtml(lim.id)}: ${escapeHtml(lim.title)}</h2>
          <span class="badge ${sevBadge}">${escapeHtml(lim.severity)}</span>
        </div>
        <div class="card-body">
          <p style="font-size:13px; line-height:1.6; color:var(--text);">${escapeHtml(lim.description)}</p>
        </div>
      `;
      container.appendChild(div);
    });
  } catch (err) {
    console.error("Failed to load limitations:", err);
  }
}

// ─── Custom CSV Dataset Evaluation ───
let lastCsvEvalResult = null;

function onCsvFileSelected(event) {
  const file = event.target.files && event.target.files[0];
  const statusEl = document.getElementById("csv-file-status");
  const textarea = document.getElementById("csv-text-input");
  if (!file) return;

  statusEl.textContent = `Selected file: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  const reader = new FileReader();
  reader.onload = (e) => {
    textarea.value = e.target.result;
  };
  reader.readAsText(file);
}

async function loadSampleCsv() {
  const statusEl = document.getElementById("csv-file-status");
  const textarea = document.getElementById("csv-text-input");
  try {
    statusEl.textContent = "Loading benchmark demonstration sample flows...";
    const res = await fetch("/api/csv/sample");
    if (!res.ok) throw new Error("Failed to load sample CSV from server");
    const data = await res.json();
    textarea.value = data.csv_text;
    document.getElementById("csv-eval-contract").value = data.contract || "R10";
    document.getElementById("csv-eval-model").value = data.benchmark || "cicids2017";
    statusEl.textContent = "Loaded 12 curated CIC-IDS2017 demonstration flows (Benign, DDoS, DoS Hulk). Click 'Evaluate CSV' to test.";
  } catch (err) {
    statusEl.textContent = "Error loading sample: " + err.message;
  }
}

async function runCsvEvaluation() {
  const statusEl = document.getElementById("csv-file-status");
  const textarea = document.getElementById("csv-text-input");
  const contract = document.getElementById("csv-eval-contract").value;
  const benchmark = document.getElementById("csv-eval-model").value;
  const btn = document.getElementById("btn-run-csv-eval");

  const csvText = textarea.value.trim();
  if (!csvText) {
    alert("Please choose a CSV file, load demo records, or paste CSV rows into the text area.");
    return;
  }

  try {
    btn.disabled = true;
    btn.textContent = "⏳ Evaluating...";
    statusEl.textContent = "Evaluating records against frozen model artifacts...";

    const res = await fetch("/api/csv/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        csv_text: csvText,
        contract: contract,
        benchmark: benchmark,
      }),
    });

    const data = await res.json();
    if (!res.ok || data.error) {
      throw new Error(data.error || "Evaluation failed");
    }

    lastCsvEvalResult = data;
    renderCsvEvaluationResults(data);
    statusEl.textContent = `✓ Evaluation complete. Evaluated ${data.row_accounting.evaluated_rows} flows.`;
  } catch (err) {
    alert("CSV Evaluation Error: " + err.message);
    statusEl.textContent = "Evaluation failed: " + err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "⚡ Evaluate CSV";
  }
}

function renderCsvEvaluationResults(data) {
  const resContainer = document.getElementById("csv-eval-results");
  if (!resContainer) return;
  resContainer.style.display = "block";

  // Row accounting
  const accEl = document.getElementById("csv-row-accounting");
  const acct = data.row_accounting || {};
  accEl.innerHTML = `
    <strong>Row Accounting:</strong> Received <strong>${acct.total_rows_received}</strong> rows ·
    Evaluated <strong>${acct.evaluated_rows}</strong> valid rows ·
    Dropped <strong>${acct.invalid_rows_dropped}</strong> invalid rows (${escapeHtml(acct.drop_reason)}).<br>
    <em>Model: ${escapeHtml(data.model_identifier)} · Feature Contract: ${escapeHtml(data.contract)}</em>
  `;

  // Metrics (if labelled)
  const metricsGrid = document.getElementById("csv-metrics-grid");
  const cmCard = document.getElementById("csv-cm-card");
  if (data.is_labelled && data.metrics) {
    metricsGrid.style.display = "grid";
    cmCard.style.display = "block";

    document.getElementById("csv-metric-acc").textContent = `${(data.metrics.accuracy * 100).toFixed(2)}%`;
    document.getElementById("csv-metric-prec").textContent = fmt(data.metrics.precision);
    document.getElementById("csv-metric-rec").textContent = fmt(data.metrics.recall);
    document.getElementById("csv-metric-f1").textContent = fmt(data.metrics.f1);

    const cm = data.confusion_matrix || {};
    document.getElementById("csv-cm-tn").textContent = cm.tn != null ? cm.tn.toLocaleString() : "—";
    document.getElementById("csv-cm-fp").textContent = cm.fp != null ? cm.fp.toLocaleString() : "—";
    document.getElementById("csv-cm-fn").textContent = cm.fn != null ? cm.fn.toLocaleString() : "—";
    document.getElementById("csv-cm-tp").textContent = cm.tp != null ? cm.tp.toLocaleString() : "—";
  } else {
    metricsGrid.style.display = "none";
    cmCard.style.display = "none";
  }

  // Distribution
  const dist = data.score_distribution || {};
  document.getElementById("csv-dist-low").textContent = `${dist.low_threat_under_040 || 0} flows`;
  document.getElementById("csv-dist-med").textContent = `${dist.medium_threat_040_to_065 || 0} flows`;
  document.getElementById("csv-dist-high").textContent = `${dist.high_threat_over_065 || 0} flows`;
  document.getElementById("csv-dist-mean").textContent = fmt(dist.mean_score);
  document.getElementById("csv-model-badge").textContent = escapeHtml(data.contract);

  // Flows table
  const tbody = document.getElementById("csv-flows-tbody");
  tbody.innerHTML = "";
  (data.flows || []).forEach(f => {
    const isAtk = f.prediction_class === 1;
    const predBadge = isAtk ? `<span class="badge badge-red">ATTACK</span>` : `<span class="badge badge-green">BENIGN</span>`;
    let verdictBadge = `<span class="badge badge-dim">${escapeHtml(f.verdict)}</span>`;
    if (f.verdict === "CORRECT") verdictBadge = `<span class="badge badge-green">CORRECT</span>`;
    if (f.verdict === "FALSE_POSITIVE" || f.verdict === "FALSE_NEGATIVE") verdictBadge = `<span class="badge badge-red">${escapeHtml(f.verdict)}</span>`;

    const feats = f.features || {};
    const featSummary = `Dur: ${feats.flow_duration_ms || 0}ms · Pkts/s: ${fmt(feats.flow_packets_per_s, 1)} · Bytes/s: ${fmt(feats.flow_bytes_per_s, 1)}`;

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">#${f.flow_id}</td>
      <td><strong>${escapeHtml(f.ground_truth_label)}</strong></td>
      <td class="mono"><strong>${fmt(f.attack_score)}</strong></td>
      <td>${predBadge}</td>
      <td>${verdictBadge}</td>
      <td class="mono" style="font-size:11px; color:var(--text-muted);">${escapeHtml(featSummary)}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function downloadEvaluatedCsv() {
  if (!lastCsvEvalResult) {
    alert("No evaluated records to export. Please evaluate a CSV first.");
    return;
  }
  try {
    const res = await fetch("/api/csv/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ eval_result: lastCsvEvalResult }),
    });
    if (!res.ok) throw new Error("Export failed on server");
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `xrlids_${lastCsvEvalResult.benchmark}_evaluated_flows.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
  } catch (err) {
    alert("Failed to export evaluated CSV: " + err.message);
  }
}

// ─── Traffic Modes & Live Monitor ───
function onLiveModeChange() {
  const mode = document.getElementById("live-mode").value;
  const dsCat = document.getElementById("dataset-category");
  const iface = document.getElementById("live-iface");
  const notice = document.getElementById("live-notice");

  if (dsCat) dsCat.style.display = mode === "dataset" ? "inline-block" : "none";
  if (iface) iface.style.display = mode === "live" ? "inline-block" : "none";

  if (notice) {
    if (mode === "dataset") {
      notice.textContent = "Mode 2: Streams curated benchmark flows through the observational pipeline. Ground truth is tracked separately.";
    } else if (mode === "sample") {
      notice.textContent = "Mode 3: Replays captured packets from an offline PCAP file through FlowBuilder.";
    } else {
      notice.textContent = "Mode 5: Captures real packets via raw AF_PACKET socket (requires root). Observational alert mode only; zero network mutations.";
    }
  }
}

async function startLive() {
  const mode = document.getElementById("live-mode").value;
  const dsCat = document.getElementById("dataset-category").value;
  const iface = document.getElementById("live-iface").value;

  try {
    const res = await fetch("/api/live/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: mode, dataset_category: dsCat, interface: iface }),
    });
    const data = await res.json();
    if (data.error) {
      alert("Stream Error: " + data.error);
    } else {
      liveSessionActive = true;
      document.getElementById("live-session-status").textContent = "Running";
      document.getElementById("live-dot").className = "pulse-dot live";
      document.getElementById("topbar-status-text").textContent = "Stream Running";
    }
  } catch (err) {
    alert("Failed to start stream: " + err.message);
  }
}

async function stopLive() {
  try {
    await fetch("/api/live/stop", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    liveSessionActive = false;
    document.getElementById("live-session-status").textContent = "Stopped";
    document.getElementById("live-dot").className = "pulse-dot";
    document.getElementById("topbar-status-text").textContent = "Stream Stopped";
  } catch (_) {}
}

async function pollLive() {
  try {
    const res = await fetch("/api/live");
    if (!res.ok) return;
    const snap = await res.json();

    if (snap.status === "running") {
      document.getElementById("live-session-status").textContent = "Running (" + (snap.counters ? snap.counters.flows : 0) + " flows)";
      document.getElementById("live-dot").className = "pulse-dot live";
      document.getElementById("topbar-status-text").textContent = "Observing Traffic";

      // Render recent flows
      if (snap.recent_flows && snap.recent_flows.length > 0) {
        const tbody = document.getElementById("live-flows-tbody");
        tbody.innerHTML = "";
        snap.recent_flows.slice(-10).reverse().forEach(fl => {
          const predBadge = fl.prediction_class === 1 ? `<span class="badge badge-red">ATTACK</span>` : `<span class="badge badge-green">BENIGN</span>`;
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td class="mono">${fmt(fl.timestamp, 2)}</td>
            <td class="mono">${escapeHtml(fl.src_endpoint)} → ${escapeHtml(fl.dst_endpoint)}</td>
            <td>${escapeHtml(fl.protocol)}</td>
            <td class="mono">${fl.packet_count}</td>
            <td class="mono">${fmt(fl.attack_score)}</td>
            <td>${predBadge}</td>
            <td>${escapeHtml(fl.ground_truth || "UNKNOWN")}</td>
          `;
          tbody.appendChild(tr);
        });
      }
    } else if (snap.status === "stopped") {
      document.getElementById("live-session-status").textContent = "Idle";
      document.getElementById("live-dot").className = "pulse-dot";
      document.getElementById("topbar-status-text").textContent = "Workbench Idle";
    }

    // Always update attack sources and passive device discoveries
    renderAttackSources(snap.recent_alerts || []);
    renderDevices(snap);
  } catch (_) {}
}

function policyFor(score) {
  if (score >= 0.50) return { action: "BLOCK (SUGGESTED)", cls: "badge-red" };
  if (score >= 0.40) return { action: "THROTTLE (SUGGESTED)", cls: "badge-orange" };
  if (score >= 0.20) return { action: "MONITOR", cls: "badge-blue" };
  return { action: "ALLOW", cls: "badge-green" };
}

function formatAge(seconds) {
  const v = Number(seconds);
  if (!Number.isFinite(v) || v < 0) return "—";
  if (v < 5) return "now";
  if (v < 60) return Math.round(v) + "s";
  if (v < 3600) return Math.floor(v / 60) + "m";
  return Math.floor(v / 3600) + "h";
}

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
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; padding:16px; color:var(--text-dim)">No attack sources detected</td></tr>';
    return;
  }
  tbody.innerHTML = "";
  rows.forEach(e => {
    const p = policyFor(e.maxScore);
    const isSim = e.ip.startsWith("203.0.113.");
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono"><strong>${escapeHtml(e.ip)}</strong>${isSim ? ' <span class="badge badge-sim">SIM</span>' : ""}</td>
      <td class="mono">${e.alerts}</td>
      <td class="mono"><strong style="color:var(--red)">${fmt(e.maxScore)}</strong></td>
      <td><span class="badge ${p.cls}">${p.action}</span></td>
    `;
    tbody.appendChild(tr);
  });
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
      : "Live capture not active";
    countEl.textContent = "0 observed";
    countEl.className = "badge badge-dim";
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:16px; color:var(--text-dim)">Start live capture to discover devices</td></tr>';
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
  countEl.textContent = devices.length + " observed";
  countEl.className = "badge" + (devices.length ? " badge-blue" : " badge-dim");

  if (devices.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:16px; color:var(--text-dim)">Waiting for ARP/DHCP/mDNS traffic…</td></tr>';
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

// ─── Initialization ───
document.addEventListener("DOMContentLoaded", () => {
  onLiveModeChange();
  renderAttackSources([]);
  renderDevices({ mode: null });
  loadEvaluation(); // Default active tab is Page B (Dataset Evaluation)
  setInterval(pollLive, LIVE_POLL_MS);
});
