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
let currentCsvMode = "exhibition";

const BENCHMARK_CONTRACT_MAP = {
  cicids2017: "R10",
  cse2018: "R10",
  unswnb15: "R4",
};

function onCsvModeSelect(mode) {
  currentCsvMode = mode;
  const pillEx = document.getElementById("mode-pill-exhibition");
  const pillFull = document.getElementById("mode-pill-full-test");
  const pillCust = document.getElementById("mode-pill-custom");
  if (pillEx) pillEx.classList.toggle("active", mode === "exhibition");
  if (pillFull) pillFull.classList.toggle("active", mode === "full_test");
  if (pillCust) pillCust.classList.toggle("active", mode === "custom");

  const descEl = document.getElementById("csv-mode-description");
  const maxRowsGroup = document.getElementById("csv-max-rows-group");
  const customUploadControls = document.getElementById("csv-custom-upload-controls");
  const customInputArea = document.getElementById("csv-custom-input-area");
  const statusEl = document.getElementById("csv-file-status");
  const badgeEl = document.getElementById("csv-eval-badge");

  if (mode === "exhibition") {
    if (badgeEl) {
      badgeEl.textContent = "Mode B: 200 Exhibition Demo";
      badgeEl.className = "badge badge-purple";
    }
    updateModeBDescription();
    if (maxRowsGroup) maxRowsGroup.style.display = "none";
    if (customUploadControls) customUploadControls.style.display = "none";
    if (customInputArea) customInputArea.style.display = "none";
    if (statusEl) statusEl.textContent = "Ready. Click 'Run Evaluation' to score the 200 held-out test flows against RF + LSTM + Fusion.";
  } else if (mode === "full_test") {
    if (badgeEl) {
      badgeEl.textContent = "Mode A: Full Held-Out Test";
      badgeEl.className = "badge badge-blue";
    }
    if (descEl) {
      descEl.innerHTML = `<strong>Mode A — Full Held-Out Test Evaluation:</strong>
        Evaluates the complete authoritative test split directly against the frozen multi-model pipeline. Select the dataset and max evaluation rows, then click 'Run Evaluation'.`;
    }
    if (maxRowsGroup) maxRowsGroup.style.display = "flex";
    if (customUploadControls) customUploadControls.style.display = "none";
    if (customInputArea) customInputArea.style.display = "none";
    if (statusEl) statusEl.textContent = "Ready. Select dataset and max rows, then click 'Run Evaluation'.";
  } else {
    if (badgeEl) {
      badgeEl.textContent = "Mode C: Custom CSV Upload";
      badgeEl.className = "badge badge-orange";
    }
    if (descEl) {
      descEl.innerHTML = `<strong>Mode C — Custom CSV Dataset Evaluation:</strong>
        Evaluate any external or custom network flow CSV matching the dataset's feature contract. Ground-truth labels are strictly isolated from feature inputs.`;
    }
    if (maxRowsGroup) maxRowsGroup.style.display = "none";
    if (customUploadControls) customUploadControls.style.display = "flex";
    if (customInputArea) customInputArea.style.display = "block";
    if (statusEl) statusEl.textContent = "Ready. Choose a CSV file or paste flow rows below, then click 'Run Evaluation'.";
  }
}

function updateModeBDescription() {
  const descEl = document.getElementById("csv-mode-description");
  if (!descEl) return;
  const model = document.getElementById("csv-eval-model") ? document.getElementById("csv-eval-model").value : "cicids2017";
  if (model === "cse2018") {
    descEl.innerHTML = `<strong>Mode B — CSE-CIC-IDS2018 Fixed Exhibition Subset:</strong>
      Fast, deterministic verification using 200 flows (166 Benign, 34 Attack: 34 DDoS LOIC-HTTP) from the canonical CSE-CIC-IDS2018 held-out test split, source file <code>Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv</code>. The feature table has no IP addresses, so endpoints are labeled synthetic RFC 5737 display addresses (192.0.2.X &rarr; 198.51.100.X) and protocol is N/A. Evaluates RF + LSTM (T=5) + Score Fusion (&alpha;=0.00), runs TreeSHAP explanation on demand, and simulates Dueling DQN response recommendations.`;
  } else if (model === "unswnb15") {
    descEl.innerHTML = `<strong>Mode B — UNSW-NB15 Fixed Exhibition Subset:</strong>
      Fast, deterministic verification using 200 flows (166 Benign, 34 Attack: 18 Exploits, 10 Fuzzers, 4 Reconnaissance, 1 Generic, 1 DoS) from the canonical UNSW-NB15 held-out test split, source file <code>UNSW_NB15_testing-set.csv</code>, under the R4 sensor-degradation contract. The feature table has no IP addresses, so endpoints are labeled synthetic RFC 5737 display addresses (192.0.2.X &rarr; 198.51.100.X) and protocol is N/A. Evaluates RF + LSTM (T=5) + Score Fusion (&alpha;=0.60), runs TreeSHAP explanation on demand, and simulates Dueling DQN response recommendations.`;
  } else {
    descEl.innerHTML = `<strong>Mode B — CIC-IDS2017 Fixed Exhibition Subset (Recommended Demo):</strong>
      Fast, deterministic verification using 200 flows (166 Benign, 34 Attack: 28 DoS Hulk, 5 DoS GoldenEye, 1 DoS Slowhttptest) from the canonical CIC-IDS2017 held-out test split, source file <code>Wednesday-workingHours.pcap_ISCX.csv</code>. The feature table has no IP addresses, so endpoints are labeled synthetic RFC 5737 display addresses (192.0.2.X &rarr; 198.51.100.X) and protocol is N/A. Evaluates RF + LSTM (T=5) + Score Fusion (&alpha;=0.50), runs TreeSHAP explanation on demand, and simulates Dueling DQN response recommendations.`;
  }
}

function onCsvModelChange() {
  const model = document.getElementById("csv-eval-model").value;
  const contractSelect = document.getElementById("csv-eval-contract");
  if (!contractSelect) return;
  if (model === "unswnb15") {
    contractSelect.value = "R4";
    for (let opt of contractSelect.options) {
      opt.disabled = (opt.value !== "R4");
    }
  } else {
    contractSelect.value = "R10";
    for (let opt of contractSelect.options) {
      opt.disabled = (opt.value !== "R10");
    }
  }
  if (currentCsvMode === "exhibition") {
    updateModeBDescription();
  }
}

async function loadSampleCsvIntoTextarea() {
  const model = document.getElementById("csv-eval-model").value;
  const textarea = document.getElementById("csv-text-input");
  const statusEl = document.getElementById("csv-file-status");
  try {
    statusEl.textContent = `Loading 200 sample flows for benchmark ${model}...`;
    const res = await fetch(`/api/csv/sample?benchmark=${model}&limit=200`);
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    if (textarea) textarea.value = data.csv_text;
    statusEl.textContent = `✓ Loaded ${data.rows} sample flows for ${data.benchmark} (Contract: ${data.contract}). Ready to evaluate.`;
  } catch (err) {
    statusEl.textContent = "Failed to load sample: " + err.message;
  }
}

function onCsvContractChange() {
  const contract = document.getElementById("csv-eval-contract").value;
  const modelSelect = document.getElementById("csv-eval-model");
  if (!modelSelect) return;
  if (contract === "R4") {
    modelSelect.value = "unswnb15";
    for (let opt of modelSelect.options) {
      opt.disabled = (opt.value !== "unswnb15");
    }
  } else {
    if (modelSelect.value === "unswnb15") {
      modelSelect.value = "cicids2017";
    }
    for (let opt of modelSelect.options) {
      opt.disabled = (opt.value === "unswnb15");
    }
  }
}

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

async function runCsvEvaluation() {
  const statusEl = document.getElementById("csv-file-status");
  const textarea = document.getElementById("csv-text-input");
  const contract = document.getElementById("csv-eval-contract").value;
  const benchmark = document.getElementById("csv-eval-model").value;
  const btn = document.getElementById("btn-run-csv-eval");

  const expectedContract = BENCHMARK_CONTRACT_MAP[benchmark];
  if (expectedContract && contract !== expectedContract) {
    alert(`Configuration mismatch: Benchmark '${benchmark}' requires feature contract '${expectedContract}', but '${contract}' was selected.`);
    return;
  }

  const payload = {
    mode: currentCsvMode,
    benchmark: benchmark,
    contract: contract,
  };

  if (currentCsvMode === "custom") {
    const csvText = textarea ? textarea.value.trim() : "";
    if (!csvText) {
      alert("Please choose a CSV file or paste CSV rows into the text area for Mode C.");
      return;
    }
    payload.csv_text = csvText;
  } else if (currentCsvMode === "full_test") {
    const maxRowsSelect = document.getElementById("csv-eval-max-rows");
    const maxRows = parseInt(maxRowsSelect ? maxRowsSelect.value : "1000", 10);
    payload.max_rows = maxRows;
  }

  try {
    btn.disabled = true;
    btn.textContent = "⏳ Evaluating...";
    statusEl.textContent = `Evaluating flows in ${currentCsvMode} mode against RF + LSTM (T=5) + Fusion...`;

    const res = await fetch("/api/csv/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const data = await res.json();
    if (!res.ok || data.error) {
      throw new Error(data.error || "Evaluation failed");
    }

    lastCsvEvalResult = data;
    renderCsvEvaluationResults(data);
    statusEl.textContent = `✓ Evaluation complete. Mode: ${data.mode} · Evaluated: ${data.row_accounting.evaluated_rows} flows · Latency: ${(data.evaluation_latency_ms || 0).toFixed(1)} ms · Throughput: ${(data.throughput_flows_per_s || 0).toFixed(0)} flows/s.`;
  } catch (err) {
    alert("Evaluation Error: " + err.message);
    statusEl.textContent = "Evaluation failed: " + err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = "⚡ Run Evaluation";
  }
}

function renderCsvEvaluationResults(data) {
  const resContainer = document.getElementById("csv-eval-results");
  if (!resContainer) return;
  resContainer.style.display = "block";

  // Row accounting
  const accEl = document.getElementById("csv-row-accounting");
  const acct = data.row_accounting || {};
  const lat = (data.evaluation_latency_ms || 0).toFixed(1);
  const thru = (data.throughput_flows_per_s || 0).toFixed(0);
  accEl.innerHTML = `
    <strong>Row Accounting &amp; Provenance:</strong> Mode: <strong>${escapeHtml(data.mode)}</strong> &middot;
    Dataset: <strong>${escapeHtml(data.benchmark)}</strong> (${escapeHtml(data.split_name || 'test')}) &middot;
    Received: <strong>${acct.total_rows_received}</strong> &middot;
    Evaluated: <strong>${acct.evaluated_rows}</strong> valid rows &middot;
    Dropped: <strong>${acct.invalid_rows_dropped}</strong> (${escapeHtml(acct.drop_reason || 'none')}) &middot;
    Inference Latency: <strong>${lat} ms</strong> &middot;
    Throughput: <strong>${thru} flows/s</strong><br>
    <em>Artifacts: ${escapeHtml(data.model_identifier)} &middot; Feature Contract: ${escapeHtml(data.contract)}</em>
  `;

  // Multi-Model Metrics
  const metricsGrid = document.getElementById("csv-multi-model-metrics");
  const cmRow = document.getElementById("csv-cm-row");
  const rfM = data.rf_metrics || data.metrics || {};
  const lstmM = data.lstm_metrics || {};
  const fusM = data.fusion_metrics || {};

  if (data.is_labelled && (rfM.accuracy != null || lstmM.accuracy != null)) {
    if (metricsGrid) metricsGrid.style.display = "block";
    if (cmRow) cmRow.style.display = "grid";

    // Random Forest
    document.getElementById("csv-rf-f1").textContent = fmt(rfM.f1);
    document.getElementById("csv-rf-acc").textContent = `${((rfM.accuracy || 0) * 100).toFixed(2)}%`;
    document.getElementById("csv-rf-prec").textContent = fmt(rfM.precision);
    document.getElementById("csv-rf-rec").textContent = fmt(rfM.recall);
    document.getElementById("csv-rf-auc").textContent = rfM.roc_auc != null ? fmt(rfM.roc_auc) : "—";

    const rfCm = data.rf_confusion_matrix || data.confusion_matrix || {};
    document.getElementById("csv-rf-tn").textContent = rfCm.tn != null ? rfCm.tn.toLocaleString() : "—";
    document.getElementById("csv-rf-fp").textContent = rfCm.fp != null ? rfCm.fp.toLocaleString() : "—";
    document.getElementById("csv-rf-fn").textContent = rfCm.fn != null ? rfCm.fn.toLocaleString() : "—";
    document.getElementById("csv-rf-tp").textContent = rfCm.tp != null ? rfCm.tp.toLocaleString() : "—";

    // LSTM
    document.getElementById("csv-lstm-f1").textContent = fmt(lstmM.f1);
    document.getElementById("csv-lstm-acc").textContent = `${((lstmM.accuracy || 0) * 100).toFixed(2)}%`;
    document.getElementById("csv-lstm-prec").textContent = fmt(lstmM.precision);
    document.getElementById("csv-lstm-rec").textContent = fmt(lstmM.recall);
    document.getElementById("csv-lstm-auc").textContent = lstmM.roc_auc != null ? fmt(lstmM.roc_auc) : "—";
    document.getElementById("csv-lstm-aligned-count").textContent = `${lstmM.aligned_flows_count || 0} flows`;

    const lstmCm = data.lstm_confusion_matrix || {};
    document.getElementById("csv-lstm-tn").textContent = lstmCm.tn != null ? lstmCm.tn.toLocaleString() : "—";
    document.getElementById("csv-lstm-fp").textContent = lstmCm.fp != null ? lstmCm.fp.toLocaleString() : "—";
    document.getElementById("csv-lstm-fn").textContent = lstmCm.fn != null ? lstmCm.fn.toLocaleString() : "—";
    document.getElementById("csv-lstm-tp").textContent = lstmCm.tp != null ? lstmCm.tp.toLocaleString() : "—";

    // Score Fusion
    const alpha = data.fusion_alpha != null ? data.fusion_alpha : 0.5;
    document.getElementById("csv-fusion-alpha-badge").textContent = `α = ${alpha.toFixed(2)}`;
    document.getElementById("csv-fusion-f1").textContent = fmt(fusM.f1);
    document.getElementById("csv-fusion-acc").textContent = `${((fusM.accuracy || 0) * 100).toFixed(2)}%`;
    document.getElementById("csv-fusion-prec").textContent = fmt(fusM.precision);
    document.getElementById("csv-fusion-rec").textContent = fmt(fusM.recall);
    document.getElementById("csv-fusion-auc").textContent = fusM.roc_auc != null ? fmt(fusM.roc_auc) : "—";
    document.getElementById("csv-fusion-formula").textContent = `${alpha.toFixed(2)}·RF + ${(1 - alpha).toFixed(2)}·LSTM`;

    const fusCm = data.fusion_confusion_matrix || {};
    document.getElementById("csv-fusion-tn").textContent = fusCm.tn != null ? fusCm.tn.toLocaleString() : "—";
    document.getElementById("csv-fusion-fp").textContent = fusCm.fp != null ? fusCm.fp.toLocaleString() : "—";
    document.getElementById("csv-fusion-fn").textContent = fusCm.fn != null ? fusCm.fn.toLocaleString() : "—";
    document.getElementById("csv-fusion-tp").textContent = fusCm.tp != null ? fusCm.tp.toLocaleString() : "—";
  } else {
    if (metricsGrid) metricsGrid.style.display = "none";
    if (cmRow) cmRow.style.display = "none";
  }

  // Flows table
  const tbody = document.getElementById("csv-flows-tbody");
  tbody.innerHTML = "";
  (data.flows || []).forEach(f => {
    let verdictBadge = `<span class="badge badge-dim">${escapeHtml(f.verdict || 'UNLABELLED')}</span>`;
    if (f.verdict === "CORRECT") verdictBadge = `<span class="badge badge-green">CORRECT</span>`;
    if (f.verdict === "FALSE_POSITIVE" || f.verdict === "FALSE_NEGATIVE") verdictBadge = `<span class="badge badge-red">${escapeHtml(f.verdict)}</span>`;

    let lstmDisplay = "—";
    if (f.lstm_status === "WARM_UP") {
      lstmDisplay = `<span class="badge badge-dim" title="Initial T-1 causal warm-up flow">WARM-UP</span>`;
    } else if (f.lstm_score != null) {
      lstmDisplay = `<span class="mono">${fmt(f.lstm_score)}</span>`;
    }

    let endpointDisplay = `<span style="color:var(--text-dim); font-size:11px;">Not available in source</span>`;
    if (f.src_endpoint && f.dst_endpoint) {
      endpointDisplay = `<span class="mono" style="font-size:11px;">${escapeHtml(f.src_endpoint)} &rarr; ${escapeHtml(f.dst_endpoint)} [${escapeHtml(f.protocol || 'TCP')}]</span>`;
    }

    const action = f.response_action || "ALLOW";
    let actionBadge = `<span class="badge badge-green">${escapeHtml(action)}</span>`;
    if (action === "ALERT") actionBadge = `<span class="badge badge-orange">${escapeHtml(action)}</span>`;
    if (action === "RATE_LIMIT") actionBadge = `<span class="badge badge-purple">${escapeHtml(action)}</span>`;
    if (action === "ISOLATE") actionBadge = `<span class="badge badge-red">${escapeHtml(action)}</span>`;

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">#${f.flow_id}</td>
      <td>${endpointDisplay}</td>
      <td><strong>${escapeHtml(f.ground_truth_label || 'Unknown')}</strong></td>
      <td class="mono">${fmt(f.rf_score)}</td>
      <td>${lstmDisplay}</td>
      <td class="mono" style="color:var(--accent); font-weight:700;">${fmt(f.attack_score)}</td>
      <td>${verdictBadge}</td>
      <td>${actionBadge}</td>
      <td><button class="btn btn-sm" onclick="inspectFlow(${f.flow_id})">🔍 Inspect</button></td>
    `;
    tbody.appendChild(tr);
  });
}

async function inspectFlow(flowId) {
  if (!lastCsvEvalResult || !lastCsvEvalResult.flows) return;
  const flow = lastCsvEvalResult.flows.find(f => f.flow_id === flowId);
  if (!flow) return;

  const modal = document.getElementById("flow-inspect-modal");
  if (!modal) return;
  modal.classList.add("active");

  document.getElementById("modal-flow-id").textContent = `Flow #${flow.flow_id}`;
  if (flow.src_endpoint && flow.dst_endpoint) {
    document.getElementById("modal-endpoints").textContent = `${flow.src_endpoint} → ${flow.dst_endpoint} [${flow.protocol || 'TCP'}]`;
  } else {
    document.getElementById("modal-endpoints").textContent = "Endpoint metadata not available in benchmark split";
  }
  document.getElementById("modal-gt").textContent = flow.ground_truth_label || "Unlabelled";

  document.getElementById("modal-rf-score").textContent = fmt(flow.rf_score);
  document.getElementById("modal-lstm-score").textContent = flow.lstm_status === "WARM_UP" ? "WARM-UP" : fmt(flow.lstm_score);
  document.getElementById("modal-fusion-score").textContent = fmt(flow.attack_score);

  const decBadge = document.getElementById("modal-decision-badge");
  const isAttack = flow.attack_score >= 0.50;
  decBadge.textContent = isAttack ? "ATTACK" : "BENIGN";
  decBadge.className = `badge ${isAttack ? 'badge-red' : 'badge-green'}`;

  // DQN response recommendation
  const action = flow.response_action || "ALLOW";
  const actionEl = document.getElementById("modal-dqn-action");
  actionEl.textContent = action;
  actionEl.style.color = action === "ISOLATE" ? "var(--red)" : action === "RATE_LIMIT" ? "var(--purple)" : action === "ALERT" ? "var(--orange)" : "var(--green)";

  const descMap = {
    ALLOW: "Normal flow behavior; allow uninterrupted network transmission.",
    ALERT: "Anomalous flow characteristics observed; logged for SOC security analyst review.",
    RATE_LIMIT: "High throughput or suspicious burst detected; flow rate-limited to throttle abuse.",
    ISOLATE: "Confirmed malicious threat; dynamic IP/port quarantine recommended."
  };
  document.getElementById("modal-dqn-desc").textContent = descMap[action] || "Policy action recommended.";

  const feats = flow.features || {};
  const bytes = feats.flow_bytes_per_s || 0;
  const bytesNorm = Math.min(1.0, (bytes / 100000.0)).toFixed(3);
  document.getElementById("modal-dqn-state").textContent =
    `[S=${fmt(flow.attack_score)}, BytesNorm=${bytesNorm}, HostCrit=0.50, CurrQ=0.00, Cooldown=0.00, Hist=0.00]`;

  // Fetch TreeSHAP explanation on demand
  const shapContainer = document.getElementById("modal-shap-container");
  shapContainer.innerHTML = `<div style="text-align: center; color: var(--text-dim); padding: 12px;">Computing TreeSHAP local attribution for Flow #${flow.flow_id}...</div>`;

  try {
    const res = await fetch("/api/csv/explain", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        evaluation_id: lastCsvEvalResult.evaluation_id,
        flow_id: flow.flow_id,
        features: flow.features,
        benchmark: lastCsvEvalResult.benchmark,
        contract: lastCsvEvalResult.contract,
      }),
    });
    const expData = await res.json();
    if (!res.ok || expData.error) {
      throw new Error(expData.error || "Explanation failed");
    }

    renderShapAttributions(expData.attributions || [], expData.base_value);
  } catch (err) {
    shapContainer.innerHTML = `<div style="color: var(--orange); font-size: 12px; padding: 8px;">Notice: ${escapeHtml(err.message)}</div>`;
  }
}

function renderShapAttributions(attributions, baseValue) {
  const container = document.getElementById("modal-shap-container");
  if (!attributions || attributions.length === 0) {
    container.innerHTML = `<div style="color: var(--text-dim); font-size: 12px;">No attribution values returned.</div>`;
    return;
  }

  const maxVal = Math.max(...attributions.map(a => Math.abs(a.attribution)), 0.001);

  let html = `<div style="margin-bottom: 8px; font-size: 11px; color: var(--text-dim);">
    Model Expected Value (Base Attack Rate): <span class="mono">${fmt(baseValue)}</span>
  </div>`;

  attributions.forEach(item => {
    const val = item.attribution;
    const isPos = val >= 0;
    const pct = Math.min(100, (Math.abs(val) / maxVal) * 50);

    html += `
      <div class="shap-bar-row">
        <div class="shap-feat-name" title="${escapeHtml(item.feature)}">${escapeHtml(item.feature)}</div>
        <div class="shap-bar-track">
          <div class="shap-bar-center"></div>
          <div class="shap-bar-fill ${isPos ? 'pos' : 'neg'}" style="width: ${pct}%;"></div>
        </div>
        <div class="shap-val mono" style="color: ${isPos ? 'var(--red)' : 'var(--accent)'}; text-align: right;">
          ${isPos ? '+' : ''}${val.toFixed(4)}
        </div>
      </div>
    `;
  });

  container.innerHTML = html;
}

function closeFlowModal() {
  const modal = document.getElementById("flow-inspect-modal");
  if (modal) modal.classList.remove("active");
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
      body: JSON.stringify({
        evaluation_id: lastCsvEvalResult.evaluation_id,
        eval_result: lastCsvEvalResult,
      }),
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
  onCsvModelChange();
  renderAttackSources([]);
  renderDevices({ mode: null });
  loadEvaluation(); // Default active tab is Page B (Dataset Evaluation)
  setInterval(pollLive, LIVE_POLL_MS);
});
