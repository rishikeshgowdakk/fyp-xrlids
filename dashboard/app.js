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


function renderDatasetVisuals(data) {
  const chart = document.getElementById("ds-model-chart");
  const comp = document.getElementById("ds-composition-chart");
  const rows = Array.isArray(data.cross_dataset_summary) ? data.cross_dataset_summary : [];
  const colors = ["#60a5fa", "#a78bfa", "#67e8f9"];
  if (chart) {
    if (!rows.length) {
      chart.innerHTML = '<div class="chart-empty">No cross-dataset model metrics available.</div>';
    } else {
      chart.className = "bar-chart";
      chart.innerHTML = rows.map(row => {
        const name = row.benchmark_name || row.benchmark || "Dataset";
        const values = [
          ["RF", Number(row.rf_f1), colors[0]],
          ["LSTM", Number(row.lstm_f1), colors[1]],
          ["Fusion", Number(row.fusion_f1), colors[2]]
        ];
        return '<div style="padding-bottom:12px;border-bottom:1px solid var(--border)">' +
          '<div style="font-size:11px;font-weight:700;color:#e2e8f0;margin-bottom:8px">' + escapeHtml(name) + '</div>' +
          values.map(v => {
            const valid = Number.isFinite(v[1]) && v[1] >= 0;
            const pct = valid ? Math.max(0, Math.min(100, v[1] * 100)) : 0;
            return '<div class="bar-row" style="grid-template-columns:54px minmax(0,1fr) 48px;margin:6px 0">' +
              '<span class="bar-label">' + v[0] + '</span><div class="bar-track"><div class="bar-fill" style="width:' + pct.toFixed(2) + '%;background:' + v[2] + '"></div></div>' +
              '<span class="bar-value">' + (valid ? v[1].toFixed(3) : '—') + '</span></div>';
          }).join("") + '</div>';
      }).join("");
    }
  }
  if (comp) {
    const prevalence = Number(data.attack_prevalence_pct);
    if (!Number.isFinite(prevalence)) {
      comp.innerHTML = '<div class="chart-empty">Prevalence unavailable.</div>';
    } else {
      const attack = Math.max(0, Math.min(100, prevalence));
      comp.className = "";
      comp.innerHTML =
        '<div style="display:flex;align-items:flex-end;gap:10px;margin:22px 0 10px">' +
          '<div style="font-size:38px;font-weight:800;letter-spacing:-1.5px;color:#fb7185">' + attack.toFixed(1) + '<span style="font-size:16px">%</span></div>' +
          '<div style="font-size:12px;color:var(--text-muted);padding-bottom:7px">attack flows</div></div>' +
        '<div style="height:16px;display:flex;border-radius:99px;overflow:hidden;background:#263241">' +
          '<div title="Benign ' + (100-attack).toFixed(1) + '%" style="width:' + (100-attack) + '%;background:#34d399"></div>' +
          '<div title="Attack ' + attack.toFixed(1) + '%" style="width:' + attack + '%;background:#fb7185"></div></div>' +
        '<div style="display:flex;justify-content:space-between;gap:8px;margin-top:12px;font-size:11px;color:var(--text-muted)">' +
          '<span><i class="legend-dot" style="background:#34d399;display:inline-block;margin-right:6px"></i>Benign ' + Number(data.benign_count || 0).toLocaleString() + '</span>' +
          '<span><i class="legend-dot" style="background:#fb7185;display:inline-block;margin-right:6px"></i>Attack ' + Number(data.attack_count || 0).toLocaleString() + '</span></div>';
    }
  }
}

function renderModelMetricsChart(data) {
  const root = document.getElementById("cmp-metrics-chart");
  if (!root) return;
  const models = [
    {key:"random_forest", label:"Random Forest", color:"#60a5fa"},
    {key:"lstm", label:"LSTM", color:"#a78bfa"},
    {key:"fusion", label:"RF + LSTM Fusion", color:"#67e8f9"}
  ];
  const metrics = [
    {key:"f1", label:"F1"},
    {key:"precision", label:"Precision"},
    {key:"recall", label:"Recall"},
    {key:"roc_auc", label:"ROC-AUC"}
  ];
  if (!data || !data.models) {
    root.innerHTML = '<div class="chart-empty">Model metrics unavailable.</div>';
    return;
  }
  root.className = "model-bars";
  root.innerHTML = models.map(model => {
    const m = data.models[model.key] || {};
    return '<div class="model-bars-row"><div class="model-bars-name">' + model.label + '</div><div class="metric-bars">' +
      metrics.map(metric => {
        const value = Number(m[metric.key]);
        const valid = Number.isFinite(value) && value >= 0;
        const pct = valid ? Math.max(0, Math.min(100, value * 100)) : 0;
        return '<div class="metric-bar-line"><span>' + metric.label + '</span><div class="bar-track"><div class="bar-fill" style="width:' + pct.toFixed(2) + '%;background:' + model.color + '"></div></div><span class="bar-value">' + (valid ? value.toFixed(3) : '—') + '</span></div>';
      }).join("") + '</div></div>';
  }).join("");
}

// ─── Top-Level Mode & Tab Switching ───
let currentMainMode = "research"; // "research" or "live"
let currentResearchTab = "dataset-explorer";
let currentExplorerBenchmark = "cicids2017";
let currentCmpBenchmark = "cicids2017";

function switchMainMode(mode) {
  currentMainMode = mode;
  const btnResearch = document.getElementById("btn-mode-research");
  const btnLive = document.getElementById("btn-mode-live");
  const viewResearch = document.getElementById("view-research");
  const viewLive = document.getElementById("view-live");
  const hintEl = document.getElementById("mode-hint-text");

  if (mode === "research") {
    if (btnResearch) btnResearch.classList.add("active");
    if (btnLive) btnLive.classList.remove("active");
    if (viewResearch) viewResearch.style.display = "block";
    if (viewLive) viewLive.style.display = "none";
    if (hintEl) {
      hintEl.innerHTML = `Mode: <strong>Research &amp; Benchmarks</strong> — complete held-out evaluation on CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15.`;
    }
    showResearchTab(currentResearchTab || "dataset-explorer");
  } else {
    if (btnResearch) btnResearch.classList.remove("active");
    if (btnLive) btnLive.classList.add("active");
    if (viewResearch) viewResearch.style.display = "none";
    if (viewLive) viewLive.style.display = "block";
    if (hintEl) {
      hintEl.innerHTML = `Mode: <strong>Live Exhibition Demo</strong> — fast interactive 200-flow sample, streaming PCAP replay, in-memory attack simulation.`;
    }
  }
}

function showResearchTab(tabName) {
  currentResearchTab = tabName;
  document.querySelectorAll(".research-subnav button").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.tab === tabName);
  });
  document.querySelectorAll("#view-research .tab-content").forEach(el => {
    el.classList.toggle("active", el.id === "tab-" + tabName);
  });

  if (tabName === "dataset-explorer") {
    loadDatasetExplorer();
  } else if (tabName === "model-comparison") {
    loadModelComparison();
  } else if (tabName === "performance-benchmarks") {
    loadPerformanceBenchmarks();
  } else if (tabName === "explainability-attacks") {
    loadExplainabilityAndAttacks();
  } else if (tabName === "autonomous-response") {
    loadAutonomousResponse();
  } else if (tabName === "replay-lab") {
    loadReplayLab();
  } else if (tabName === "overview") {
    loadOverview();
  } else if (tabName === "limitations") {
    loadLimitations();
  }
}

// Backward-compatibility router for existing calls
function showTab(name) {
  if (name === "live" || name === "live-monitor") {
    switchMainMode("live");
  } else {
    switchMainMode("research");
    if (name === "evidence" || name === "evaluation") {
      showResearchTab("dataset-explorer");
    } else if (name === "comparison") {
      showResearchTab("model-comparison");
    } else if (name === "flows" || name === "explainability") {
      showResearchTab("explainability-attacks");
    } else if (name === "response") {
      showResearchTab("autonomous-response");
    } else {
      showResearchTab(name);
    }
  }
}

// ─── SECTION 1: Dataset Explorer ───
async function loadDatasetExplorer() {
  const select = document.getElementById("explorer-dataset-select");
  if (select) currentExplorerBenchmark = select.value;
  try {
    const res = await fetch(`/api/dataset-explorer?benchmark=${currentExplorerBenchmark}`);
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    renderDatasetExplorer(data);
  } catch (err) {
    console.error("Failed to load dataset explorer:", err);
  }
}

function onExplorerDatasetChange() {
  const select = document.getElementById("explorer-dataset-select");
  if (select) currentExplorerBenchmark = select.value;
  loadDatasetExplorer();
}

function renderDatasetExplorer(data) {
  if (!data) return;

  renderDatasetVisuals(data);

  // Stat tiles
  const rawRowsEl = document.getElementById("ds-raw-rows");
  if (rawRowsEl) rawRowsEl.textContent = (data.raw_rows || 0).toLocaleString();
  const rawFilesEl = document.getElementById("ds-raw-files");
  if (rawFilesEl) rawFilesEl.textContent = `${data.raw_capture_files} capture files`;

  const dedupRowsEl = document.getElementById("ds-dedup-rows");
  if (dedupRowsEl) dedupRowsEl.textContent = (data.dedup_rows || 0).toLocaleString();
  const dedupRemovedEl = document.getElementById("ds-dedup-removed");
  if (dedupRemovedEl) dedupRemovedEl.textContent = `${(data.duplicate_rows_removed || 0).toLocaleString()} duplicate rows removed`;

  const splitEl = document.getElementById("ds-split-summary");
  if (splitEl) splitEl.textContent = `${data.train_split_pct}% / ${data.val_split_pct}% / ${data.test_split_pct}%`;
  const testPopEl = document.getElementById("ds-test-population");
  if (testPopEl) testPopEl.textContent = `${(data.test_population || 0).toLocaleString()} held-out test flows`;

  const prevEl = document.getElementById("ds-attack-prev");
  if (prevEl) prevEl.textContent = `${(data.attack_prevalence_pct || 0).toFixed(2)}%`;
  const barBenign = document.getElementById("ds-bar-benign");
  if (barBenign) barBenign.style.width = `${(100 - (data.attack_prevalence_pct || 0)).toFixed(1)}%`;
  const barAttack = document.getElementById("ds-bar-attack");
  if (barAttack) barAttack.style.width = `${(data.attack_prevalence_pct || 0).toFixed(1)}%`;
  const countsEl = document.getElementById("ds-benign-attack-counts");
  if (countsEl) countsEl.textContent = `${(data.benign_count || 0).toLocaleString()} Benign / ${(data.attack_count || 0).toLocaleString()} Attack`;

  // Preprocessing & environment
  const envEl = document.getElementById("ds-env");
  if (envEl) envEl.textContent = data.environment || "—";
  const datesEl = document.getElementById("ds-dates");
  if (datesEl) datesEl.textContent = data.capture_dates || "—";
  const contractNameEl = document.getElementById("ds-contract-name");
  if (contractNameEl) contractNameEl.textContent = `${data.contract} (${data.feature_count} features)`;
  const dropsEl = document.getElementById("ds-boundary-drops");
  if (dropsEl) dropsEl.textContent = data.boundary_drops_text || "—";
  const badgeEl = document.getElementById("ds-contract-badge");
  if (badgeEl) badgeEl.textContent = `${data.contract} Contract`;

  // Feature list badges
  const featEl = document.getElementById("ds-features-list");
  if (featEl && data.features) {
    featEl.innerHTML = data.features.map(f => `<span class="badge badge-dim">${escapeHtml(f)}</span>`).join(" ");
  }

  // Attack Classes table
  const tbody = document.getElementById("ds-attack-classes-tbody");
  if (tbody && data.attack_classes) {
    tbody.innerHTML = "";
    data.attack_classes.forEach(ac => {
      const tr = document.createElement("tr");
      const detColor = ac.detection_rate >= 0.8 ? 'var(--green)' : (ac.detection_rate >= 0.3 ? 'var(--orange)' : 'var(--red)');
      tr.innerHTML = `
        <td><strong>${escapeHtml(ac.class_name)}</strong></td>
        <td><span class="badge badge-dim">${escapeHtml(ac.category)}</span></td>
        <td class="mono">${(ac.support || 0).toLocaleString()}</td>
        <td class="mono"><strong style="color:${detColor}">${(ac.detection_rate * 100).toFixed(2)}%</strong></td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Cross Dataset comparison table
  const crossTbody = document.getElementById("cross-dataset-tbody");
  if (crossTbody && data.cross_dataset_summary) {
    crossTbody.innerHTML = "";
    data.cross_dataset_summary.forEach(row => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${escapeHtml(row.benchmark_name)}</strong></td>
        <td class="mono">${escapeHtml(row.contract)}</td>
        <td class="mono">${(row.raw_rows || 0).toLocaleString()}</td>
        <td class="mono">${(row.dedup_rows || 0).toLocaleString()}</td>
        <td class="mono">${(row.test_population || 0).toLocaleString()}</td>
        <td class="mono">${(row.attack_prevalence_pct || 0).toFixed(1)}%</td>
        <td class="mono">${fmt(row.rf_f1)}</td>
        <td class="mono">${fmt(row.lstm_f1)}</td>
        <td class="mono"><strong style="color:var(--accent)">${fmt(row.fusion_f1)}</strong></td>
        <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(row.primary_research_finding)}</td>
      `;
      crossTbody.appendChild(tr);
    });
  }
}

// ─── SECTION 2: Model Comparison ───
async function loadModelComparison() {
  const select = document.getElementById("cmp-dataset-select");
  if (select) currentCmpBenchmark = select.value;
  try {
    const res = await fetch(`/api/comparison?benchmark=${currentCmpBenchmark}`);
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    renderModelComparison(data);
  } catch (err) {
    console.error("Failed to load model comparison:", err);
  }
}

function onCmpDatasetChange() {
  const select = document.getElementById("cmp-dataset-select");
  if (select) currentCmpBenchmark = select.value;
  loadModelComparison();
}

function renderModelComparison(data) {
  if (!data || !data.models) return;
  renderModelMetricsChart(data);

  // Degenerate alert
  const alertEl = document.getElementById("cmp-degenerate-alert");
  const alertText = document.getElementById("cmp-degenerate-text");
  if (data.fusion && data.fusion.is_degenerate) {
    if (alertEl) alertEl.style.display = "block";
    if (alertText) alertText.textContent = data.fusion.warning;
  } else {
    if (alertEl) alertEl.style.display = "none";
  }

  // RF Card
  const rf = data.models.random_forest || {};
  const rfF1El = document.getElementById("cmp-rf-f1");
  if (rfF1El) rfF1El.textContent = fmt(rf.f1);
  const rfAccEl = document.getElementById("cmp-rf-acc");
  if (rfAccEl) rfAccEl.textContent = rf.accuracy != null ? (rf.accuracy * 100).toFixed(2) + "%" : "—";
  const rfPrecEl = document.getElementById("cmp-rf-prec");
  if (rfPrecEl) rfPrecEl.textContent = fmt(rf.precision);
  const rfRecEl = document.getElementById("cmp-rf-rec");
  if (rfRecEl) rfRecEl.textContent = fmt(rf.recall);
  const rfAucEl = document.getElementById("cmp-rf-auc");
  if (rfAucEl) rfAucEl.textContent = fmt(rf.roc_auc);
  const rfPrAucEl = document.getElementById("cmp-rf-prauc");
  if (rfPrAucEl) rfPrAucEl.textContent = fmt(rf.pr_auc);
  const rfCiEl = document.getElementById("cmp-rf-ci");
  if (rfCiEl) {
    const ci = data.bootstrap_cis && data.bootstrap_cis.random_forest ? data.bootstrap_cis.random_forest.threshold_metrics : null;
    rfCiEl.textContent = ci && ci.f1 ? `[${fmt(ci.f1.ci_lower)}, ${fmt(ci.f1.ci_upper)}]` : "—";
  }

  // LSTM Card
  const lstm = data.models.lstm || {};
  const lstmF1El = document.getElementById("cmp-lstm-f1");
  if (lstmF1El) lstmF1El.textContent = fmt(lstm.f1);
  const lstmAccEl = document.getElementById("cmp-lstm-acc");
  if (lstmAccEl) lstmAccEl.textContent = lstm.accuracy != null ? (lstm.accuracy * 100).toFixed(2) + "%" : "—";
  const lstmPrecEl = document.getElementById("cmp-lstm-prec");
  if (lstmPrecEl) lstmPrecEl.textContent = fmt(lstm.precision);
  const lstmRecEl = document.getElementById("cmp-lstm-rec");
  if (lstmRecEl) lstmRecEl.textContent = fmt(lstm.recall);
  const lstmAucEl = document.getElementById("cmp-lstm-auc");
  if (lstmAucEl) lstmAucEl.textContent = fmt(lstm.roc_auc);
  const lstmPrAucEl = document.getElementById("cmp-lstm-prauc");
  if (lstmPrAucEl) lstmPrAucEl.textContent = fmt(lstm.pr_auc);
  const lstmCiEl = document.getElementById("cmp-lstm-ci");
  if (lstmCiEl) {
    const ci = data.bootstrap_cis && data.bootstrap_cis.lstm ? data.bootstrap_cis.lstm.threshold_metrics : null;
    lstmCiEl.textContent = ci && ci.f1 ? `[${fmt(ci.f1.ci_lower)}, ${fmt(ci.f1.ci_upper)}]` : "—";
  }

  // Fusion Card
  const fusion = data.models.fusion || {};
  const fusionF1El = document.getElementById("cmp-fusion-f1");
  if (fusionF1El) fusionF1El.textContent = fmt(fusion.f1);
  const fusionAccEl = document.getElementById("cmp-fusion-acc");
  if (fusionAccEl) fusionAccEl.textContent = fusion.accuracy != null ? (fusion.accuracy * 100).toFixed(2) + "%" : "—";
  const fusionPrecEl = document.getElementById("cmp-fusion-prec");
  if (fusionPrecEl) fusionPrecEl.textContent = fmt(fusion.precision);
  const fusionRecEl = document.getElementById("cmp-fusion-rec");
  if (fusionRecEl) fusionRecEl.textContent = fmt(fusion.recall);
  const fusionAucEl = document.getElementById("cmp-fusion-auc");
  if (fusionAucEl) fusionAucEl.textContent = fmt(fusion.roc_auc);
  const fusionPrAucEl = document.getElementById("cmp-fusion-prauc");
  if (fusionPrAucEl) fusionPrAucEl.textContent = fmt(fusion.pr_auc);
  const fusionFormulaEl = document.getElementById("cmp-fusion-formula");
  if (fusionFormulaEl) fusionFormulaEl.textContent = data.fusion.formula || "—";
  const fusionAlphaBadge = document.getElementById("cmp-fusion-alpha-badge");
  if (fusionAlphaBadge) fusionAlphaBadge.textContent = `α = ${fmt(data.fusion.alpha, 2)}`;

  // 3 Side-by-Side Confusion Matrices
  const cms = data.confusion_matrices || {};
  const rfCm = cms.random_forest || { tn: 0, fp: 0, fn: 0, tp: 0 };
  const lstmCm = cms.lstm || { tn: 0, fp: 0, fn: 0, tp: 0 };
  const fusionCm = cms.fusion || { tn: 0, fp: 0, fn: 0, tp: 0 };

  const setCm = (prefix, cm) => {
    const tn = document.getElementById(`${prefix}-tn`);
    const fp = document.getElementById(`${prefix}-fp`);
    const fn = document.getElementById(`${prefix}-fn`);
    const tp = document.getElementById(`${prefix}-tp`);
    if (tn) tn.textContent = (cm.tn || 0).toLocaleString();
    if (fp) fp.textContent = (cm.fp || 0).toLocaleString();
    if (fn) fn.textContent = (cm.fn || 0).toLocaleString();
    if (tp) tp.textContent = (cm.tp || 0).toLocaleString();
  };
  setCm("cmp-cm-rf", rfCm);
  setCm("cmp-cm-lstm", lstmCm);
  setCm("cmp-cm-fusion", fusionCm);

  // Per-family performance
  const famTbody = document.getElementById("cmp-per-family-tbody");
  if (famTbody && data.per_family) {
    famTbody.innerHTML = "";
    data.per_family.forEach(fam => {
      const tr = document.createElement("tr");
      const detRate = fam.detection_rate != null ? fam.detection_rate : (fam.recall != null ? fam.recall : 0);
      const errRate = 1.0 - detRate;
      const detColor = detRate >= 0.8 ? 'var(--green)' : (detRate >= 0.3 ? 'var(--orange)' : 'var(--red)');
      tr.innerHTML = `
        <td><strong>${escapeHtml(fam.attack_family || fam.family || "Attack")}</strong></td>
        <td class="mono">${(fam.support || fam.test_flows || 0).toLocaleString()}</td>
        <td class="mono">${(fam.correct_detections || Math.round(detRate * (fam.support || fam.test_flows || 0))).toLocaleString()}</td>
        <td class="mono"><strong style="color:${detColor}">${(detRate * 100).toFixed(2)}%</strong></td>
        <td class="mono">${(errRate * 100).toFixed(2)}%</td>
      `;
      famTbody.appendChild(tr);
    });
  }
}


function renderPerformanceVisuals(data) {
  const root = document.getElementById("perf-policy-chart");
  if (!root) return;
  const items = Array.isArray(data && data.policy_latency_benchmarks) ? data.policy_latency_benchmarks : [];
  if (!items.length) {
    root.innerHTML = '<div class="chart-empty">Policy latency measurements unavailable.</div>';
    return;
  }
  const valid = items.filter(item => Number.isFinite(Number(item.median_latency_us)) && Number(item.median_latency_us) >= 0);
  if (!valid.length) {
    root.innerHTML = '<div class="chart-empty">No valid policy latency values were returned.</div>';
    return;
  }
  const max = Math.max(...valid.map(item => Number(item.median_latency_us)), 0.000001);
  root.className = "bar-chart";
  root.innerHTML = valid.map(item => {
    const value = Number(item.median_latency_us);
    const width = Math.max(value > 0 ? 1 : 0, value / max * 100);
    const winner = String(item.policy_name || "").toLowerCase().includes("cost-optimal");
    return '<div class="bar-row" style="grid-template-columns:minmax(110px,150px) minmax(0,1fr) 78px">' +
      '<span class="bar-label" title="' + escapeHtml(item.policy_name || "Policy") + '">' + escapeHtml(item.policy_name || "Policy") + '</span>' +
      '<div class="bar-track"><div class="bar-fill" style="width:' + width.toFixed(2) + '%;background:' + (winner ? "#67e8f9" : "#a78bfa") + '"></div></div>' +
      '<span class="bar-value">' + value.toFixed(2) + ' µs</span></div>';
  }).join("");
}

// ─── SECTION 3: Performance Benchmarks ───
async function loadPerformanceBenchmarks() {
  try {
    const res = await fetch("/api/performance-benchmarks");
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    renderPerformanceBenchmarks(data);
  } catch (err) {
    console.error("Failed to load performance benchmarks:", err);
  }
}

function renderPerformanceBenchmarks(data) {
  if (!data) return;
  renderPerformanceVisuals(data);

  // Policy latency table
  const polTbody = document.getElementById("perf-policy-latency-tbody");
  if (polTbody && data.policy_latency_benchmarks) {
    polTbody.innerHTML = "";
    data.policy_latency_benchmarks.forEach(item => {
      const isWinner = item.policy_name.includes("Cost-Optimal");
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${isWinner ? `<span class="badge badge-green">${escapeHtml(item.policy_name)}</span>` : escapeHtml(item.policy_name)}</strong></td>
        <td class="mono">${item.median_latency_us.toFixed(2)} µs</td>
        <td class="mono">${(item.throughput_decisions_per_s || 0).toLocaleString()} dec/s</td>
        <td style="font-size:12px; color:var(--text-muted);">${escapeHtml(item.notes || "")}</td>
      `;
      polTbody.appendChild(tr);
    });
  }

  const speedupEl = document.getElementById("perf-speedup-text");
  if (speedupEl && data.speedup_comparison) {
    speedupEl.innerHTML = `<strong>Cost-Optimal Speedup:</strong> ${escapeHtml(data.speedup_comparison.speedup_statement)} (${escapeHtml(data.speedup_comparison.conclusion)})`;
  }

  // Detector latency table
  const detTbody = document.getElementById("perf-detector-latency-tbody");
  if (detTbody && data.detector_latency_benchmarks) {
    detTbody.innerHTML = "";
    data.detector_latency_benchmarks.forEach(item => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${escapeHtml(item.path)}</strong></td>
        <td class="mono">${item.latency_per_flow_us.toFixed(2)} µs</td>
        <td class="mono">${(item.throughput_flows_per_s || 0).toLocaleString()} flows/s</td>
      `;
      detTbody.appendChild(tr);
    });
  }

  // Burst benchmark
  if (data.burst_traffic_benchmark) {
    const b = data.burst_traffic_benchmark;
    const pktsEl = document.getElementById("perf-burst-packets");
    if (pktsEl) pktsEl.textContent = `${(b.packets_processed || 0).toLocaleString()} / ${(b.target_packets || 0).toLocaleString()}`;
    const rateEl = document.getElementById("perf-burst-rate");
    if (rateEl) rateEl.textContent = `${(b.peak_packet_rate || 0).toLocaleString()} pkts/s`;
    const flowsEl = document.getElementById("perf-burst-flows");
    if (flowsEl) flowsEl.textContent = `${b.flows_reconstructed} flows (${b.flows_completed} completed via FIN/RST)`;
    const latPercEl = document.getElementById("perf-burst-latency-percentiles");
    if (latPercEl && b.p50_latency_ms) {
      latPercEl.textContent = `P50 = ${b.p50_latency_ms} ms | P95 = ${b.p95_latency_ms} ms`;
    }
  }

  // Resource profile
  if (data.resource_profile) {
    const r = data.resource_profile;
    const memEl = document.getElementById("perf-mem-total");
    if (memEl) memEl.textContent = r.total_process_ram || "—";
    const cpuEl = document.getElementById("perf-cpu-burst");
    if (cpuEl) cpuEl.textContent = r.burst_cpu_utilization || "—";
  }

  // Repeated runs CI
  const ciTbody = document.getElementById("perf-ci-tbody");
  if (ciTbody && data.repeated_runs_ci) {
    ciTbody.innerHTML = "";
    data.repeated_runs_ci.forEach(row => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${escapeHtml(row.benchmark)}</strong></td>
        <td class="mono">${escapeHtml(row.contract)}</td>
        <td class="mono">${escapeHtml(row.rf_f1_ci)}</td>
        <td class="mono">${escapeHtml(row.lstm_f1_ci)}</td>
        <td class="mono"><strong style="color:var(--accent)">${escapeHtml(row.fusion_f1_ci)}</strong></td>
      `;
      ciTbody.appendChild(tr);
    });
  }

  // Canonical Artifacts Registry Table
  const artTbody = document.getElementById("perf-artifacts-tbody");
  const artBadge = document.getElementById("perf-artifacts-loaded-badge");
  if (artTbody && data.provenance && data.provenance.loaded_artifacts) {
    const arts = data.provenance.loaded_artifacts;
    if (artBadge) {
      artBadge.textContent = `${arts.length} / ${arts.length} Canonical Artifacts Dynamically Loaded`;
    }
    artTbody.innerHTML = "";
    const purposeMap = {
      "latency_reconciliation.json": "Isolated Microbenchmarks & Policy Speedup",
      "throughput_metrics.json": "1,000-Packet Synthetic Burst Line-Rate Assembly",
      "latency_metrics.json": "Pipeline Stages & Queue Contention Latencies",
      "resource_metrics.json": "Peak Stress RSS, Soak Growth & Sustained CPU Profile",
      "multi_seed_metrics.json": "3-Seed Repeated Stability Sweeps (Mean ± Std)",
      "bootstrap_cis.json": "95% Empirical Bootstrap Confidence Intervals (B=1000)",
    };

    arts.forEach(art => {
      const filename = art.path.split("/").pop();
      const purpose = purposeMap[filename] || "Empirical Benchmark Artifact";
      const sizeKb = (art.size_bytes / 1024).toFixed(1) + " KB";
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><code style="color:var(--accent);">${escapeHtml(art.path)}</code></td>
        <td>${escapeHtml(purpose)}</td>
        <td class="mono">${sizeKb}</td>
        <td><span class="badge badge-green">VERIFIED ON DISK</span></td>
      `;
      artTbody.appendChild(tr);
    });
  }
}


// ─── SECTION 4: Explainability & Attack Analysis ───
async function loadExplainabilityAndAttacks() {
  const bench = currentExplorerBenchmark || "cicids2017";
  try {
    const res = await fetch(`/api/explainability?benchmark=${bench}`);
    if (!res.ok) return;
    const data = await res.json();
    renderExplainabilityAndAttacks(data);
  } catch (err) {
    console.error("Failed to load explainability:", err);
  }
  loadFlows();
}

function renderExplainabilityAndAttacks(data) {
  if (!data) return;

  // Blind spots
  const blindContainer = document.getElementById("blind-spots-container");
  if (blindContainer && data.critical_blind_spots) {
    blindContainer.innerHTML = "";
    data.critical_blind_spots.forEach(bs => {
      const card = document.createElement("div");
      card.className = "blindspot-card";
      card.innerHTML = `
        <div class="blindspot-title">
          <span>⚠️ ${escapeHtml(bs.attack_class)}</span>
          <span class="mono">${(bs.recall_rate * 100).toFixed(2)}% Recall (${(bs.missed_rate * 100).toFixed(2)}% Missed)</span>
        </div>
        <div class="blindspot-desc">
          <strong>Support:</strong> ${bs.test_support} test flows. <strong>Empirical Finding:</strong> ${escapeHtml(bs.finding)}
        </div>
      `;
      blindContainer.appendChild(card);
    });
  }

  // TreeSHAP Global Importance table with visual bar
  const tbody = document.getElementById("shap-global-tbody");
  if (tbody && data.global_importance) {
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

    const maxVal = Math.max(...data.global_importance.map(x => Number(x.mean_abs_shap || x.importance || 0.001)));

    data.global_importance.forEach((item, idx) => {
      const val = Number(item.mean_abs_shap || item.importance || 0);
      const pct = maxVal > 0 ? Math.min(100, Math.round((val / maxVal) * 100)) : 10;
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td class="mono">#${idx + 1}</td>
        <td><strong>${escapeHtml(item.feature)}</strong></td>
        <td class="mono">${escapeHtml(data.contract || "R10")}</td>
        <td class="mono">${fmt(val)}</td>
        <td>
          <div class="shap-bar-track" style="height:12px; width:140px;">
            <div class="shap-bar-fill pos" style="width:${pct}%;"></div>
          </div>
        </td>
        <td style="color:var(--text-muted); font-size:12px;">${descriptions[item.feature] || "Traffic flow moment metric"}</td>
      `;
      tbody.appendChild(tr);
    });
  }
}

// ─── SECTION 5: Autonomous Response Evaluation ───
async function loadAutonomousResponse() {
  const regimeSelect = document.getElementById("resp-regime-select");
  const modeSelect = document.getElementById("resp-mode-select");
  const regime = regimeSelect ? regimeSelect.value : "standard_enterprise";
  const mode = modeSelect ? modeSelect.value : "4-action";

  try {
    const res = await fetch(`/api/response-benchmark?regime=${regime}&mode=${mode}`);
    if (!res.ok) return;
    const data = await res.json();
    renderAutonomousResponse(data);
  } catch (err) {
    console.error("Failed to load response benchmark:", err);
  }
}

function onResponseParamsChange() {
  loadAutonomousResponse();
}

function renderAutonomousResponse(data) {
  if (!data || !data.policies) return;

  // Head to head winner callout
  const winnerEl = document.getElementById("resp-winner-text");
  if (winnerEl && data.head_to_head) {
    const h2h = data.head_to_head;
    const isBaseline = h2h.superior_policy.includes("Cost_Optimal");
    const diffPct = Math.abs(h2h.relative_cost_reduction_pct).toFixed(2);
    winnerEl.innerHTML = isBaseline
      ? `<span class="badge badge-green">Cost-Optimal Baseline WON</span> Achieving <strong>${diffPct}% lower operational cost</strong> than the trained DQN.`
      : `<span class="badge badge-purple">DQN Achieved Lower Cost</span> with ${diffPct}% cost reduction (Failed the 15% practical improvement target).`;
  }

  // Policies table
  const tbody = document.getElementById("resp-policies-tbody");
  if (tbody) {
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

  // Rollback evidence ledger
  const rbTbody = document.getElementById("resp-rollback-tbody");
  if (rbTbody && data.rollback_evidence) {
    rbTbody.innerHTML = "";
    data.rollback_evidence.forEach(rb => {
      const tr = document.createElement("tr");
      const isOk = rb.status === "RESTORED" || rb.status === "IDEMPOTENT_NOOP";
      const badgeCls = isOk ? "badge-green" : "badge-red";
      tr.innerHTML = `
        <td class="mono">${escapeHtml(rb.tx_id)}</td>
        <td>${escapeHtml(rb.action)}</td>
        <td><span class="badge ${badgeCls}">${escapeHtml(rb.status)}</span></td>
        <td class="mono" style="font-size:11px;">${escapeHtml(rb.safety_state)}</td>
      `;
      rbTbody.appendChild(tr);
    });
  }
}

// Backward compatibility aliases
const loadEvaluation = loadDatasetExplorer;
const loadComparison = loadModelComparison;
const loadExplainability = loadExplainabilityAndAttacks;
const loadResponseBenchmark = loadAutonomousResponse;

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
  // The selected benchmark determines its feature contract automatically.
  // Keep the exhibition path simple: no manual contract selector is exposed.
  if (currentCsvMode === "exhibition") updateModeBDescription();
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
  const benchmarkSelect = document.getElementById("csv-eval-model");
  const btn = document.getElementById("btn-run-csv-eval");
  const benchmark = benchmarkSelect ? benchmarkSelect.value : "cicids2017";
  const contract = BENCHMARK_CONTRACT_MAP[benchmark] || "R10";
  const payload = { mode: "exhibition", benchmark, contract };

  try {
    if (btn) { btn.disabled = true; btn.textContent = "⏳ Running sample..."; }
    if (statusEl) statusEl.textContent = `Running the held-out ${benchmark} sample through RF, LSTM and score fusion...`;

    const res = await fetch("/api/csv/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok || data.error) throw new Error(data.error || `HTTP ${res.status}`);

    lastCsvEvalResult = data;
    renderCsvEvaluationResults(data);
    if (statusEl) {
      const rows = data.row_accounting || {};
      statusEl.textContent = `Evaluation complete · ${data.benchmark} · ${(rows.evaluated_rows || 0).toLocaleString()} flows · ${Number(data.evaluation_latency_ms || 0).toFixed(1)} ms · ${Number(data.throughput_flows_per_s || 0).toFixed(0)} flows/s`;
    }
  } catch (err) {
    console.error("Sample evaluation failed:", err);
    if (statusEl) statusEl.textContent = `Evaluation failed: ${err.message}. Check that the backend is running, then retry.`;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "⚡ Run Sample Evaluation"; }
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
function handleRouteHash() {
  const hash = window.location.hash;
  if (hash === "#replay-lab") {
    switchMainMode("research");
    showResearchTab("replay-lab");
  } else if (hash === "#live") {
    switchMainMode("live");
  } else if (hash.startsWith("#tab-")) {
    const tab = hash.replace("#tab-", "");
    switchMainMode("research");
    showResearchTab(tab);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  onLiveModeChange();
  onCsvModelChange();
  renderAttackSources([]);
  renderDevices({ mode: null });
  switchMainMode("research");
  showResearchTab("dataset-explorer");
  handleRouteHash();
  setInterval(pollLive, LIVE_POLL_MS);
});

window.addEventListener("hashchange", handleRouteHash);


// ═══════════════════ LABELLED REPLAY LAB CONTROLLER ═══════════════════
let replayPollInterval = null;
let replayLabConfigData = null;
let lastReplayStatus = null;

async function loadReplayLab() {
  try {
    const res = await fetch('/api/replay-lab/config');
    if (!res.ok) return;
    replayLabConfigData = await res.json();
    updateReplayFamilyDropdown();
    pollReplayStatus();
  } catch (err) {
    console.warn('Could not load Replay Lab config:', err);
  }
}

function onReplayDatasetChange() {
  updateReplayFamilyDropdown();
}

function updateReplayFamilyDropdown() {
  if (!replayLabConfigData || !replayLabConfigData.families) return;
  const dsSelect = document.getElementById('replay-dataset-select');
  const famSelect = document.getElementById('replay-family-select');
  if (!dsSelect || !famSelect) return;

  const ds = dsSelect.value;
  const currentVal = famSelect.value;
  famSelect.innerHTML = '<option value="mixed">Mixed (Benign &amp; Attack Stratified)</option>';

  replayLabConfigData.families.forEach(f => {
    if (f.family === 'Benign') return;
    const opt = document.createElement('option');
    opt.value = f.family;
    let available = true;
    let label = `${f.family}`;

    if (ds === 'cicids2017') {
      available = f.in_cicids2017;
      label += ` (${f.count_cicids2017} records)`;
    } else if (ds === 'cse2018') {
      available = f.in_cse2018;
      label += available ? ` (${f.count_cse2018} records)` : ' (Unavailable in CSE-2018)';
    } else {
      label += ` (${f.total_count} records across both)`;
    }

    opt.textContent = label;
    if (!available) {
      opt.disabled = true;
      opt.style.color = 'var(--text-dim)';
    }
    famSelect.appendChild(opt);
  });

  if ([...famSelect.options].some(o => o.value === currentVal && !o.disabled)) {
    famSelect.value = currentVal;
  } else {
    famSelect.value = 'mixed';
  }
}

function onReplayCountChange() {
  const countSelect = document.getElementById('replay-count-select');
  const customInput = document.getElementById('replay-custom-count');
  if (!countSelect || !customInput) return;
  customInput.style.display = (countSelect.value === 'custom') ? 'block' : 'none';
}

async function startReplayLab() {
  const ds = document.getElementById('replay-dataset-select').value;
  const countSel = document.getElementById('replay-count-select').value;
  let count = parseInt(countSel, 10);
  if (countSel === 'custom') {
    count = parseInt(document.getElementById('replay-custom-count').value, 10) || 1000;
  }
  count = Math.max(1, Math.min(10000, count));

  const sel = document.getElementById('replay-family-select').value;
  const speed = document.getElementById('replay-speed-select').value;
  const seed = parseInt(document.getElementById('replay-seed-input').value, 10) || 42;

  document.getElementById('btn-replay-start').disabled = true;
  document.getElementById('btn-replay-pause').disabled = false;
  document.getElementById('btn-replay-pause').textContent = '⏸ Pause';
  document.getElementById('btn-replay-restart').disabled = false;
  document.getElementById('btn-replay-stop').disabled = false;

  try {
    const res = await fetch('/api/replay-lab/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        dataset: ds,
        count: count,
        selection: sel,
        speed: speed,
        seed: seed,
      }),
    });
    if (!res.ok) throw new Error('Failed to start replay');
    if (replayPollInterval) clearInterval(replayPollInterval);
    replayPollInterval = setInterval(pollReplayStatus, 250);
    pollReplayStatus();
  } catch (err) {
    alert('Replay Lab start failed: ' + err.message);
    document.getElementById('btn-replay-start').disabled = false;
  }
}

async function togglePauseReplayLab() {
  const pauseBtn = document.getElementById('btn-replay-pause');
  if (!lastReplayStatus) return;
  const isPaused = lastReplayStatus.status === 'PAUSED';
  const endpoint = isPaused ? '/api/replay-lab/resume' : '/api/replay-lab/pause';

  try {
    const res = await fetch(endpoint, { method: 'POST' });
    if (res.ok) {
      pauseBtn.textContent = isPaused ? '⏸ Pause' : '▶ Resume';
      pollReplayStatus();
    }
  } catch (err) {
    console.error('Pause toggle failed:', err);
  }
}

async function restartReplayLab() {
  startReplayLab();
}

async function stopReplayLab() {
  try {
    const res = await fetch('/api/replay-lab/stop', { method: 'POST' });
    if (res.ok) {
      pollReplayStatus();
    }
  } catch (err) {
    console.error('Stop failed:', err);
  }
}

function exportReplayLabCSV() {
  window.location.href = '/api/replay-lab/export';
}

async function pollReplayStatus() {
  try {
    const res = await fetch('/api/replay-lab/status');
    if (!res.ok) return;
    const status = await res.json();
    lastReplayStatus = status;
    updateReplayLabUI(status);
  } catch (err) {
    console.debug('Replay status poll error:', err);
  }
}

function updateReplayLabUI(st) {
  const badgeEl = document.getElementById('replay-status-badge');
  if (badgeEl) {
    badgeEl.textContent = `Status: ${st.status}`;
    badgeEl.className = 'badge ' + (
      st.status === 'RUNNING' ? 'badge-blue' :
      st.status === 'COMPLETED' ? 'badge-green' :
      st.status === 'PAUSED' ? 'badge-orange' : 'badge-dim'
    );
  }

  const pLabel = document.getElementById('replay-progress-label');
  const rLabel = document.getElementById('replay-rate-label');
  const pBar = document.getElementById('replay-progress-bar');

  if (pLabel) pLabel.textContent = `Progress: ${st.progress_pct}% (${Number(st.processed_count).toLocaleString()} / ${Number(st.selected_count).toLocaleString()} flows)`;
  if (rLabel) rLabel.textContent = `${st.throughput_flows_per_s} flows/sec · ${st.elapsed_seconds}s elapsed`;
  if (pBar) pBar.style.width = `${st.progress_pct}%`;

  const m = st.metrics || {};
  const accEl = document.getElementById('replay-metric-acc');
  const precEl = document.getElementById('replay-metric-prec');
  const recEl = document.getElementById('replay-metric-rec');
  const f1El = document.getElementById('replay-metric-f1');

  if (accEl) accEl.textContent = m.accuracy !== undefined ? `${(m.accuracy * 100).toFixed(2)}%` : '—';
  if (precEl) precEl.textContent = m.precision !== undefined ? `${(m.precision * 100).toFixed(2)}%` : '—';
  if (recEl) recEl.textContent = m.recall !== undefined ? `${(m.recall * 100).toFixed(2)}%` : '—';
  if (f1El) f1El.textContent = m.f1 !== undefined ? m.f1.toFixed(4) : '—';

  const cm = m.confusion_matrix || { tp: 0, fp: 0, tn: 0, fn: 0 };
  const cmTp = document.getElementById('replay-cm-tp');
  const cmFp = document.getElementById('replay-cm-fp');
  const cmTn = document.getElementById('replay-cm-tn');
  const cmFn = document.getElementById('replay-cm-fn');

  if (cmTp) cmTp.textContent = Number(cm.tp).toLocaleString();
  if (cmFp) cmFp.textContent = Number(cm.fp).toLocaleString();
  if (cmTn) cmTn.textContent = Number(cm.tn).toLocaleString();
  if (cmFn) cmFn.textContent = Number(cm.fn).toLocaleString();

  const pfTbody = document.getElementById('replay-per-family-tbody');
  if (pfTbody) {
    const list = m.per_family || [];
    if (list.length === 0) {
      pfTbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-dim); padding: 16px;">Waiting for flow records...</td></tr>';
    } else {
      pfTbody.innerHTML = list.map(item => `
        <tr style="border-bottom: 1px solid var(--border);">
          <td style="padding: 6px 8px;">
            <span style="font-weight: 700; color: ${item.is_attack ? 'var(--status-red)' : 'var(--status-green)'};">
              ${escapeHtml(item.family)}
            </span>
          </td>
          <td style="padding: 6px 8px; text-align: right; font-family: var(--font-mono);">${Number(item.support).toLocaleString()}</td>
          <td style="padding: 6px 8px; text-align: right; font-family: var(--font-mono);">${Number(item.detected).toLocaleString()}</td>
          <td style="padding: 6px 8px; text-align: right; font-weight: 700; color: ${item.recall_pct >= 90 ? 'var(--status-green)' : item.recall_pct >= 50 ? 'var(--status-amber)' : 'var(--status-red)'}; font-family: var(--font-mono);">
            ${item.recall_pct.toFixed(1)}%
          </td>
        </tr>
      `).join('');
    }
  }

  const streamTbody = document.getElementById('replay-stream-tbody');
  if (streamTbody) {
    const flows = st.recent_flows || [];
    if (flows.length === 0) {
      if (st.status === 'RUNNING') {
        streamTbody.innerHTML = '<tr><td colspan="10" style="text-align: center; padding: 20px; color: var(--text-dim);">Streaming replayed flows...</td></tr>';
      }
    } else {
      streamTbody.innerHTML = flows.slice(-50).reverse().map(f => {
        const isAtt = f.rf_binary_prediction === 'ATTACK';
        const isCor = f.is_correct;
        const scorePct = (f.rf_attack_probability * 100).toFixed(1);
        const ruleMatches = (f.rule_matches || []).join(', ');

        return `
          <tr style="border-bottom: 1px solid var(--border);">
            <td style="padding: 7px 10px; font-family: var(--font-mono);">${f.flow_id}</td>
            <td style="padding: 7px 10px;"><span class="badge badge-dim" style="font-size:10px;">${escapeHtml(f.dataset)}</span></td>
            <td style="padding: 7px 10px; font-family: var(--font-mono); font-size: 11px;">
              ${escapeHtml(f.source_file.split('.')[0])} <span style="color:var(--text-dim);">#${f.source_row_index}</span>
            </td>
            <td style="padding: 7px 10px;">
              <strong style="color: ${f.is_attack ? 'var(--status-red)' : 'var(--status-green)'};">
                ${escapeHtml(f.ground_truth_family)}
              </strong>
              <div style="font-size: 10px; color: var(--text-dim);">${escapeHtml(f.original_label)}</div>
            </td>
            <td style="padding: 7px 10px; font-family: var(--font-mono); font-weight: 700; color: ${scorePct >= 50 ? 'var(--status-red)' : 'var(--status-green)'};">
              ${scorePct}%
            </td>
            <td style="padding: 7px 10px;">
              <span class="badge ${isAtt ? 'badge-red' : 'badge-green'}" style="font-size:10px;">${f.rf_binary_prediction}</span>
              ${isCor ? '<span style="color:var(--status-green); font-size:10px; margin-left:2px;">✓</span>' : '<span style="color:var(--status-red); font-size:10px; margin-left:2px;">✗</span>'}
            </td>
            <td style="padding: 7px 10px; font-size: 11px;">
              ${f.rule_triggered ? `<span class="badge badge-orange" style="font-size:10px;" title="${escapeHtml(ruleMatches)}">RULE MATCH</span>` : '<span style="color:var(--text-dim);">Clean</span>'}
            </td>
            <td style="padding: 7px 10px;">
              <span class="badge ${f.dqn_action === 'ISOLATE' ? 'badge-red' : f.dqn_action === 'RATE_LIMIT' ? 'badge-purple' : f.dqn_action === 'ALERT' ? 'badge-orange' : 'badge-green'}" style="font-size:10px;">
                ${escapeHtml(f.dqn_action)}
              </span>
            </td>
            <td style="padding: 7px 10px; font-size: 11px; color: var(--text-dim);">
              ${escapeHtml(f.safety_status)}
            </td>
            <td style="padding: 7px 10px; text-align: center;">
              <button class="btn btn-secondary" onclick="explainReplayFlow(${f.flow_id})" style="padding: 3px 8px; font-size: 10px;">Explain</button>
            </td>
          </tr>
        `;
      }).join('');
    }
  }

  if (st.status === 'COMPLETED' || st.status === 'STOPPED' || st.status === 'ERROR') {
    const startBtn = document.getElementById('btn-replay-start');
    const pauseBtn = document.getElementById('btn-replay-pause');
    const stopBtn = document.getElementById('btn-replay-stop');
    if (startBtn) startBtn.disabled = false;
    if (pauseBtn) pauseBtn.disabled = true;
    if (stopBtn) stopBtn.disabled = true;
    if (replayPollInterval) {
      clearInterval(replayPollInterval);
      replayPollInterval = null;
    }
  }
}

async function explainReplayFlow(flowId) {
  try {
    const res = await fetch('/api/replay-lab/explain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ flow_id: flowId }),
    });
    if (!res.ok) throw new Error('Explanation request failed');
    const data = await res.json();

    const modal = document.getElementById('flow-inspect-modal');
    if (!modal) return;
    modal.classList.add('active');

    document.getElementById('modal-flow-id').textContent = `Replay Flow #${data.flow_id}`;
    document.getElementById('modal-endpoints').textContent = `Dataset: ${data.benchmark ? data.benchmark.toUpperCase() : 'N/A'} · Source Label: ${data.original_label}`;
    document.getElementById('modal-gt').textContent = `${data.ground_truth_family} ("${data.original_label}")`;

    document.getElementById('modal-rf-score').textContent = (data.rf_attack_probability * 100).toFixed(1) + '%';
    document.getElementById('modal-lstm-score').textContent = 'N/A (Tabular RF Mode)';
    document.getElementById('modal-fusion-score').textContent = (data.rf_attack_probability * 100).toFixed(1) + '%';

    const decBadge = document.getElementById('modal-decision-badge');
    decBadge.textContent = data.rf_binary_prediction;
    decBadge.className = `badge ${data.rf_binary_prediction === 'ATTACK' ? 'badge-red' : 'badge-green'}`;

    document.getElementById('modal-dqn-action').textContent = data.dqn_action;
    document.getElementById('modal-dqn-desc').textContent = `Deterministic Safety Gate: ${data.safety_status} (Advisory Mode)`;

    const shapContainer = document.getElementById('modal-shap-container');
    if (shapContainer) {
      const sorted = (data.features || []).sort((a, b) => Math.abs(b.shap_attribution) - Math.abs(a.shap_attribution));
      shapContainer.innerHTML = sorted.map((feat, idx) => {
        const isInc = feat.shap_attribution > 0;
        return `
          <div style="background: var(--surface-2); border-left: 3px solid ${isInc ? 'var(--red)' : 'var(--green)'}; border-radius: 4px; padding: 6px 10px; margin-bottom: 6px; display: flex; justify-content: space-between; font-size: 11px;">
            <div>
              <strong class="mono">${idx + 1}. ${escapeHtml(feat.feature)}</strong>
              <div style="color: var(--text-dim); font-size: 10px;">Value: ${feat.value}</div>
            </div>
            <div style="text-align: right; font-family: var(--mono); font-weight: 700; color: ${isInc ? 'var(--red)' : 'var(--green)'};">
              ${feat.shap_attribution > 0 ? '+' : ''}${feat.shap_attribution.toFixed(4)}
              <div style="font-size: 9px; font-weight: normal; color: var(--text-dim);">${isInc ? '▲ Threat' : '▼ Benign'}</div>
            </div>
          </div>
        `;
      }).join('');
    }
  } catch (err) {
    alert('TreeSHAP explanation failed: ' + err.message);
  }
}
