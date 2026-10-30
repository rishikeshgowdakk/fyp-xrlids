"""Page 3: Model Evaluation & Multi-Dataset Benchmarks (Phase 12).

Displays empirical detection metrics, runtime inference speed, and model parameter efficiency
loaded dynamically from models/registry/champion_registry.json across all three canonical datasets:
CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pandas as pd
import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

st.set_page_config(page_title="Model Evaluation - XRL-IDARS", page_icon="📈", layout="wide")

st.title("📈 Model Evaluation & Multi-Dataset Benchmarks")
st.markdown("""
Examine empirical detection metrics, runtime inference speed, and model parameter efficiency across all
three canonical intrusion detection benchmarks: **CIC-IDS2017**, **CSE-CIC-IDS2018**, and **UNSW-NB15**.
All metrics are loaded directly from the empirical benchmark registry.
""")

st.divider()

# Load Champion Registry
registry_path = REPO_ROOT / "models" / "registry" / "champion_registry.json"
if not registry_path.exists():
    st.error("Champion registry not found at models/registry/champion_registry.json")
    st.stop()

with open(registry_path, "r") as f:
    registry = json.load(f)

benchmarks = registry.get("benchmarks", {})
bmark_keys = list(benchmarks.keys())

bmark_labels = {
    "cicids2017": "CIC-IDS2017 (R10 Contract - 10 Features)",
    "cse2018": "CSE-CIC-IDS2018 (R10 Contract - 10 Features)",
    "unswnb15": "UNSW-NB15 (R4 Contract - 4 Features)",
}

selected_label = st.selectbox("Select Target Benchmark Dataset", [bmark_labels.get(k, k) for k in bmark_keys])
selected_key = next((k for k in bmark_keys if bmark_labels.get(k, k) == selected_label), bmark_keys[0])

bdata = benchmarks[selected_key]
rf_m = bdata["rf_metrics"]
xgb_m = bdata["xgb_metrics"]
rf_lat = bdata["rf_latency"]
xgb_lat = bdata["xgb_latency"]
rf_size = bdata["rf_size_mb"]
xgb_size = bdata["xgb_size_mb"]
champion = bdata.get("champion", "Random Forest")

# KPI Columns
col_kpi1, col_kpi2, col_kpi3, col_kpi4 = st.columns(4)
col_kpi1.metric("Test Population", f"{rf_m['population']:,} Flows", f"Positive Support: {rf_m['positive_support']:,}")
col_kpi2.metric("Champion Selected", champion, "Strict F1 Selection")
f1_diff = (xgb_m['f1'] - rf_m['f1'])
col_kpi3.metric("XGBoost F1 Score", f"{xgb_m['f1']:.4f}", f"{f1_diff:+.4f} vs RF ({rf_m['f1']:.4f})")
lat_speedup = rf_lat['median_ms'] / max(0.001, xgb_lat['median_ms'])
col_kpi4.metric("Inference Speedup", f"{lat_speedup:.1f}x Faster", f"{xgb_lat['median_ms']:.2f} ms vs {rf_lat['median_ms']:.2f} ms")

st.divider()

# Comprehensive Metrics Comparison Table
metrics_table = [
    {
        "Metric": "Accuracy",
        "Random Forest Baseline": f"{rf_m['accuracy']*100:.2f}%",
        "XGBoost Candidate": f"{xgb_m['accuracy']*100:.2f}%",
        "Delta": f"{(xgb_m['accuracy'] - rf_m['accuracy'])*100:+.2f}%",
        "Winner": "XGBoost 🏆" if xgb_m['accuracy'] >= rf_m['accuracy'] else "Random Forest 🏆",
    },
    {
        "Metric": "Precision (Attack)",
        "Random Forest Baseline": f"{rf_m['precision']*100:.2f}%",
        "XGBoost Candidate": f"{xgb_m['precision']*100:.2f}%",
        "Delta": f"{(xgb_m['precision'] - rf_m['precision'])*100:+.2f}%",
        "Winner": "XGBoost 🏆" if xgb_m['precision'] >= rf_m['precision'] else "Random Forest 🏆",
    },
    {
        "Metric": "Recall (Attack)",
        "Random Forest Baseline": f"{rf_m['recall']*100:.2f}%",
        "XGBoost Candidate": f"{xgb_m['recall']*100:.2f}%",
        "Delta": f"{(xgb_m['recall'] - rf_m['recall'])*100:+.2f}%",
        "Winner": "XGBoost 🏆" if xgb_m['recall'] >= rf_m['recall'] else "Random Forest 🏆",
    },
    {
        "Metric": "F1 Score (Attack)",
        "Random Forest Baseline": f"{rf_m['f1']:.4f}",
        "XGBoost Candidate": f"{xgb_m['f1']:.4f}",
        "Delta": f"{(xgb_m['f1'] - rf_m['f1']):+.4f}",
        "Winner": "XGBoost 🏆" if xgb_m['f1'] >= rf_m['f1'] else "Random Forest 🏆",
    },
    {
        "Metric": "PR-AUC",
        "Random Forest Baseline": f"{rf_m['pr_auc']:.4f}",
        "XGBoost Candidate": f"{xgb_m['pr_auc']:.4f}",
        "Delta": f"{(xgb_m['pr_auc'] - rf_m['pr_auc']):+.4f}",
        "Winner": "XGBoost 🏆" if xgb_m['pr_auc'] >= rf_m['pr_auc'] else "Random Forest 🏆",
    },
    {
        "Metric": "ROC-AUC",
        "Random Forest Baseline": f"{rf_m['roc_auc']:.4f}",
        "XGBoost Candidate": f"{xgb_m['roc_auc']:.4f}",
        "Delta": f"{(xgb_m['roc_auc'] - rf_m['roc_auc']):+.4f}",
        "Winner": "XGBoost 🏆" if xgb_m['roc_auc'] >= rf_m['roc_auc'] else "Random Forest 🏆",
    },
    {
        "Metric": "False Positive Rate (FPR)",
        "Random Forest Baseline": f"{rf_m['fpr']*100:.2f}%",
        "XGBoost Candidate": f"{xgb_m['fpr']*100:.2f}%",
        "Delta": f"{(xgb_m['fpr'] - rf_m['fpr'])*100:+.2f}%",
        "Winner": "XGBoost (Lower FPR) 🏆" if xgb_m['fpr'] <= rf_m['fpr'] else "Random Forest 🏆",
    },
    {
        "Metric": "Median Latency (ms)",
        "Random Forest Baseline": f"{rf_lat['median_ms']:.2f} ms",
        "XGBoost Candidate": f"{xgb_lat['median_ms']:.2f} ms",
        "Delta": f"{lat_speedup:.1f}x speedup",
        "Winner": "XGBoost 🏆",
    },
    {
        "Metric": "Model Footprint (MB)",
        "Random Forest Baseline": f"{rf_size:.2f} MB",
        "XGBoost Candidate": f"{xgb_size:.2f} MB",
        "Delta": f"{rf_size/max(0.01, xgb_size):.1f}x smaller",
        "Winner": "XGBoost 🏆",
    },
]

st.subheader(f"📊 Head-to-Head Performance Matrix: {selected_label}")
st.dataframe(pd.DataFrame(metrics_table), use_container_width=True)

st.divider()

col_left, col_right = st.columns(2)

with col_left:
    st.subheader("⚡ Latency & Efficiency Advantage")
    st.markdown(f"""
    - **Inference Speed:** XGBoost achieves **{xgb_lat['median_ms']:.3f} ms** median latency vs **{rf_lat['median_ms']:.2f} ms** for Random Forest ({lat_speedup:.1f}x speedup).
    - **Model Serialization:** XGBoost serializes to **{xgb_size:.2f} MB** native JSON vs **{rf_size:.2f} MB** joblib pickle ({rf_size/max(0.01, xgb_size):.1f}x compression).
    """)
    lat_chart_df = pd.DataFrame({
        "Model": ["Random Forest Baseline", "XGBoost Candidate"],
        "Median Latency (ms)": [rf_lat['median_ms'], xgb_lat['median_ms']],
    }).set_index("Model")
    st.bar_chart(lat_chart_df)

with col_right:
    st.subheader("🎯 False Positive Control")
    fpr_reduction = (rf_m['fpr'] - xgb_m['fpr']) / max(0.0001, rf_m['fpr']) * 100
    st.markdown(f"""
    - **Operational False Alarms:** In enterprise operations, reducing false positives is critical.
    - On this benchmark, XGBoost achieved an FPR of **{xgb_m['fpr']*100:.2f}%** vs **{rf_m['fpr']*100:.2f}%** for Random Forest (a **{fpr_reduction:.1f}% reduction** in false positive alerts).
    """)
    fpr_chart_df = pd.DataFrame({
        "Model": ["Random Forest Baseline", "XGBoost Candidate"],
        "False Positive Rate (%)": [rf_m['fpr'] * 100.0, xgb_m['fpr'] * 100.0],
    }).set_index("Model")
    st.bar_chart(fpr_chart_df)
