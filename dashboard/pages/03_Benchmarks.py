"""Page 3: Operational Machine Learning Benchmarks — XRL-IDARS."""

from __future__ import annotations

import json
from pathlib import Path
import platform
import sys

import pandas as pd
import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

st.set_page_config(page_title="Benchmarks - XRL-IDARS", page_icon="📊", layout="wide")

st.title("📊 Operational Random Forest Benchmarks")
st.markdown("""
Authoritative empirical evaluation suite for the operational **Random Forest** intrusion detector across standardized held-out benchmark splits and the 10,000-record evaluation dataset.
""")

# Prominent Mandatory Architectural Scope
st.info("""
🛡️ **ARCHITECTURAL SCOPE & SEPARATION OF RESPONSIBILITIES**  
**Random Forest is the sole operational machine-learning intrusion detector in XRL-IDARS.**  
The Dueling Deep Q-Network (DQN) is a separate autonomous response recommendation agent operating in the mitigation tier, not an intrusion classifier. TreeSHAP explains the Random Forest detector's local feature attributions.
""")

st.divider()

# ---------------------------------------------------------------------------
# Section 1: Evaluation Dataset Provenance & Benchmark Controls
# ---------------------------------------------------------------------------
st.subheader("1. Evaluation Dataset Provenance & Execution")

eval_dir = REPO_ROOT / "results" / "final_evaluation"
summary_file = eval_dir / "evaluation_summary.json"
per_family_file = eval_dir / "per_family_metrics.json"
csv_file = REPO_ROOT / "data" / "demo" / "evaluation_10k_records.csv"

col_ctl1, col_ctl2, col_ctl3 = st.columns([1.5, 1.2, 1.2])

with col_ctl1:
    dataset_choice = st.selectbox(
        "Evaluation Dataset",
        ["CSE-CIC-IDS2017 (Flagship R10 Held-Out)", "Custom CSV Upload"],
        index=0,
    )

with col_ctl2:
    eval_size = st.selectbox(
        "Evaluation Population",
        ["10,000 Records (Authoritative Final Benchmark)", "200 Records (Exhibition Subset)"],
        index=0,
    )

with col_ctl3:
    st.markdown("**Action**")
    run_eval_clicked = st.button("▶ Run Random Forest Evaluation", use_container_width=True, type="primary")

# Custom CSV upload handle
custom_df = None
if dataset_choice == "Custom CSV Upload":
    uploaded_file = st.file_uploader("Upload Evaluation Flow CSV", type=["csv"])
    if uploaded_file is not None:
        try:
            custom_df = pd.read_csv(uploaded_file)
            st.success(f"Loaded {len(custom_df)} rows from custom CSV.")
        except Exception as exc:
            st.error(f"Error parsing uploaded CSV: {exc}")

# Execution of evaluation
if run_eval_clicked:
    with st.spinner("Executing leak-free Random Forest evaluation across records..."):
        if dataset_choice == "Custom CSV Upload" and custom_df is not None:
            target_df = custom_df
        elif "200" in eval_size:
            target_df = pd.read_csv(REPO_ROOT / "data" / "demo" / "cicids2017_exhibition_200.csv")
        else:
            if not csv_file.exists():
                from scripts.demo.run_10k_benchmark import prepare_10k_dataset
                target_df = prepare_10k_dataset()
            else:
                target_df = pd.read_csv(csv_file)

        from scripts.demo.run_10k_benchmark import run_benchmark
        summary_data = run_benchmark(target_df)
        st.success(f"Evaluated {len(target_df)} records through Random Forest detector in {summary_data.get('evaluation_duration_s', 0):.2f}s!")
        st.rerun()

# Load summary from disk
summary_data = None
if summary_file.exists():
    try:
        with open(summary_file, "r", encoding="utf-8") as f:
            summary_data = json.load(f)
    except Exception as exc:
        st.error(f"Failed to load evaluation summary: {exc}")

# Check if evaluation results are available
if not summary_data or "random_forest" not in summary_data.get("models", {}):
    st.warning("⚠️ No evaluation results available. Click '▶ Run Random Forest Evaluation' above to execute evaluation on benchmark data.")
else:
    rf_m = summary_data["models"]["random_forest"]
    cm_rf = rf_m.get("confusion", {})
    required_summary_fields = ("total_records", "evaluation_duration_s")
    if any(key not in summary_data for key in required_summary_fields):
        st.warning("No evaluation results available: the saved summary is missing its record count or measured duration.")
        st.stop()
    total_recs = int(summary_data["total_records"])
    duration_s = float(summary_data["evaluation_duration_s"])
    if total_recs <= 0 or duration_s <= 0:
        st.warning("No evaluation results available: the saved record count or measured duration is invalid.")
        st.stop()
    batch_ms_per_record = (duration_s / total_recs) * 1000.0

    st.caption(
        f"**Dataset Provenance:** `{summary_data.get('benchmark', 'cicids2017').upper()}` | "
        f"**Feature Contract:** `R10 Canonical Flow Statistics` | "
        f"**Population:** `{total_recs:,} evaluated records` | "
        f"**Model Artifact:** `models/rf/random_forest_cicids2017.joblib` | "
        f"**Preprocessor:** `results/experiments/EXP-P1-CIC2017-R10-001/preprocessor.joblib`"
    )

    st.divider()

    # -----------------------------------------------------------------------
    # Section 2: Random Forest Primary Detection Performance
    # -----------------------------------------------------------------------
    st.subheader("2. Operational Random Forest Detection Metrics")
    st.caption("Standardized test split evaluation on held-out network flows with strict label isolation and StandardScaler normalization.")

    m_c1, m_c2, m_c3, m_c4, m_c5, m_c6 = st.columns(6)
    m_c1.metric("Accuracy", f"{rf_m['accuracy'] * 100:.2f}%")
    m_c2.metric("Precision", f"{rf_m['precision'] * 100:.2f}%")
    m_c3.metric("Recall", f"{rf_m['recall'] * 100:.2f}%")
    m_c4.metric("Macro F1", f"{rf_m['macro_f1']:.4f}")
    m_c5.metric("ROC-AUC", f"{rf_m['roc_auc']:.4f}")
    m_c6.metric("Batch time / record", f"{batch_ms_per_record:.3f} ms")

    st.caption(f"""
    **Timing Metadata (not isolated model-inference latency):**
    - **Measurement Method:** Total benchmark wall-clock duration divided by evaluated records
    - **Total Elapsed Time:** {duration_s:.3f} seconds
    - **Sample Size:** {total_recs:,} records
    - **Hardware Platform:** {platform.platform()} | CPU: {platform.processor() or platform.machine()}
    - **Interpretation:** This is an end-to-end benchmark average per record; it must not be presented as standalone Random Forest inference latency.
    """)

    st.divider()

    # -----------------------------------------------------------------------
    # Section 3: Confusion Matrix & Line-Rate Assessment
    # -----------------------------------------------------------------------
    st.subheader("3. Confusion Matrix & Error Analysis")

    col_cm, col_analysis = st.columns([1.2, 1.8])

    with col_cm:
        st.markdown(f"**Binary Confusion Matrix (Population: {total_recs:,})**")
        tn = int(cm_rf.get("tn", 0))
        fp = int(cm_rf.get("fp", 0))
        fn = int(cm_rf.get("fn", 0))
        tp = int(cm_rf.get("tp", 0))

        cm_rf_df = pd.DataFrame([
            {"Actual Class": "Benign Flow (0)", "Pred Benign (TN)": f"{tn:,}", "Pred Attack (FP)": f"{fp:,}"},
            {"Actual Class": "Attack Flow (1)", "Pred Benign (FN)": f"{fn:,}", "Pred Attack (TP)": f"{tp:,}"},
        ]).set_index("Actual Class")
        st.dataframe(cm_rf_df, use_container_width=True)

        fpr = (fp / max(1, tn + fp)) * 100.0
        fnr = (fn / max(1, tp + fn)) * 100.0
        st.caption(f"False Positive Rate (FPR): **{fpr:.2f}%** | False Negative Rate (FNR): **{fnr:.2f}%**")

    with col_analysis:
        st.markdown("**Operational Line-Rate Performance Assessment**")
        st.markdown(f"""
        - **Observed False Positive Rate:** **{fpr:.2f}%** ({fp:,} false positives out of {tn + fp:,} benign flows in this evaluation).
        - **Observed False Negative Rate:** **{fnr:.2f}%** ({fn:,} missed attacks out of {fn + tp:,} attack flows in this evaluation).
        - **Interpretation:** The benchmark timing above includes the evaluation run and is not a standalone per-flow model inference measurement. Deterministic rules are a separate operational layer and are not included in these Random Forest metrics.
        """)

    st.divider()

    # -----------------------------------------------------------------------
    # Section 4: Multi-Class Attack Family Breakdown (Derived from evaluation output)
    # -----------------------------------------------------------------------
    st.subheader("4. Multi-Class Attack Family Breakdown")
    st.caption("Distribution and per-family detection effectiveness derived from the evaluated benchmark output.")

    # Load from per_family_metrics.json
    if per_family_file.exists():
        with open(per_family_file, "r", encoding="utf-8") as f:
            fam_data = json.load(f)
        df_fam = pd.DataFrame(fam_data)
        st.dataframe(df_fam, use_container_width=True)
        st.bar_chart(df_fam.set_index("Attack Category")["Population"], height=220)
    else:
        st.info("Per-family breakdown will be generated upon executing benchmark evaluation.")

    st.divider()

    # -----------------------------------------------------------------------
    # Section 5: Feature Contract & Model Parameters
    # -----------------------------------------------------------------------
    st.subheader("5. $R_{10}$ Feature Contract & Model Parameters")

    col_feats, col_spec = st.columns([1.5, 1.5])

    with col_feats:
        st.markdown("**$R_{10}$ Canonical Flow Statistics Contract**")
        feature_desc = [
            {"Order": 1, "Feature": "flow_duration_ms", "Description": "Elapsed bidirectional flow duration (ms)", "Type": "float64"},
            {"Order": 2, "Feature": "flow_packets_per_s", "Description": "Packet arrival rate per second", "Type": "float64"},
            {"Order": 3, "Feature": "flow_bytes_per_s", "Description": "Byte transfer throughput per second", "Type": "float64"},
            {"Order": 4, "Feature": "packet_length_mean", "Description": "Arithmetic mean of frame payload lengths", "Type": "float64"},
            {"Order": 5, "Feature": "packet_length_std", "Description": "Standard deviation of frame payload lengths", "Type": "float64"},
            {"Order": 6, "Feature": "syn_count", "Description": "Total TCP SYN control flags observed", "Type": "float64"},
            {"Order": 7, "Feature": "ack_count", "Description": "Total TCP ACK control flags observed", "Type": "float64"},
            {"Order": 8, "Feature": "rst_count", "Description": "Total TCP RST control flags observed", "Type": "float64"},
            {"Order": 9, "Feature": "fin_count", "Description": "Total TCP FIN control flags observed", "Type": "float64"},
            {"Order": 10, "Feature": "syn_ack_ratio", "Description": "SYN-to-ACK asymmetry ratio (syn_count / max(1, ack))", "Type": "float64"},
        ]
        st.dataframe(pd.DataFrame(feature_desc), use_container_width=True)

    with col_spec:
        st.markdown("**Model Specifications**")
        st.markdown(r"""
        - **Algorithm:** Random Forest Classifier (`sklearn.ensemble.RandomForestClassifier`)
        - **Estimators ($n_\text{trees}$):** 100 trees
        - **Max Depth:** 16 splits (prevents leaf over-specialization)
        - **Min Samples Leaf:** 2 samples
        - **Class Weight:** `balanced_subsample`
        - **Training Set:** CSE-CIC-IDS2017 ($N = 1,067,593$ canonical flows)
        - **Normalization:** Train-fitted StandardScaler ($\mu=0, \sigma=1$)
        - **Decision Threshold:** $\tau = 0.50$ (Continuous threat score $S_t \in [0.0, 1.0]$)
        - **Explainability:** Fully compatible with exact TreeSHAP polynomial-time feature attribution
        """)

    st.divider()

    # -----------------------------------------------------------------------
    # Section 6: Export Authoritative Benchmark Artifacts
    # -----------------------------------------------------------------------
    st.subheader("6. Export Authoritative Benchmark Artifacts")
    st.caption("Download verified evaluation reports, confusion matrices, and per-flow prediction logs generated in `results/final_evaluation/`.")

    exp_col1, exp_col2, exp_col3 = st.columns(3)

    with exp_col1:
        rf_summary_export = {
            "timestamp": summary_data.get("timestamp"),
            "total_records": summary_data.get("total_records"),
            "evaluation_duration_s": summary_data.get("evaluation_duration_s"),
            "benchmark": summary_data.get("benchmark"),
            "contract": summary_data.get("contract"),
            "model": "Random Forest (Sole Operational Detector)",
            "metrics": rf_m,
            "architecture_disclosure": "Random Forest is the sole operational machine-learning intrusion detector in XRL-IDARS. The DQN is a separate response recommendation agent, not an intrusion classifier.",
        }
        sum_bytes = json.dumps(rf_summary_export, indent=2).encode("utf-8")
        st.download_button(
            "⬇ Download Summary JSON",
            data=sum_bytes,
            file_name="rf_evaluation_summary.json",
            mime="application/json",
            use_container_width=True,
        )

    with exp_col2:
        cm_file = eval_dir / "confusion_matrix.csv"
        cm_bytes = cm_file.read_bytes() if cm_file.exists() else b""
        st.download_button(
            "⬇ Download Confusion Matrix CSV",
            data=cm_bytes,
            file_name="confusion_matrix.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with exp_col3:
        pred_file = eval_dir / "predictions_10k.csv"
        pred_bytes = pred_file.read_bytes() if pred_file.exists() else b""
        st.download_button(
            "⬇ Download Predictions CSV (10k)",
            data=pred_bytes,
            file_name="predictions_10k.csv",
            mime="text/csv",
            use_container_width=True,
        )
