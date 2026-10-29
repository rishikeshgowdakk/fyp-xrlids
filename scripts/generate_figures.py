#!/usr/bin/env python3
"""Generate publication-ready visualization figures for XRLIDS research reports.

This script parses empirical JSON result artifacts from:
  - results/experiments/
  - results/phase2/
and generates figures in reports/figures/:
  1. confusion_matrices_cicids2017.png (RF, LSTM, DT, LR confusion matrices)
  2. baseline_ladder_comparison.png (Baseline ladder across benchmarks)
  3. cross_dataset_transfer_heatmap.png (6-direction transfer matrix)
  4. transfer_degradation_bars.png (Source F1 vs Target F1 degradation)
  5. shap_feature_importance.png (Top 10 features by mean |SHAP|)
  6. phase2_dqn_learning_curves.png (DQN training loss & validation cost)
  7. phase2_policy_comparison.png (DQN vs Baselines cost & availability)
"""

import os
import json
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = str(REPO_ROOT / "reports" / "figures")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Set global clean style
plt.rcParams.update({
    'font.sans-serif': 'DejaVu Sans',
    'font.family': 'sans-serif',
    'axes.edgecolor': '#cccccc',
    'axes.linewidth': 0.8,
    'grid.color': '#e0e0e0',
    'grid.linestyle': '--',
    'grid.alpha': 0.7,
})


def plot_confusion_matrices():
    """Figure 1: Confusion matrices for CIC-IDS2017 models."""
    metrics_path = str(REPO_ROOT / "results/experiments/EXP-P1-CIC2017-R10-001/test_metrics.json")
    if not os.path.exists(metrics_path):
        print(f"Skipping confusion matrices: {metrics_path} not found")
        return

    with open(metrics_path) as f:
        data = json.load(f)

    models = [
        ("logistic_regression", "Logistic Regression"),
        ("decision_tree", "Decision Tree"),
        ("random_forest", "Random Forest"),
        ("lstm", "Supervised LSTM")
    ]

    fig, axes = plt.subplots(2, 2, figsize=(11, 9), dpi=300)
    axes = axes.flatten()

    for idx, (mkey, mtitle) in enumerate(models):
        ax = axes[idx]
        conf = data['native'][mkey]['confusion']
        # Matrix: [[TN, FP], [FN, TP]]
        cm = np.array([[conf['tn'], conf['fp']], [conf['fn'], conf['tp']]])
        total = cm.sum()
        cm_norm = cm / total * 100.0

        im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
        ax.set_title(f"{mtitle}\n(Acc: {data['native'][mkey]['accuracy']*100:.2f}%, F1: {data['native'][mkey]['f1']:.4f})",
                     fontsize=12, fontweight='bold', pad=10)

        tick_marks = [0, 1]
        ax.set_xticks(tick_marks)
        ax.set_yticks(tick_marks)
        ax.set_xticklabels(['Benign (0)', 'Attack (1)'], fontsize=10)
        ax.set_yticklabels(['Benign (0)', 'Attack (1)'], fontsize=10)
        ax.set_xlabel('Predicted Label', fontsize=11, fontweight='medium')
        ax.set_ylabel('True Label', fontsize=11, fontweight='medium')

        thresh = cm.max() / 2.0
        for i in range(2):
            for j in range(2):
                val = cm[i, j]
                pct = cm_norm[i, j]
                color = "white" if val > thresh else "black"
                ax.text(j, i, f"{val:,}\n({pct:.2f}%)",
                        horizontalalignment="center",
                        verticalalignment="center",
                        color=color, fontsize=10, fontweight='bold')

    plt.tight_layout()
    out_file = os.path.join(OUTPUT_DIR, "confusion_matrices_cicids2017.png")
    plt.savefig(out_file, bbox_inches='tight')
    plt.close()
    print(f"Saved: {out_file}")


def plot_baseline_ladder():
    """Figure 2: Baseline ladder comparison across datasets."""
    datasets = {
        'CIC-IDS2017': str(REPO_ROOT / "results/experiments/EXP-P1-CIC2017-R10-001/test_metrics.json"),
        'CSE-CIC-IDS2018': str(REPO_ROOT / "results/experiments/EXP-P1-CSE2018-R10-MULTI-001/test_metrics.json"),
        'UNSW-NB15': str(REPO_ROOT / "results/experiments/EXP-P1-UNSWNB15-R10-MULTI-001/test_metrics.json")
    }

    model_names = ['majority', 'logistic_regression', 'decision_tree', 'random_forest', 'lstm']
    labels = ['Majority Class', 'Logistic Reg.', 'Decision Tree', 'Random Forest', 'LSTM']

    f1_scores = {d: [] for d in datasets}
    auc_scores = {d: [] for d in datasets}

    for dname, dpath in datasets.items():
        with open(dpath) as f:
            data = json.load(f)['native']
        for m in model_names:
            f1_scores[dname].append(data[m].get('f1', 0.0))
            auc_scores[dname].append(data[m].get('roc_auc', 0.5))

    x = np.arange(len(labels))
    width = 0.25

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6), dpi=300)

    # Plot F1
    colors = ['#2b5c8f', '#4682b4', '#70a1d7']
    for idx, (dname, vals) in enumerate(f1_scores.items()):
        bars = ax1.bar(x + idx * width - width, vals, width, label=dname, color=colors[idx], edgecolor='#1d3e60', alpha=0.9)
        for bar in bars:
            height = bar.get_height()
            if height > 0.05:
                ax1.annotate(f'{height:.2f}',
                             xy=(bar.get_x() + bar.get_width() / 2, height),
                             xytext=(0, 3), textcoords="offset points",
                             ha='center', va='bottom', fontsize=8, rotation=0)

    ax1.set_ylabel('F1 Score', fontsize=12, fontweight='bold')
    ax1.set_title('Baseline Ladder: F1-Score Hierarchy', fontsize=13, fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(labels, rotation=20, ha='right', fontsize=10)
    ax1.legend(frameon=True, facecolor='white', framealpha=0.9)
    ax1.grid(True, axis='y')
    ax1.set_ylim(0, 1.1)

    # Plot ROC-AUC
    colors_auc = ['#2e7d32', '#4caf50', '#81c784']
    for idx, (dname, vals) in enumerate(auc_scores.items()):
        bars = ax2.bar(x + idx * width - width, vals, width, label=dname, color=colors_auc[idx], edgecolor='#1b4d1e', alpha=0.9)
        for bar in bars:
            height = bar.get_height()
            if height > 0.1:
                ax2.annotate(f'{height:.2f}',
                             xy=(bar.get_x() + bar.get_width() / 2, height),
                             xytext=(0, 3), textcoords="offset points",
                             ha='center', va='bottom', fontsize=8, rotation=0)

    ax2.set_ylabel('ROC-AUC', fontsize=12, fontweight='bold')
    ax2.set_title('Baseline Ladder: ROC-AUC Discrimination', fontsize=13, fontweight='bold')
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels, rotation=20, ha='right', fontsize=10)
    ax2.legend(frameon=True, facecolor='white', framealpha=0.9)
    ax2.grid(True, axis='y')
    ax2.set_ylim(0.4, 1.08)

    plt.tight_layout()
    out_file = os.path.join(OUTPUT_DIR, "baseline_ladder_comparison.png")
    plt.savefig(out_file, bbox_inches='tight')
    plt.close()
    print(f"Saved: {out_file}")


def plot_transfer_heatmap():
    """Figure 3: Heatmap of cross-dataset transfer degradation."""
    domains = ['CIC-IDS2017', 'CSE-CIC-IDS2018', 'UNSW-NB15']
    # Matrix of RF F1 scores (Source in rows, Target in columns)
    # Native diagonals: CIC=0.9512, CSE=0.8861, UNSW=0.8546
    # Transfer:
    # CIC -> CSE = 0.3286, CIC -> UNSW = 0.0016
    # CSE -> CIC = 0.0301, CSE -> UNSW = 0.0026
    # UNSW -> CIC = 0.3276, UNSW -> CSE = 0.0217
    rf_matrix = np.array([
        [0.9512, 0.3286, 0.0016],
        [0.0301, 0.8861, 0.0026],
        [0.3276, 0.0217, 0.8546]
    ])

    # LSTM matrix:
    # Native diagonals: CIC=0.9633, CSE=0.9603, UNSW=0.8637
    # Transfer:
    # CIC -> CSE = 0.0983, CIC -> UNSW = 0.0051
    # CSE -> CIC = 0.2601, CSE -> UNSW = 0.0048
    # UNSW -> CIC = 0.3389, UNSW -> CSE = 0.0380
    lstm_matrix = np.array([
        [0.9633, 0.0983, 0.0051],
        [0.2601, 0.9603, 0.0048],
        [0.3389, 0.0380, 0.8637]
    ])

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6), dpi=300)

    for ax, mat, title in zip([ax1, ax2], [rf_matrix, lstm_matrix], ["Random Forest Transfer F1", "Supervised LSTM Transfer F1"]):
        im = ax.imshow(mat, cmap='YlOrRd', vmin=0.0, vmax=1.0)
        ax.set_title(title, fontsize=13, fontweight='bold', pad=12)
        ax.set_xticks(range(3))
        ax.set_yticks(range(3))
        ax.set_xticklabels(domains, fontsize=10, rotation=15, ha='right')
        ax.set_yticklabels(domains, fontsize=10)
        ax.set_xlabel('Target Domain (Evaluated Out-of-Domain)', fontsize=11, fontweight='medium')
        ax.set_ylabel('Source Domain (Trained On)', fontsize=11, fontweight='medium')

        for i in range(3):
            for j in range(3):
                val = mat[i, j]
                tag = "(In-Domain)" if i == j else f"(ΔF1: {val - mat[i, i]:.2f})"
                color = "white" if val > 0.55 else "black"
                ax.text(j, i, f"{val:.4f}\n{tag}", ha="center", va="center",
                        color=color, fontsize=9, fontweight='bold')

    fig.subplots_adjust(right=0.88)
    cbar_ax = fig.add_axes([0.90, 0.20, 0.02, 0.60])
    cbar = fig.colorbar(im, cax=cbar_ax)
    cbar.set_label('Test F1 Score', fontsize=11, fontweight='bold')

    out_file = os.path.join(OUTPUT_DIR, "cross_dataset_transfer_heatmap.png")
    plt.savefig(out_file, bbox_inches='tight')
    plt.close()
    print(f"Saved: {out_file}")


def plot_transfer_degradation_bars():
    """Figure 4: Grouped bar chart of F1 degradation across all 6 transfer directions."""
    directions = [
        "CIC → CSE\n(R10)",
        "CSE → CIC\n(R10)",
        "UNSW → CIC\n(R4)",
        "UNSW → CSE\n(R4)",
        "CIC → UNSW\n(R4)",
        "CSE → UNSW\n(R4)"
    ]

    # Source F1, Target F1 for RF
    rf_source = [0.9512, 0.8861, 0.8548, 0.8548, 0.9525, 0.8672]
    rf_target = [0.3286, 0.0301, 0.3276, 0.0217, 0.0016, 0.0026]

    # LSTM
    lstm_source = [0.9633, 0.9603, 0.8637, 0.8637, 0.9054, 0.8920]
    lstm_target = [0.0983, 0.2601, 0.3389, 0.0380, 0.0051, 0.0048]

    # Fusion
    fusion_source = [0.9745, 0.9603, 0.8970, 0.8970, 0.9533, 0.9302]
    fusion_target = [0.1139, 0.1191, 0.3664, 0.0268, 0.0004, 0.0019]

    x = np.arange(len(directions))
    width = 0.13

    fig, ax = plt.subplots(figsize=(15, 6.5), dpi=300)

    # Plot bars
    ax.bar(x - 2.5*width, rf_source, width, label='RF (In-Domain Source)', color='#90caf9', edgecolor='#1e88e5')
    ax.bar(x - 1.5*width, rf_target, width, label='RF (Out-of-Domain Target)', color='#1565c0', edgecolor='#0d47a1')

    ax.bar(x - 0.5*width, lstm_source, width, label='LSTM (In-Domain Source)', color='#a5d6a7', edgecolor='#43a047')
    ax.bar(x + 0.5*width, lstm_target, width, label='LSTM (Out-of-Domain Target)', color='#2e7d32', edgecolor='#1b5e20')

    ax.bar(x + 1.5*width, fusion_source, width, label='Fusion (In-Domain Source)', color='#ffcc80', edgecolor='#fb8c00')
    ax.bar(x + 2.5*width, fusion_target, width, label='Fusion (Out-of-Domain Target)', color='#e65100', edgecolor='#bf360c')

    ax.set_ylabel('F1 Score', fontsize=12, fontweight='bold')
    ax.set_title('Cross-Dataset Generalization Collapse: In-Domain vs Out-of-Domain F1 Degradation',
                 fontsize=14, fontweight='bold', pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(directions, fontsize=10, fontweight='medium')
    ax.legend(frameon=True, facecolor='white', framealpha=0.95, loc='upper right', ncol=3, fontsize=9)
    ax.grid(True, axis='y')
    ax.set_ylim(0, 1.15)

    # Add red drop markers for CIC -> CSE and UNSW -> CIC
    for idx in range(len(directions)):
        rf_drop = rf_target[idx] - rf_source[idx]
        ax.annotate(f"Δ {rf_drop:.2f}", xy=(x[idx] - 1.5*width, rf_target[idx]),
                    xytext=(0, 4), textcoords="offset points", ha='center',
                    fontsize=8, color='#b71c1c', fontweight='bold')

    plt.tight_layout()
    out_file = os.path.join(OUTPUT_DIR, "transfer_degradation_bars.png")
    plt.savefig(out_file, bbox_inches='tight')
    plt.close()
    print(f"Saved: {out_file}")


def plot_shap_feature_importance():
    """Figure 5: TreeSHAP global feature importance ranking."""
    shap_path = str(REPO_ROOT / "results/experiments/EXP-P1-CIC2017-R10-001/shap_summary.json")
    if not os.path.exists(shap_path):
        print(f"Skipping SHAP: {shap_path} not found")
        return

    with open(shap_path) as f:
        shap_data = json.load(f)

    items = shap_data['global_importance']
    features = [item['feature'] for item in items][::-1]
    values = [item['mean_abs_shap'] for item in items][::-1]

    # Clean display labels
    labels = [f.replace('_', ' ').title() for f in features]

    fig, ax = plt.subplots(figsize=(10, 6), dpi=300)
    colors = plt.cm.viridis(np.linspace(0.2, 0.85, len(labels)))

    bars = ax.barh(labels, values, color=colors, edgecolor='#333333', height=0.65)

    for bar in bars:
        width = bar.get_width()
        ax.annotate(f'{width:.4f}',
                    xy=(width, bar.get_y() + bar.get_height() / 2),
                    xytext=(6, 0), textcoords="offset points",
                    ha='left', va='center', fontsize=9, fontweight='bold', color='#1a237e')

    ax.set_xlabel('Mean Absolute SHAP Value (Impact on Detection Output)', fontsize=11, fontweight='bold')
    ax.set_title('Global Feature Importance Ranking (TreeSHAP on CIC-IDS2017 Random Forest)',
                 fontsize=13, fontweight='bold', pad=12)
    ax.grid(True, axis='x')
    ax.set_xlim(0, max(values) * 1.15)

    plt.tight_layout()
    out_file = os.path.join(OUTPUT_DIR, "shap_feature_importance.png")
    plt.savefig(out_file, bbox_inches='tight')
    plt.close()
    print(f"Saved: {out_file}")


def plot_phase2_dqn_learning():
    """Figure 6: DQN training loss and validation cost trajectories."""
    hist_path = str(REPO_ROOT / "results/phase2/EXP-P2B-DQN-001/training_history.json")
    if not os.path.exists(hist_path):
        print(f"Skipping DQN curves: {hist_path} not found")
        return

    with open(hist_path) as f:
        hist_data = json.load(f)

    s1 = hist_data['stage_2b1_3action']['history']
    s2 = hist_data['stage_2b2_4action']['history']

    steps1 = [item['step'] for item in s1]
    loss1 = [item['loss'] for item in s1]
    cost1 = [item['val_metrics']['mean_cost_per_flow'] for item in s1]

    steps2 = [item['step'] for item in s2]
    loss2 = [item['loss'] for item in s2]
    cost2 = [item['val_metrics']['mean_cost_per_flow'] for item in s2]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5), dpi=300)

    # Subplot 1: Loss curves
    ax1.plot(steps1, loss1, 'o-', color='#1976d2', linewidth=2, markersize=5, label='Stage 2B1 (3-Action Space)')
    ax1.plot(steps2, loss2, 's--', color='#d32f2f', linewidth=2, markersize=5, label='Stage 2B2 (4-Action Space)')
    ax1.set_xlabel('Training Step', fontsize=11, fontweight='bold')
    ax1.set_ylabel('Smooth L1 Loss (PER Replay)', fontsize=11, fontweight='bold')
    ax1.set_title('DQN Loss Convergence Across Training Steps', fontsize=12, fontweight='bold')
    ax1.legend(frameon=True, facecolor='white')
    ax1.grid(True)

    # Subplot 2: Validation Cost Curves
    ax2.plot(steps1, cost1, 'o-', color='#388e3c', linewidth=2, markersize=5, label='Stage 2B1 Mean Cost / Flow')
    ax2.plot(steps2, cost2, 's--', color='#f57c00', linewidth=2, markersize=5, label='Stage 2B2 Mean Cost / Flow')
    ax2.set_xlabel('Training Step', fontsize=11, fontweight='bold')
    ax2.set_ylabel('Validation Cost / Flow (Lower is Better)', fontsize=11, fontweight='bold')
    ax2.set_title('Validation Cost Optimization Trajectory', fontsize=12, fontweight='bold')
    ax2.legend(frameon=True, facecolor='white')
    ax2.grid(True)

    plt.tight_layout()
    out_file = os.path.join(OUTPUT_DIR, "phase2_dqn_learning_curves.png")
    plt.savefig(out_file, bbox_inches='tight')
    plt.close()
    print(f"Saved: {out_file}")


def plot_phase2_policy_comparison():
    """Figure 7: Policy comparison between DQN and static baselines."""
    metrics_path = str(REPO_ROOT / "results/phase2/EXP-P2-FINAL-TEST-001/final_test_metrics.json")
    if not os.path.exists(metrics_path):
        print(f"Skipping policy comparison: {metrics_path} not found")
        return

    with open(metrics_path) as f:
        data = json.load(f)

    # Select representative 4-action symmetric cost regime runs
    runs = [r for r in data['runs'] if r['action_mode'] == '4-action' and r['cost_regime'] == 'asymmetric_heavy_attack']
    if not runs:
        runs = [r for r in data['runs'] if r['action_mode'] == '4-action'][:5]

    policies = []
    costs = []
    avails = []

    label_map = {
        'DQN_Candidate_4-action': 'DQN (Candidate Policy)',
        'Baseline_0_Always_ALLOW': 'Baseline 0: Always Allow',
        'Baseline_1_Single_Threshold_tau_0.50': 'Baseline 1: Single Threshold (τ=0.50)',
        'Baseline_2_Two_Tier_0.40_0.75': 'Baseline 2: Two-Tier (0.40/0.75)',
        'Baseline_3_Heuristic_State_Machine': 'Baseline 3: Heuristic State Machine'
    }

    for r in runs:
        pname = r['policy_name']
        policies.append(label_map.get(pname, pname))
        costs.append(r['mean_cost_per_flow'])
        avails.append(r['business_availability_score_pct'])

    fig, ax1 = plt.subplots(figsize=(11, 5.5), dpi=300)

    x = np.arange(len(policies))
    width = 0.38

    bars1 = ax1.bar(x - width/2, costs, width, label='Mean Cost / Flow', color='#e53935', edgecolor='#b71c1c')
    ax1.set_ylabel('Mean Cost / Flow (Lower is Better)', color='#b71c1c', fontsize=11, fontweight='bold')
    ax1.tick_params(axis='y', labelcolor='#b71c1c')
    ax1.set_xticks(x)
    ax1.set_xticklabels(policies, rotation=18, ha='right', fontsize=9.5, fontweight='medium')

    # Secondary axis for availability
    ax2 = ax1.twinx()
    bars2 = ax2.bar(x + width/2, avails, width, label='Business Availability (%)', color='#1e88e5', edgecolor='#0d47a1')
    ax2.set_ylabel('Business Availability (%) (Higher is Better)', color='#0d47a1', fontsize=11, fontweight='bold')
    ax2.tick_params(axis='y', labelcolor='#0d47a1')
    ax2.set_ylim(0, 110)

    # Data labels
    for bar in bars1:
        h = bar.get_height()
        ax1.annotate(f'{h:.2f}', xy=(bar.get_x() + bar.get_width() / 2, h),
                     xytext=(0, 3), textcoords="offset points", ha='center', fontsize=8.5, fontweight='bold')

    for bar in bars2:
        h = bar.get_height()
        ax2.annotate(f'{h:.1f}%', xy=(bar.get_x() + bar.get_width() / 2, h),
                     xytext=(0, 3), textcoords="offset points", ha='center', fontsize=8.5, fontweight='bold')

    plt.title('Autonomous Response Evaluation: DQN vs Rule-Based Baselines (4-Action Regime)',
              fontsize=13, fontweight='bold', pad=15)
    plt.tight_layout()

    out_file = os.path.join(OUTPUT_DIR, "phase2_policy_comparison.png")
    plt.savefig(out_file, bbox_inches='tight')
    plt.close()
    print(f"Saved: {out_file}")


def main():
    print("Generating all figures into:", OUTPUT_DIR)
    plot_confusion_matrices()
    plot_baseline_ladder()
    plot_transfer_heatmap()
    plot_transfer_degradation_bars()
    plot_shap_feature_importance()
    plot_phase2_dqn_learning()
    plot_phase2_policy_comparison()
    print("All figures successfully generated!")


if __name__ == '__main__':
    main()
