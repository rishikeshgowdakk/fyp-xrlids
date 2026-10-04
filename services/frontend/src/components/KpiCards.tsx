import React from 'react';
import { ReplaySummary } from '../types';
import { Activity, AlertTriangle, CheckCircle2, Shield, Layers } from './Icons';

interface KpiCardsProps {
  summary: ReplaySummary | null;
}

export const KpiCards: React.FC<KpiCardsProps> = ({ summary }) => {
  if (!summary) {
    return (
      <div className="kpi-grid">
        {['Packets Processed', 'Flows Detected', 'Attacks Detected', 'Benign Flows', 'Average Threat Score', 'Detection F1'].map(
          (title) => (
            <div key={title} className="kpi-card empty">
              <span className="kpi-title">{title}</span>
              <span className="kpi-value text-muted">N/A</span>
              <span className="kpi-sub">Awaiting data ingest</span>
            </div>
          )
        )}
      </div>
    );
  }

  const flows = summary.flow_events || [];
  const packetsProcessed = summary.total_packets != null ? summary.total_packets : 'N/A';
  const flowsDetected = summary.total_flows != null ? summary.total_flows : flows.length;

  const researchAttacks = flows.filter(
    (f) => f.pred_research_label === 'ATTACK' || f.attack_score >= (summary.research_threshold ?? 0.5)
  ).length;

  const operationalAttacks = flows.filter(
    (f) => f.pred_operational_label === 'ATTACK' || f.attack_score >= (summary.operational_candidate_threshold ?? 0.4)
  ).length;

  const researchBenign = flows.filter(
    (f) => f.pred_research_label === 'BENIGN' || f.attack_score < (summary.research_threshold ?? 0.5)
  ).length;

  const avgThreatScore =
    flows.length > 0
      ? (flows.reduce((acc, f) => acc + (f.attack_score ?? 0), 0) / flows.length).toFixed(4)
      : 'N/A';

  const researchF1 =
    summary.metrics_research?.f1 != null
      ? (summary.metrics_research.f1 * 100).toFixed(1) + '%'
      : summary.metrics?.f1 != null
      ? (summary.metrics.f1 * 100).toFixed(1) + '%'
      : 'N/A';

  const operationalF1 =
    summary.metrics_operational?.f1 != null
      ? (summary.metrics_operational.f1 * 100).toFixed(1) + '%'
      : 'N/A';

  return (
    <div className="kpi-grid">
      <div className="kpi-card">
        <div className="kpi-header">
          <span className="kpi-title">PACKETS PROCESSED</span>
          <Activity size={18} className="kpi-icon cyan" />
        </div>
        <div className="kpi-value highlight-cyan">{packetsProcessed}</div>
        <div className="kpi-sub">Ingested from {summary.pcap_file?.split('/').pop() || 'PCAP'}</div>
      </div>

      <div className="kpi-card">
        <div className="kpi-header">
          <span className="kpi-title">FLOWS DETECTED</span>
          <Layers size={18} className="kpi-icon purple" />
        </div>
        <div className="kpi-value highlight-purple">{flowsDetected}</div>
        <div className="kpi-sub">Bidirectional flows (D-006 policy)</div>
      </div>

      <div className="kpi-card">
        <div className="kpi-header">
          <span className="kpi-title">ATTACKS DETECTED</span>
          <AlertTriangle size={18} className="kpi-icon rose" />
        </div>
        <div className="kpi-value highlight-rose">
          {researchAttacks}
          <span className="kpi-value-aux"> / {operationalAttacks} (cand)</span>
        </div>
        <div className="kpi-sub">τ=0.50 baseline vs τ=0.40 candidate</div>
      </div>

      <div className="kpi-card">
        <div className="kpi-header">
          <span className="kpi-title">BENIGN FLOWS</span>
          <CheckCircle2 size={18} className="kpi-icon emerald" />
        </div>
        <div className="kpi-value highlight-emerald">{researchBenign}</div>
        <div className="kpi-sub">Cleared at research threshold</div>
      </div>

      <div className="kpi-card">
        <div className="kpi-header">
          <span className="kpi-title">AVG THREAT SCORE</span>
          <Shield size={18} className="kpi-icon amber" />
        </div>
        <div className="kpi-value highlight-amber">{avgThreatScore}</div>
        <div className="kpi-sub">Range: 0.0000 → 1.0000</div>
      </div>

      <div className="kpi-card">
        <div className="kpi-header">
          <span className="kpi-title">DETECTION F1 SCORE</span>
          <Activity size={18} className="kpi-icon blue" />
        </div>
        <div className="kpi-value highlight-blue">
          {researchF1}
          {operationalF1 !== 'N/A' && (
            <span className="kpi-value-aux"> → {operationalF1} (cand)</span>
          )}
        </div>
        <div className="kpi-sub">Hold-out model benchmark validation</div>
      </div>
    </div>
  );
};
